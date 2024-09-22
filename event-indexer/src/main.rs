mod auto_refresh_token;
mod config;
mod event_listener;
mod gov_db_provider;
mod indexer_state_redis_cache;

use ethers_providers::{Middleware, Provider, Ws};
use std::sync::Arc;
use tokio::time::{sleep_until, Instant};

use event_listener::{EventListener, GovEvent, GovEventNotification};
use gov_db_provider::GovDbProvider;
use indexer_state_redis_cache::IndexerStateRedisCache;
use shared::{
    common::{RewardInfo, RewardStatus, SBTInfo},
    logger, utils,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    logger::init();
    utils::set_heavy_panic();

    // Try load environment variables from `.env` if provided
    dotenv::dotenv().ok();

    let config = utils::load_config::<config::AppConfig>("./event-indexer").await?;

    // TODO: configurable number of reconnection attempts
    let provider = Arc::new(Provider::<Ws>::connect(&config.rpc_node).await?);
    let chain_id = provider.get_chainid().await?.as_u64();

    let mut indexer_state_redis_cache =
        IndexerStateRedisCache::new(chain_id, &config.redis).await?;
    // TODO: remove next line
    indexer_state_redis_cache.block_number = 0;

    let mut gov_db_provider = GovDbProvider::new(config.db.clone())?;

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<GovEventNotification>();

    let listener = EventListener::new(config, provider, indexer_state_redis_cache.block_number)?;

    tokio::spawn(async move {
        let idle_interval = std::time::Duration::from_secs(10);

        loop {
            let idle_until = Instant::now() + idle_interval;

            let event_notification = tokio::select! {
                event = rx.recv() => {
                    let Some(event_notification) = event else {
                        tracing::warn!("Event notification channel has been dropped!");
                        break;
                    };

                    event_notification
                }
                _ = sleep_until(idle_until) => {
                    tracing::info!("No new government events since block #{block_number}", block_number = indexer_state_redis_cache.block_number);
                    continue;
                }
            };

            tracing::trace!(
                event = ?event_notification.event,
                "Processing government event at block #{block_number}",
                block_number = event_notification.block_number
            );

            let result = match event_notification.event {
                GovEvent::SBTMint(wallet) => {
                    let sbt = SBTInfo {
                        name: event_notification.contract_name.clone(),
                        address: event_notification.contract_address,
                        issued_at_block: event_notification.block_number,
                    };

                    gov_db_provider.upsert_user_sbt(wallet, sbt).await
                }
                GovEvent::SBTBurn(wallet) => {
                    gov_db_provider
                        .remove_user_sbt(wallet, event_notification.contract_address)
                        .await
                }
                GovEvent::Reward(wallet, amount, timestamp) => {
                    gov_db_provider
                        .insert_reward(RewardInfo {
                            wallet,
                            id: event_notification.block_number,
                            amount,
                            timestamp: timestamp.as_u64(),
                            status: RewardStatus::Granted,
                        })
                        .await
                }
                GovEvent::ClaimReward(wallet, id) => gov_db_provider.claim_reward(wallet, id).await,
                GovEvent::RevertReward(id) => gov_db_provider.revert_reward(id).await,
            };

            if let Ok(axum::Json(())) = result {
                // Save next block number to start processing from
                if let Err(e) = indexer_state_redis_cache
                    .store_block_number(event_notification.block_number + 1)
                    .await
                {
                    tracing::error!(
                        "Failed to store processed block #{block_number}: {e:?}",
                        block_number = event_notification.block_number
                    );
                    break;
                }
            } else {
                tracing::error!(
                    ?event_notification,
                    "Failed to process event notification: {result:?}"
                );
                break;
            }
        }
    });

    if let Err(e) = listener.start(tx).await {
        tracing::warn!("Event listener stopped. Error: {e:?}");
    }

    Ok(())
}
