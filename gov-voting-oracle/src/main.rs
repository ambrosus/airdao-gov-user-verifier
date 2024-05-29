mod config;
mod event_listener;
//mod token_holder_registry;

use config::AppConfig;
use event_listener::EventListener;
use shared::{logger, utils};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    logger::init();
    utils::set_heavy_panic();

    // Try load environment variables from `.env` if provided
    dotenv::dotenv().ok();

    let config = utils::load_config::<AppConfig>("./gov-event-listener").await?;

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    EventListener::new(config)?.start(tx)?;

    tokio::spawn(async move {
        while let Some((wallet, application, tx_hash)) = rx.recv().await {
            tracing::info!(
                "User wallet {wallet:?} updated application {application:?} (tx: {tx_hash:?})"
            );
        }
    })
    .await?;

    Ok(())
}
