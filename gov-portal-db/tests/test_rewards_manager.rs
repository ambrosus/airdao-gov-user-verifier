#![cfg(feature = "enable-integration-tests")]

use assert_matches::assert_matches;
use chrono::Utc;
use ethereum_types::U256;
use web3::types::Address;

use airdao_gov_portal_db::{
    mongo_client::MongoConfig,
    rewards_manager::{error, RewardsManager, RewardsManagerConfig},
};
use shared::common::{RewardInfo, RewardStatus, UpdateRewardKind};

#[tokio::test]
async fn test_update_reward() -> Result<(), anyhow::Error> {
    let mongo_config = MongoConfig {
        url: Some("mongodb://localhost:27017".to_owned()),
        db: "AirDAOGovPortal_IntegrationTest".to_owned(),
        request_timeout: 10,
    };

    let rewards_manager = RewardsManager::new(
        &mongo_config,
        RewardsManagerConfig {
            moderators: vec![],
            collection: "Rewards".to_owned(),
        },
    )
    .await?;

    rewards_manager
        .db_client
        .collection
        .inner
        .delete_many(bson::doc! {})
        .await?;

    let addr_1 = Address::from_low_u64_le(1);
    let addr_2 = Address::from_low_u64_le(2);

    rewards_manager
        .update_reward(UpdateRewardKind::Grant(RewardInfo {
            wallet: addr_1,
            id: 1,
            amount: U256::one(),
            timestamp: Utc::now().timestamp() as u64,
            status: RewardStatus::Granted,
        }))
        .await?;

    rewards_manager
        .update_reward(UpdateRewardKind::Grant(RewardInfo {
            wallet: addr_2,
            id: 2,
            amount: U256::one(),
            timestamp: Utc::now().timestamp() as u64,
            status: RewardStatus::Granted,
        }))
        .await?;

    rewards_manager
        .update_reward(UpdateRewardKind::Claim {
            wallet: addr_1,
            id: 1,
        })
        .await?;

    rewards_manager
        .update_reward(UpdateRewardKind::Revert { id: 2 })
        .await?;

    rewards_manager.db_client.collection.inner.drop().await?;

    Ok(())
}

#[tokio::test]
async fn test_rewards_endpoint() -> Result<(), anyhow::Error> {
    let mongo_config = MongoConfig {
        url: Some("mongodb://localhost:27017".to_owned()),
        db: "AirDAOGovPortal_IntegrationTest".to_owned(),
        request_timeout: 10,
    };

    let moderators = vec![
        Address::from_low_u64_le(1_234_567),
        Address::from_low_u64_le(1_234_568),
        Address::from_low_u64_le(1_234_569),
    ];

    let rewards_manager = std::sync::Arc::new(
        RewardsManager::new(
            &mongo_config,
            RewardsManagerConfig {
                moderators,
                collection: "Rewards".to_owned(),
            },
        )
        .await?,
    );

    rewards_manager
        .db_client
        .collection
        .inner
        .delete_many(bson::doc! {})
        .await?;

    let now = Utc::now().timestamp() as u64;

    futures_util::future::join_all((1u64..=29).map(|i| {
        let users_manager = rewards_manager.clone();

        async move {
            let wallet = Address::from_low_u64_le(i / 3 + 1);
            users_manager
                .update_reward(UpdateRewardKind::Grant(RewardInfo {
                    wallet,
                    id: i % 10 + 1,
                    amount: U256::from(i * 1_000_000_000),
                    timestamp: now + i % 10 + 1,
                    status: RewardStatus::Granted,
                }))
                .await
        }
    }))
    .await;

    assert_matches!(
        rewards_manager
            .get_rewards(&Address::from_low_u64_le(0), None, None)
            .await,
        Err(error::Error::Unauthorized)
    );

    assert_matches!(
        rewards_manager
            .get_rewards_by_wallet(
                &Address::from_low_u64_le(0),
                &Address::from_low_u64_le(1),
                None,
                None
            )
            .await,
        Err(error::Error::Unauthorized)
    );

    assert!(rewards_manager
        .get_rewards_by_wallet(
            &Address::from_low_u64_le(1),
            &Address::from_low_u64_le(1),
            None,
            None
        )
        .await
        .is_ok());

    // Min limit is 1
    assert!(!rewards_manager
        .get_rewards(&Address::from_low_u64_le(1_234_567), None, Some(0))
        .await
        .unwrap()
        .is_empty(),);

    let mut rewards = rewards_manager
        .get_rewards_by_wallet(
            &Address::from_low_u64_le(1_234_567),
            &Address::from_low_u64_le(1),
            None,
            None,
        )
        .await
        .unwrap()
        .into_iter()
        .flat_map(|rewards| rewards.rewards_by_wallet.into_values())
        .collect::<Vec<_>>();
    rewards.sort_by(|l, r| l.id.cmp(&r.id));

    assert_eq!(
        rewards,
        vec![
            RewardInfo {
                id: 2,
                wallet: Address::from_low_u64_le(1),
                amount: U256::from(1_000_000_000),
                timestamp: now + 2,
                status: RewardStatus::Granted,
            },
            RewardInfo {
                id: 3,
                wallet: Address::from_low_u64_le(1),
                amount: U256::from(2_000_000_000),
                timestamp: now + 3,
                status: RewardStatus::Granted,
            }
        ]
    );

    rewards_manager.db_client.collection.inner.drop().await?;

    Ok(())
}
