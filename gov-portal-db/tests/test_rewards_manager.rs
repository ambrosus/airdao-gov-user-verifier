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
    let addr_grantor = Address::from_low_u64_le(11111111);

    rewards_manager
        .update_reward(UpdateRewardKind::Grant(RewardInfo {
            id: 1,
            grantor: addr_grantor,
            wallet: addr_1,
            amount: U256::one(),
            timestamp: Utc::now().timestamp() as u64,
            event_name: "Rewards".to_owned(),
            region: "NA".to_owned(),
            community: None,
            pseudo: None,
            status: RewardStatus::Granted,
        }))
        .await?;

    rewards_manager
        .update_reward(UpdateRewardKind::Grant(RewardInfo {
            id: 2,
            grantor: addr_grantor,
            wallet: addr_2,
            amount: U256::one(),
            timestamp: Utc::now().timestamp() as u64,
            event_name: "Rewards".to_owned(),
            region: "NA".to_owned(),
            community: Some("test".into()),
            pseudo: None,
            status: RewardStatus::Granted,
        }))
        .await?;

    rewards_manager
        .update_reward(UpdateRewardKind::Claim {
            id: 1,
            wallet: addr_1,
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
    let addr_grantor = Address::from_low_u64_le(11111111);

    futures_util::future::join_all((1u64..=29).map(|i| {
        let users_manager = rewards_manager.clone();

        async move {
            let wallet = Address::from_low_u64_le(i / 3 + 1);
            users_manager
                .update_reward(UpdateRewardKind::Grant(RewardInfo {
                    id: i % 10 + 1,
                    grantor: addr_grantor,
                    wallet,
                    amount: U256::from(i * 1_000_000_000),
                    timestamp: now + i % 10 + 1,
                    event_name: "Rewards".to_owned(),
                    region: "NA".to_owned(),
                    community: Some((i % 10 + 1).to_string()),
                    pseudo: None,
                    status: RewardStatus::Granted,
                }))
                .await
        }
    }))
    .await;

    assert_matches!(
        rewards_manager
            .get_rewards(&Address::from_low_u64_le(0), None, None, None, None, None)
            .await,
        Err(error::Error::Unauthorized)
    );

    assert_matches!(
        rewards_manager
            .get_rewards_by_wallet(
                &Address::from_low_u64_le(0),
                &Address::from_low_u64_le(1),
                None,
                None,
                None,
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
            None,
            None,
            None,
            None
        )
        .await
        .is_ok());

    // Min limit is 1
    assert!(!rewards_manager
        .get_rewards(
            &Address::from_low_u64_le(1_234_567),
            None,
            Some(0),
            None,
            None,
            None
        )
        .await
        .unwrap()
        .is_empty(),);

    let mut rewards = rewards_manager
        .get_rewards_by_wallet(
            &Address::from_low_u64_le(1_234_567),
            &Address::from_low_u64_le(1),
            None,
            None,
            None,
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
                grantor: Address::from_low_u64_le(11111111),
                wallet: Address::from_low_u64_le(1),
                amount: U256::from(1_000_000_000),
                timestamp: now + 2,
                event_name: "Rewards".to_owned(),
                region: "NA".to_owned(),
                community: Some("2".into()),
                pseudo: None,
                status: RewardStatus::Granted,
            },
            RewardInfo {
                id: 3,
                grantor: Address::from_low_u64_le(11111111),
                wallet: Address::from_low_u64_le(1),
                amount: U256::from(2_000_000_000),
                timestamp: now + 3,
                event_name: "Rewards".to_owned(),
                region: "NA".to_owned(),
                community: Some("3".into()),
                pseudo: None,
                status: RewardStatus::Granted,
            }
        ]
    );

    let rewards = rewards_manager
        .get_rewards_by_wallet(
            &Address::from_low_u64_le(1_234_567),
            &Address::from_low_u64_le(1),
            None,
            None,
            None,
            None,
            Some("3"),
        )
        .await
        .unwrap()
        .into_iter()
        .flat_map(|rewards| rewards.rewards_by_wallet.into_values())
        .collect::<Vec<_>>();

    assert_eq!(
        rewards,
        vec![RewardInfo {
            id: 3,
            grantor: Address::from_low_u64_le(11111111),
            wallet: Address::from_low_u64_le(1),
            amount: U256::from(2_000_000_000),
            timestamp: now + 3,
            event_name: "Rewards".to_owned(),
            region: "NA".to_owned(),
            community: Some("3".into()),
            pseudo: None,
            status: RewardStatus::Granted,
        }]
    );

    let rewards = rewards_manager
        .get_rewards_by_wallet(
            &Address::from_low_u64_le(1_234_567),
            &Address::from_low_u64_le(1),
            None,
            None,
            Some(now + 2),
            Some(now + 3),
            None,
        )
        .await
        .unwrap()
        .into_iter()
        .flat_map(|rewards| rewards.rewards_by_wallet.into_values())
        .collect::<Vec<_>>();

    assert_eq!(
        rewards,
        vec![RewardInfo {
            id: 2,
            grantor: Address::from_low_u64_le(11111111),
            wallet: Address::from_low_u64_le(1),
            amount: U256::from(1_000_000_000),
            timestamp: now + 2,
            event_name: "Rewards".to_owned(),
            region: "NA".to_owned(),
            community: Some("2".into()),
            pseudo: None,
            status: RewardStatus::Granted,
        },]
    );

    rewards_manager.db_client.collection.inner.drop().await?;

    Ok(())
}

#[tokio::test]
async fn test_rewards_by_wallet() -> Result<(), anyhow::Error> {
    let mongo_config = MongoConfig {
        url: Some("mongodb://localhost:27017".to_owned()),
        db: "AirDAOGovPortal_IntegrationTest".to_owned(),
        request_timeout: 10,
    };

    let moderators = vec![Address::from_low_u64_le(11111111)];

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
    let addr_grantor = Address::from_low_u64_le(11111111);

    futures_util::future::join_all((1u64..=1000).map(|i| {
        let users_manager = rewards_manager.clone();

        async move {
            let wallet = Address::from_low_u64_le(i / 60 + 1);
            let id = i % 200 + 1;
            let timestamp = now + id * 4 * 60 * 60;
            users_manager
                .update_reward(UpdateRewardKind::Grant(RewardInfo {
                    id,
                    grantor: addr_grantor,
                    wallet,
                    amount: U256::from(i * 1_000_000_000),
                    timestamp,
                    event_name: "Rewards".to_owned(),
                    region: "NA".to_owned(),
                    community: Some((id / 10).to_string()),
                    pseudo: None,
                    status: RewardStatus::Granted,
                }))
                .await
        }
    }))
    .await;

    let mut all_rewards = Vec::with_capacity(1000);

    loop {
        let Ok(batch) = rewards_manager
            .get_rewards(
                &addr_grantor,
                Some(all_rewards.len() as u64),
                None,
                None,
                None,
                None,
            )
            .await
        else {
            panic!("Failed to fetch rewards")
        };

        if batch.is_empty() {
            break;
        }

        all_rewards.extend(batch);
    }

    all_rewards.retain(|rewards| {
        rewards
            .rewards_by_wallet
            .contains_key(&Address::from_low_u64_le(1))
    });

    let mut rewards_by_wallet = Vec::with_capacity(100);

    loop {
        let Ok(batch) = rewards_manager
            .get_rewards_by_wallet(
                &Address::from_low_u64_le(1),
                &Address::from_low_u64_le(1),
                Some(rewards_by_wallet.len() as u64),
                None,
                None,
                None,
                None,
            )
            .await
        else {
            panic!("Failed to fetch rewards by wallet")
        };

        if batch.is_empty() {
            break;
        }

        rewards_by_wallet.extend(batch);
    }

    assert_eq!(
        all_rewards
            .into_iter()
            .map(|rewards| rewards.id)
            .collect::<Vec<_>>(),
        rewards_by_wallet
            .into_iter()
            .map(|rewards| rewards.id)
            .collect::<Vec<_>>(),
    );

    assert_eq!(
        rewards_manager
            .get_rewards_by_wallet(
                &Address::from_low_u64_le(1),
                &Address::from_low_u64_le(1),
                None,
                None,
                Some(now + 2 * 4 * 60 * 60),
                Some(now + 10 * 4 * 60 * 60),
                None,
            )
            .await
            .unwrap()
            .len(),
        8
    );

    assert_eq!(
        rewards_manager
            .get_rewards_by_wallet(
                &Address::from_low_u64_le(1),
                &Address::from_low_u64_le(1),
                None,
                None,
                None,
                Some(now + 2 * 4 * 60 * 60 + 1),
                None,
            )
            .await
            .unwrap()
            .len(),
        1
    );

    assert_eq!(
        rewards_manager
            .get_rewards_by_wallet(
                &Address::from_low_u64_le(1),
                &Address::from_low_u64_le(1),
                None,
                None,
                Some(now + 2 * 4 * 60 * 60 + 1),
                None,
                None,
            )
            .await
            .unwrap()
            .len(),
        58
    );

    assert_eq!(
        rewards_manager
            .get_rewards_by_wallet(
                &Address::from_low_u64_le(1),
                &Address::from_low_u64_le(1),
                None,
                None,
                Some(now + 2 * 4 * 60 * 60 + 1),
                None,
                Some("0"),
            )
            .await
            .unwrap()
            .len(),
        7
    );

    assert_eq!(
        rewards_manager
            .get_rewards_by_wallet(
                &Address::from_low_u64_le(1),
                &Address::from_low_u64_le(1),
                None,
                None,
                Some(now + 2 * 4 * 60 * 60 + 1),
                None,
                Some("1"),
            )
            .await
            .unwrap()
            .len(),
        10
    );

    rewards_manager.db_client.collection.inner.drop().await?;

    Ok(())
}
