#![cfg(feature = "enable-integration-tests")]

use std::time::Duration;

use assert_matches::assert_matches;
use chrono::Utc;
use ethereum_types::U256;
use web3::types::Address;

use airdao_gov_portal_db::{
    mongo_client::MongoConfig,
    rewards_manager::{self, error, RewardsManager, RewardsManagerConfig},
    server::{get_rewards_csv_report, get_rewards_csv_report_by_wallet},
};
use shared::common::{BatchId, RewardInfo, RewardStatus, TimestampSeconds, UpdateRewardKind};

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
            max_csv_report_date_range: rewards_manager::default_max_csv_report_date_range(),
            max_get_rewards_limit: rewards_manager::default_max_get_rewards_limit(),
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
            id: BatchId(1),
            grantor: addr_grantor,
            wallet: addr_1,
            amount: U256::one(),
            timestamp: Utc::now().into(),
            event_name: "Rewards".to_owned(),
            region: "NA".to_owned(),
            community: None,
            pseudo: None,
            status: RewardStatus::Granted,
        }))
        .await?;

    rewards_manager
        .update_reward(UpdateRewardKind::Grant(RewardInfo {
            id: BatchId(2),
            grantor: addr_grantor,
            wallet: addr_2,
            amount: U256::one(),
            timestamp: Utc::now().into(),
            event_name: "Rewards".to_owned(),
            region: "NA".to_owned(),
            community: Some("test".into()),
            pseudo: None,
            status: RewardStatus::Granted,
        }))
        .await?;

    rewards_manager
        .update_reward(UpdateRewardKind::Claim {
            block_number: 3,
            id: BatchId(1),
            wallet: addr_1,
        })
        .await?;

    rewards_manager
        .update_reward(UpdateRewardKind::Revert {
            block_number: 4,
            id: BatchId(2),
        })
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
                max_csv_report_date_range: rewards_manager::default_max_csv_report_date_range(),
                max_get_rewards_limit: rewards_manager::default_max_get_rewards_limit(),
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
                    id: BatchId(i % 10 + 1),
                    grantor: addr_grantor,
                    wallet,
                    amount: U256::from(i * 1_000_000_000),
                    timestamp: TimestampSeconds(now + i % 10 + 1),
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
            .get_rewards(&Address::from_low_u64_le(0), None, None, None, None, None,)
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
                None,
            )
            .await,
        Err(error::Error::Unauthorized)
    );

    assert_eq!(
        rewards_manager
            .count_rewards(&Address::from_low_u64_le(1_234_567), None, None, None)
            .await
            .unwrap(),
        10
    );

    assert!(rewards_manager
        .get_rewards_by_wallet(
            &Address::from_low_u64_le(1),
            &Address::from_low_u64_le(1),
            None,
            None,
            None,
            None,
            None,
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
            None,
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
                id: BatchId(2),
                grantor: Address::from_low_u64_le(11111111),
                wallet: Address::from_low_u64_le(1),
                amount: U256::from(1_000_000_000),
                timestamp: TimestampSeconds(now + 2),
                event_name: "Rewards".to_owned(),
                region: "NA".to_owned(),
                community: Some("2".into()),
                pseudo: None,
                status: RewardStatus::Granted,
            },
            RewardInfo {
                id: BatchId(3),
                grantor: Address::from_low_u64_le(11111111),
                wallet: Address::from_low_u64_le(1),
                amount: U256::from(2_000_000_000),
                timestamp: TimestampSeconds(now + 3),
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
            id: BatchId(3),
            grantor: Address::from_low_u64_le(11111111),
            wallet: Address::from_low_u64_le(1),
            amount: U256::from(2_000_000_000),
            timestamp: TimestampSeconds(now + 3),
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
            id: BatchId(2),
            grantor: Address::from_low_u64_le(11111111),
            wallet: Address::from_low_u64_le(1),
            amount: U256::from(1_000_000_000),
            timestamp: TimestampSeconds(now + 2),
            event_name: "Rewards".to_owned(),
            region: "NA".to_owned(),
            community: Some("2".into()),
            pseudo: None,
            status: RewardStatus::Granted,
        },]
    );

    assert_matches!(
        get_rewards_csv_report(
            rewards_manager.clone(),
            rewards_manager.config.moderators[0],
            Some(now),
            Some(now + rewards_manager.config.max_csv_report_date_range.as_secs()),
            None
        )
        .await,
        Ok(_)
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
                moderators: moderators.clone(),
                collection: "Rewards".to_owned(),
                max_csv_report_date_range: rewards_manager::default_max_csv_report_date_range(),
                max_get_rewards_limit: rewards_manager::default_max_get_rewards_limit(),
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

    for i in 1..1000 {
        let wallet = Address::from_low_u64_le(i % 16 + 1);
        let id = BatchId(i / 5 + 1);
        let timestamp = TimestampSeconds(now + id.0 * 4 * 60 * 60);

        rewards_manager
            .update_reward(UpdateRewardKind::Grant(RewardInfo {
                id,
                grantor: addr_grantor,
                wallet,
                amount: U256::from(i * 1_000_000_000),
                timestamp,
                event_name: "Rewards".to_owned(),
                region: "NA".to_owned(),
                community: Some((id.0 / 10).to_string()),
                pseudo: None,
                status: RewardStatus::Granted,
            }))
            .await
            .unwrap();
    }

    let mut all_rewards = Vec::with_capacity(1000);

    loop {
        let batch = rewards_manager
            .get_rewards(
                &addr_grantor,
                Some(all_rewards.len() as u64),
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();

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

    all_rewards.sort_by(|l, r| l.id.cmp(&r.id));
    rewards_by_wallet.sort_by(|l, r| l.id.cmp(&r.id));

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
                Some(now + 4 * 60 * 60),
                Some(now + 9 * 4 * 60 * 60),
                None,
            )
            .await
            .unwrap()
            .len(),
        2
    );

    assert_eq!(
        rewards_manager
            .get_rewards_by_wallet(
                &Address::from_low_u64_le(1),
                &Address::from_low_u64_le(1),
                None,
                None,
                None,
                Some(now + 4 * 4 * 60 * 60 + 1),
                None,
            )
            .await
            .unwrap()
            .len(),
        1
    );

    let total = rewards_manager
        .count_rewards_by_wallet(
            &Address::from_low_u64_le(1),
            &Address::from_low_u64_le(1),
            None,
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(total, 62);

    let total = rewards_manager
        .count_rewards_by_wallet(
            &Address::from_low_u64_le(1),
            &Address::from_low_u64_le(1),
            Some(now + 4 * 4 * 60 * 60 + 1),
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(total, 61);

    assert_eq!(
        rewards_manager
            .get_rewards_by_wallet(
                &Address::from_low_u64_le(1),
                &Address::from_low_u64_le(1),
                None,
                None,
                Some(now + 4 * 60 * 60 + 1),
                None,
                None,
            )
            .await
            .unwrap()
            .len(),
        62
    );

    assert_eq!(
        rewards_manager
            .get_rewards_by_wallet(
                &Address::from_low_u64_le(1),
                &Address::from_low_u64_le(1),
                None,
                None,
                Some(now + 4 * 60 * 60 + 1),
                None,
                Some("0"),
            )
            .await
            .unwrap()
            .len(),
        2
    );

    assert_eq!(
        rewards_manager
            .get_rewards_by_wallet(
                &Address::from_low_u64_le(1),
                &Address::from_low_u64_le(1),
                None,
                None,
                Some(now + 4 * 60 * 60 + 1),
                None,
                Some("10"),
            )
            .await
            .unwrap()
            .len(),
        4
    );

    tokio::time::sleep(Duration::from_millis(1000)).await;

    // let mut total = U256::zero();
    // for reward in rewards_manager
    //     .get_rewards_by_wallet(
    //         &Address::from_low_u64_le(1),
    //         &Address::from_low_u64_le(1),
    //         None,
    //         None,
    //         None,
    //         None,
    //         None,
    //     )
    //     .await
    //     .unwrap()
    // {
    //     total = total.saturating_add(
    //         reward
    //             .rewards_by_wallet
    //             .get(&Address::from_low_u64_le(1))
    //             .map(|r| r.amount)
    //             .unwrap_or_default(),
    //     );
    // }
    // println!("{total:?}");

    assert_eq!(
        rewards_manager
            .get_available_rewards(&Address::from_low_u64_le(1), &Address::from_low_u64_le(1))
            .unwrap(),
        U256::from_dec_str("31248000000000").unwrap()
    );

    // Restore cache from db
    let rewards_manager = std::sync::Arc::new(
        RewardsManager::new(
            &mongo_config,
            RewardsManagerConfig {
                moderators,
                collection: "Rewards".to_owned(),
                max_csv_report_date_range: rewards_manager::default_max_csv_report_date_range(),
                max_get_rewards_limit: rewards_manager::default_max_get_rewards_limit(),
            },
        )
        .await?,
    );

    assert_eq!(
        rewards_manager
            .get_available_rewards(&Address::from_low_u64_le(1), &Address::from_low_u64_le(1))
            .unwrap(),
        U256::from_dec_str("31248000000000").unwrap()
    );

    assert_eq!(
        rewards_manager
            .get_available_rewards(
                &rewards_manager.config.moderators[0],
                &Address::from_low_u64_le(1)
            )
            .unwrap(),
        U256::from_dec_str("31248000000000").unwrap()
    );

    rewards_manager
        .update_reward(UpdateRewardKind::Revert {
            block_number: 201,
            id: BatchId(4),
        })
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(1000)).await;

    assert_eq!(
        rewards_manager
            .get_available_rewards(&Address::from_low_u64_le(1), &Address::from_low_u64_le(1))
            .unwrap(),
        U256::from_dec_str("31232000000000").unwrap()
    );

    rewards_manager
        .update_reward(UpdateRewardKind::Revert {
            block_number: 202,
            id: BatchId(7),
        })
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(1000)).await;

    assert_eq!(
        rewards_manager
            .get_available_rewards(
                &rewards_manager.config.moderators[0],
                &Address::from_low_u64_le(1)
            )
            .unwrap(),
        U256::from_dec_str("31200000000000").unwrap()
    );

    assert_matches!(
        get_rewards_csv_report_by_wallet(
            rewards_manager.clone(),
            rewards_manager.config.moderators[0],
            Address::from_low_u64_le(1),
            Some(now),
            Some(now + rewards_manager.config.max_csv_report_date_range.as_secs()),
            None
        )
        .await,
        Ok(_)
    );

    rewards_manager.db_client.collection.inner.drop().await?;

    Ok(())
}
