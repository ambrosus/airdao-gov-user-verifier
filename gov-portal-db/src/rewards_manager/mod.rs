pub mod client;
pub mod error;

use bson::{doc, Document};
use ethereum_types::Address;
use futures_util::TryStreamExt;
use mongodb::options::{CountOptions, FindOptions, UpdateOptions};
use serde::Deserialize;

use shared::common::{
    RewardDbEntry, RewardInfo, RewardStatus, Rewards, RewardsDbEntry, UpdateRewardKind,
};

use crate::mongo_client::{MongoClient, MongoConfig};
use client::RewardsDbClient;

const MAX_GET_REWARDS_LIMIT: u64 = 100;
const DEFAULT_GET_REWARDS_LIMIT: u64 = 100;

/// Rewards manager's [`RewardsManager`] settings
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RewardsManagerConfig {
    pub moderators: Vec<Address>,
    /// MongoDB rewards collection name
    pub collection: String,
}

/// User profiles manager which provides read/write access to user profile data stored MongoDB
pub struct RewardsManager {
    pub db_client: RewardsDbClient,
    pub config: RewardsManagerConfig,
}

impl RewardsManager {
    /// Constructs [`RewardsManager`] with provided confuguration
    pub async fn new(
        mongo_config: &MongoConfig,
        config: RewardsManagerConfig,
    ) -> anyhow::Result<Self> {
        let db_client = RewardsDbClient::new(mongo_config, &config.collection).await?;

        Ok(Self { db_client, config })
    }

    /// Update reward struct at MongoDB by reward id [`u64`]
    pub async fn update_reward(&self, update_kind: UpdateRewardKind) -> Result<(), error::Error> {
        let (query, set_doc) = match update_kind {
            UpdateRewardKind::Grant(reward) => {
                let (id, wallet, reward_entry) = <(u64, Address, RewardDbEntry)>::from(reward);

                let query = doc! {
                    "id": bson::to_bson(&id)?,
                };
                let set_doc = doc! {
                    "id": bson::to_bson(&id)?,
                    format!("wallets.0x{}", hex::encode(wallet)): bson::to_bson(&reward_entry)?,
                };

                (query, set_doc)
            }
            UpdateRewardKind::Claim { wallet, id } => {
                let query = doc! {
                    "id": bson::to_bson(&id)?,
                };
                let set_doc = doc! {
                    "id": bson::to_bson(&id)?,
                    format!("wallets.0x{}.status", hex::encode(wallet)): bson::to_bson(&RewardStatus::Claimed)?,
                };

                (query, set_doc)
            }
            UpdateRewardKind::Revert { id } => {
                let query = doc! {
                    "id": bson::to_bson(&id)?,
                };
                let set_doc = doc! {
                    "id": bson::to_bson(&id)?,
                    "status": bson::to_bson(&RewardStatus::Reverted)?,
                };

                (query, set_doc)
            }
        };

        let update = doc! {
            "$set": set_doc
        };

        let options = UpdateOptions::builder().upsert(true).build();

        let upsert_result = tokio::time::timeout(self.db_client.req_timeout, async {
            self.db_client
                .collection()
                .update_one(query, update, options)
                .await
        })
        .await?;

        match upsert_result {
            // Upserts a Reward entry with an id
            Ok(_) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Counts all rewards allocated by requestor within MongoDB by provided wallet EVM-like address [`Address`]
    pub async fn count_rewards(
        &self,
        requestor: &Address,
        from: Option<u64>,
        to: Option<u64>,
        community: Option<&str>,
    ) -> Result<u64, error::Error> {
        if !self
            .config
            .moderators
            .iter()
            .any(|wallet| wallet == requestor)
        {
            return Err(error::Error::Unauthorized);
        }

        let expr = self.build_rewards_filter_expr(from, to, community)?;
        let filter = doc! {
            "$expr": bson::to_bson(&expr)?,
        };

        let res = tokio::time::timeout(
            self.db_client.req_timeout,
            self.db_client
                .collection()
                .count(filter, CountOptions::default()),
        )
        .await?
        .map_err(error::Error::from);

        tracing::debug!("Count total rewards result: {res:?}");

        res
    }

    /// Searches all rewards allocated by requestor within MongoDB by provided wallet EVM-like address [`Address`] and returns [`Vec<Rewards>`]
    pub async fn get_rewards(
        &self,
        requestor: &Address,
        start: Option<u64>,
        limit: Option<u64>,
        from: Option<u64>,
        to: Option<u64>,
        community: Option<&str>,
    ) -> Result<Vec<Rewards>, error::Error> {
        let start = start.unwrap_or_default();
        let limit = limit
            .unwrap_or(DEFAULT_GET_REWARDS_LIMIT)
            .clamp(1, MAX_GET_REWARDS_LIMIT) as i64;

        if !self
            .config
            .moderators
            .iter()
            .any(|wallet| wallet == requestor)
        {
            return Err(error::Error::Unauthorized);
        }

        let expr = self.build_rewards_filter_expr(from, to, community)?;
        let filter = doc! {
            "$expr": expr
        };

        let find_options = FindOptions::builder()
            .max_time(self.db_client.req_timeout)
            .skip(start)
            .limit(limit)
            .build();

        let res = tokio::time::timeout(self.db_client.req_timeout, async {
            let mut results = Vec::with_capacity(limit as usize);
            let mut stream = self
                .db_client
                .collection()
                .find(filter, find_options)
                .await?;
            while let Ok(Some(doc)) = stream.try_next().await {
                let rewards =
                    bson::from_document::<RewardsDbEntry>(doc).map_err(error::Error::from)?;
                results.push(rewards);
            }
            Ok(results)
        })
        .await?;

        tracing::debug!("Get rewards (start: {start} limit: {limit}) result: {res:?}");

        res.map(|entries| {
            entries
                .into_iter()
                .map(|db_entry| Rewards {
                    id: db_entry.id,
                    timestamp: db_entry
                        .wallets
                        .values()
                        .next()
                        .map(|reward_db_entry| reward_db_entry.timestamp)
                        .unwrap_or_default(),
                    rewards_by_wallet: db_entry
                        .wallets
                        .into_iter()
                        .map(|(wallet, reward_db_entry)| {
                            (
                                wallet,
                                RewardInfo::from((db_entry.id, wallet, reward_db_entry)),
                            )
                        })
                        .collect(),
                    status: db_entry.status,
                })
                .collect()
        })
    }

    /// Counts rewards allocated for user within MongoDB by provided wallet EVM-like address [`Address`]
    pub async fn count_rewards_by_wallet(
        &self,
        requestor: &Address,
        wallet: &Address,
        from: Option<u64>,
        to: Option<u64>,
        community: Option<&str>,
    ) -> Result<u64, error::Error> {
        let requires_moderator_access_rights = wallet != requestor;

        if requires_moderator_access_rights
            && !self
                .config
                .moderators
                .iter()
                .any(|wallet| wallet == requestor)
        {
            return Err(error::Error::Unauthorized);
        }

        let expr = self.build_rewards_filter_expr(from, to, community)?;
        let filter = doc! {
            format!("wallets.0x{}", hex::encode(wallet)): { "$exists": true },
            "$expr": bson::to_bson(&expr)?,
        };

        let res = tokio::time::timeout(
            self.db_client.req_timeout,
            self.db_client
                .collection()
                .count(filter, CountOptions::default()),
        )
        .await?
        .map_err(error::Error::from);

        tracing::debug!("Count total rewards by wallet ({wallet:?}) result: {res:?}");

        res
    }

    /// Searches rewards allocated for user within MongoDB by provided wallet EVM-like address [`Address`] and returns [`Vec<Rewards>`]
    #[allow(clippy::too_many_arguments)]
    pub async fn get_rewards_by_wallet(
        &self,
        requestor: &Address,
        wallet: &Address,
        start: Option<u64>,
        limit: Option<u64>,
        from: Option<u64>,
        to: Option<u64>,
        community: Option<&str>,
    ) -> Result<Vec<Rewards>, error::Error> {
        let start = start.unwrap_or_default();
        let limit = limit
            .unwrap_or(DEFAULT_GET_REWARDS_LIMIT)
            .clamp(1, MAX_GET_REWARDS_LIMIT) as i64;

        let requires_moderator_access_rights = wallet != requestor;

        if requires_moderator_access_rights
            && !self
                .config
                .moderators
                .iter()
                .any(|wallet| wallet == requestor)
        {
            return Err(error::Error::Unauthorized);
        }

        let expr = self.build_rewards_filter_expr(from, to, community)?;
        let filter = doc! {
            format!("wallets.0x{}", hex::encode(wallet)): { "$exists": true },
            "$expr": bson::to_bson(&expr)?,
        };

        let find_options = FindOptions::builder()
            .max_time(self.db_client.req_timeout)
            .skip(start)
            .limit(limit)
            .projection(doc! {
                "id": 1,
                "status": 1,
                format!("wallets.0x{}", hex::encode(wallet)): 1
            })
            .build();

        let res = tokio::time::timeout(self.db_client.req_timeout, async {
            let mut results = Vec::with_capacity(limit as usize);
            let mut stream = self
                .db_client
                .collection()
                .find(filter, find_options)
                .await?;
            while let Ok(Some(doc)) = stream.try_next().await {
                let rewards =
                    bson::from_document::<RewardsDbEntry>(doc).map_err(error::Error::from)?;
                results.push(rewards);
            }
            Ok(results)
        })
        .await?;

        tracing::debug!("Get rewards by wallet ({wallet:?}) result: {res:?}");

        res.map(|entries| {
            entries
                .into_iter()
                .map(|db_entry| Rewards {
                    id: db_entry.id,
                    timestamp: db_entry
                        .wallets
                        .values()
                        .next()
                        .map(|reward_db_entry| reward_db_entry.timestamp)
                        .unwrap_or_default(),
                    rewards_by_wallet: db_entry
                        .wallets
                        .into_iter()
                        .map(|(wallet, reward_db_entry)| {
                            (
                                wallet,
                                RewardInfo::from((db_entry.id, wallet, reward_db_entry)),
                            )
                        })
                        .collect(),
                    status: db_entry.status,
                })
                .collect()
        })
    }

    fn build_rewards_filter_expr(
        &self,
        from: Option<u64>,
        to: Option<u64>,
        community: Option<&str>,
    ) -> Result<Document, error::Error> {
        let mut in_and_cond_doc = doc! {
            "$and": []
        };

        let mut cond = doc! {};

        if let Some(community) = community {
            cond.insert("$eq", bson::to_bson(&["$$wallet.v.community", community])?);

            in_and_cond_doc.get_array_mut("$and")?.push(
                doc! {
                    "$gt": [{ "$size": "$$entries" }, 0]
                }
                .into(),
            );
        }

        if from.is_some() || to.is_some() {
            if let Some(from) = from {
                in_and_cond_doc.get_array_mut("$and")?.push(
                    doc! {
                        "$gte": ["$$timestamp", bson::to_bson(&from)?]
                    }
                    .into(),
                );
            }

            if let Some(to) = to {
                in_and_cond_doc.get_array_mut("$and")?.push(
                    doc! {
                        "$lt": ["$$timestamp", bson::to_bson(&to)?]
                    }
                    .into(),
                );
            }
        }

        Ok(doc! {
            "$let":{
                "vars":{
                    "entries":{
                        "$filter":{
                            "input":{
                                "$objectToArray":"$wallets"
                            },
                            "as":"wallet",
                            "cond": cond
                        }
                    }
                },
                "in":{
                    "$let": {
                        "vars": {
                            "timestamp":{
                                "$arrayElemAt":[{
                                    "$map":{
                                        "input":"$$entries",
                                        "as":"entry",
                                        "in":"$$entry.v.timestamp"
                                    }
                                },0]
                            }
                        },
                        "in": in_and_cond_doc
                    }
                }
            }
        })
    }
}
