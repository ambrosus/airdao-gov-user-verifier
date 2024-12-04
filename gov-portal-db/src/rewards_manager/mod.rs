pub mod client;
pub mod error;
mod rewards_cache;

use bson::{doc, Document};
use ethereum_types::{Address, U256};
use futures_util::TryStreamExt;
use mongodb::options::{CountOptions, FindOptions, UpdateOptions};
use rewards_cache::{RewardsCache, RewardsDelta};
use serde::Deserialize;
use std::time::Duration;

use shared::common::{
    BatchId, RewardDbEntry, RewardInfo, RewardStatus, Rewards, RewardsDbEntry, UpdateRewardKind,
};

use crate::mongo_client::{MongoClient, MongoConfig};
use client::RewardsDbClient;

const DEFAULT_MAX_GET_REWARDS_LIMIT: u64 = 100;
const DEFAULT_GET_REWARDS_LIMIT: u64 = 100;

/// Rewards manager's [`RewardsManager`] settings
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RewardsManagerConfig {
    pub moderators: Vec<Address>,
    /// MongoDB rewards collection name
    pub collection: String,
    #[serde(
        deserialize_with = "shared::utils::de_secs_duration",
        default = "default_max_csv_report_date_range"
    )]
    pub max_csv_report_date_range: Duration,
    #[serde(default = "default_max_get_rewards_limit")]
    pub max_get_rewards_limit: u64,
}

pub fn default_max_get_rewards_limit() -> u64 {
    DEFAULT_MAX_GET_REWARDS_LIMIT
}

pub fn default_max_csv_report_date_range() -> Duration {
    Duration::from_secs(16_070_400) // 186 days
}

/// User profiles manager which provides read/write access to user profile data stored MongoDB
pub struct RewardsManager {
    pub db_client: RewardsDbClient,
    pub config: RewardsManagerConfig,
    pub rewards_cache: RewardsCache,
}

impl RewardsManager {
    /// Constructs [`RewardsManager`] with provided confuguration
    pub async fn new(
        mongo_config: &MongoConfig,
        config: RewardsManagerConfig,
    ) -> anyhow::Result<Self> {
        let db_client = RewardsDbClient::new(mongo_config, &config.collection).await?;

        let mut rewards = Vec::with_capacity(config.max_get_rewards_limit as usize);

        loop {
            let fetched = Self::load_all_rewards(
                &db_client,
                rewards.len() as u64,
                config.max_get_rewards_limit,
            )
            .await?;

            if fetched.is_empty() {
                break;
            }

            rewards.extend(fetched);
        }

        let rewards_cache = RewardsCache::try_spawn(rewards)?;

        Ok(Self {
            db_client,
            config,
            rewards_cache,
        })
    }

    /// Update reward struct at MongoDB by reward id [`BatchId`]
    pub async fn update_reward(&self, update_kind: UpdateRewardKind) -> Result<(), error::Error> {
        let (query, set_doc, rewards_delta) = match update_kind {
            UpdateRewardKind::Grant(reward) => {
                let (id, wallet, reward_entry) = <(BatchId, Address, RewardDbEntry)>::from(reward);

                let query = doc! {
                    "id": bson::to_bson(&id)?,
                };
                let set_doc = doc! {
                    "id": bson::to_bson(&id)?,
                    format!("wallets.0x{}", hex::encode(wallet)): bson::to_bson(&reward_entry)?,
                };

                (
                    query,
                    set_doc,
                    // [`BatchId`] is a block number in which it was created
                    RewardsDelta::Grant(id.0, id, wallet, reward_entry.amount),
                )
            }
            UpdateRewardKind::Claim {
                block_number,
                wallet,
                id,
            } => {
                let query = doc! {
                    "id": bson::to_bson(&id)?,
                };
                let set_doc = doc! {
                    "id": bson::to_bson(&id)?,
                    format!("wallets.0x{}.status", hex::encode(wallet)): bson::to_bson(&RewardStatus::Claimed)?,
                };

                (
                    query,
                    set_doc,
                    RewardsDelta::Claim(block_number, id, wallet),
                )
            }
            UpdateRewardKind::Revert { block_number, id } => {
                let query = doc! {
                    "id": bson::to_bson(&id)?,
                };
                let set_doc = doc! {
                    "id": bson::to_bson(&id)?,
                    "status": bson::to_bson(&RewardStatus::Reverted)?,
                };

                (query, set_doc, RewardsDelta::RevertBatch(block_number, id))
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
            Ok(_) => self.rewards_cache.push_rewards_delta(rewards_delta),
            Err(e) => Err(e.into()),
        }
    }

    async fn load_all_rewards(
        db_client: &RewardsDbClient,
        start: u64,
        limit: u64,
    ) -> Result<Vec<RewardsDbEntry>, error::Error> {
        let find_options = FindOptions::builder()
            .max_time(db_client.req_timeout)
            .skip(start)
            .limit(limit.max(i64::MAX as u64) as i64)
            .build();

        tokio::time::timeout(db_client.req_timeout, async {
            let mut results = Vec::with_capacity(limit as usize);
            let mut stream = db_client.collection().find(doc! {}, find_options).await?;
            while let Ok(Some(doc)) = stream.try_next().await {
                let rewards =
                    bson::from_document::<RewardsDbEntry>(doc).map_err(error::Error::from)?;
                results.push(rewards);
            }
            Ok(results)
        })
        .await?
    }

    pub fn get_available_rewards(
        &self,
        requestor: &Address,
        wallet: &Address,
    ) -> Result<U256, error::Error> {
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

        Ok(self.rewards_cache.get_available_rewards(wallet))
    }

    pub fn get_total_rewards(&self, requestor: &Address) -> Result<U256, error::Error> {
        if !self
            .config
            .moderators
            .iter()
            .any(|wallet| wallet == requestor)
        {
            return Err(error::Error::Unauthorized);
        }
        Ok(self.rewards_cache.get_total_rewards())
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

        let expr = Self::build_rewards_filter_expr(from, to, community)?;
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
            .clamp(1, self.config.max_get_rewards_limit) as i64;

        if !self
            .config
            .moderators
            .iter()
            .any(|wallet| wallet == requestor)
        {
            return Err(error::Error::Unauthorized);
        }

        let expr = Self::build_rewards_filter_expr(from, to, community)?;
        let filter = doc! {
            "$expr": expr
        };

        let find_options = FindOptions::builder()
            .max_time(self.db_client.req_timeout)
            .sort(doc! {
                "id": -1,
            })
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

        let expr = Self::build_rewards_filter_expr(from, to, community)?;
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
            .clamp(1, self.config.max_get_rewards_limit) as i64;

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

        let expr = Self::build_rewards_filter_expr(from, to, community)?;
        let filter = doc! {
            format!("wallets.0x{}", hex::encode(wallet)): { "$exists": true },
            "$expr": bson::to_bson(&expr)?,
        };

        let find_options = FindOptions::builder()
            .max_time(self.db_client.req_timeout)
            .sort(doc! {
                "id": -1,
            })
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
