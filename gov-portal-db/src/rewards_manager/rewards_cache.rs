use ethereum_types::{Address, U256};
use parking_lot::RwLock;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::mpsc;

use shared::common::{BatchId, RewardStatus, RewardsDbEntry};

use super::error;

const REWARDS_BUF_LENGTH: usize = 128;

pub struct RewardsCache {
    total_rewards: Arc<RwLock<Reward>>,
    available_rewards_by_wallets: Arc<RwLock<HashMap<Address, Reward>>>,
    unclaimed_rewards: Arc<RwLock<HashMap<BatchId, HashMap<Address, Reward>>>>,
    total_rewards_tx: mpsc::UnboundedSender<RewardsDelta>,
}

#[derive(Default, Debug)]
pub struct Reward {
    pub updated_at_block: u64,
    pub amount: U256,
}

impl Reward {
    pub fn new(amount: U256, block_number: u64) -> Self {
        Self {
            amount,
            updated_at_block: block_number,
        }
    }

    pub fn add(&mut self, diff_amount: U256, block_number: u64) {
        if self.updated_at_block < block_number {
            self.amount = self.amount.saturating_add(diff_amount);
            self.updated_at_block = block_number;
        }
    }

    pub fn sub(&mut self, diff_amount: U256, block_number: u64) {
        if self.updated_at_block < block_number {
            self.amount = self.amount.saturating_sub(diff_amount);
            self.updated_at_block = block_number;
        }
    }
}

#[derive(Debug)]
pub enum RewardsDelta {
    Grant(u64, BatchId, Address, U256),
    Claim(u64, BatchId, Address),
    RevertBatch(u64, BatchId),
}

impl RewardsCache {
    pub fn init(rewards: Vec<RewardsDbEntry>) -> Result<Self, error::Error> {
        let (total_rewards_tx, mut total_rewards_rx) = mpsc::unbounded_channel();

        let mut total_rewards = Reward::default();
        let mut available_rewards_by_wallet =
            HashMap::<Address, Reward>::with_capacity(rewards.len());
        let mut unclaimed_rewards = HashMap::<BatchId, HashMap<Address, Reward>>::default();

        for entry in rewards {
            if entry.status == RewardStatus::Claimed {
                return Err(anyhow::anyhow!("Unexpected status for a batch {entry:?}").into());
            }

            // [`BatchId`] is a block number in which it was created
            let block_number = entry.id.0;

            for (wallet, reward) in entry.wallets {
                match reward.status {
                    // If batch was reverted
                    RewardStatus::Granted if entry.status != RewardStatus::Granted => {
                        continue;
                    }
                    RewardStatus::Granted => {
                        total_rewards.add(reward.amount, block_number);

                        unclaimed_rewards
                            .entry(entry.id)
                            .or_default()
                            .insert(wallet, Reward::new(reward.amount, block_number));
                    }
                    RewardStatus::Claimed => {
                        total_rewards.add(reward.amount, block_number);
                        continue;
                    }
                    RewardStatus::Reverted => {
                        return Err(
                            anyhow::anyhow!("Unexpected status for reward {reward:?}").into()
                        );
                    }
                }

                available_rewards_by_wallet
                    .entry(wallet)
                    .or_default()
                    .add(reward.amount, block_number);
            }
        }

        let cache = Self {
            total_rewards_tx,
            total_rewards: Arc::new(RwLock::new(total_rewards)),
            available_rewards_by_wallets: Arc::new(RwLock::new(available_rewards_by_wallet)),
            unclaimed_rewards: Arc::new(RwLock::new(unclaimed_rewards)),
        };

        let total_rewards = cache.total_rewards.clone();
        let available_rewards_by_wallets = cache.available_rewards_by_wallets.clone();
        let unclaimed_rewards = cache.unclaimed_rewards.clone();

        tokio::spawn(async move {
            let mut total_rewards_buf = Vec::with_capacity(REWARDS_BUF_LENGTH);

            while total_rewards_rx
                .recv_many(&mut total_rewards_buf, REWARDS_BUF_LENGTH)
                .await
                > 0
            {
                let mut total_rewards = total_rewards.write();
                let mut available_rewards_by_wallets = available_rewards_by_wallets.write();
                let mut unclaimed_rewards = unclaimed_rewards.write();

                for rewards_delta in total_rewards_buf.drain(..) {
                    match rewards_delta {
                        RewardsDelta::Grant(block_number, id, wallet, amount) => {
                            total_rewards.add(amount, block_number);

                            unclaimed_rewards
                                .entry(id)
                                .or_default()
                                .insert(wallet, Reward::new(amount, block_number));

                            available_rewards_by_wallets
                                .entry(wallet)
                                .or_default()
                                .add(amount, block_number);
                        }
                        RewardsDelta::Claim(block_number, id, wallet) => {
                            unclaimed_rewards.entry(id).and_modify(|entry| {
                                entry.remove(&wallet);
                            });

                            if let Some(available_reward) =
                                available_rewards_by_wallets.get_mut(&wallet)
                            {
                                available_reward.sub(available_reward.amount, block_number);
                            }
                        }
                        RewardsDelta::RevertBatch(block_number, id) => {
                            let Some(rewards_by_wallets) = unclaimed_rewards.remove(&id) else {
                                continue;
                            };

                            for (wallet, reward) in rewards_by_wallets {
                                if let Some(available_reward) =
                                    available_rewards_by_wallets.get_mut(&wallet)
                                {
                                    available_reward.sub(reward.amount, block_number);
                                }

                                total_rewards.sub(reward.amount, block_number);
                            }
                        }
                    }
                }
            }
        });

        Ok(cache)
    }

    pub fn push_rewards_delta(&self, rewards_delta: RewardsDelta) -> Result<(), error::Error> {
        self.total_rewards_tx
            .send(rewards_delta)
            .map_err(error::Error::from)
    }

    pub fn get_available_rewards(&self, wallet: &Address) -> U256 {
        self.available_rewards_by_wallets
            .read()
            .get(wallet)
            .map(|reward| reward.amount)
            .unwrap_or_default()
    }

    pub fn get_total_rewards(&self) -> U256 {
        self.total_rewards.read().amount
    }
}
