use ethereum_types::{Address, U256};
use parking_lot::RwLock;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::mpsc;

use shared::common::{BatchId, RewardStatus, RewardsDbEntry};

use super::error;

const REWARDS_BUF_LENGTH: usize = 128;

#[cfg_attr(test, derive(Debug))]
pub struct RewardsCache {
    total_rewards: Arc<RwLock<Reward>>,
    available_rewards_by_wallets: Arc<RwLock<HashMap<Address, Reward>>>,
    unclaimed_rewards: Arc<RwLock<HashMap<BatchId, HashMap<Address, Reward>>>>,
    total_rewards_tx: mpsc::UnboundedSender<RewardsDelta>,
}

#[derive(Default, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
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
        self.amount = self.amount.saturating_add(diff_amount);
        self.updated_at_block = block_number;
    }

    pub fn sub(&mut self, diff_amount: U256, block_number: u64) {
        self.amount = self.amount.saturating_sub(diff_amount);
        self.updated_at_block = block_number;
    }
}

#[derive(Debug)]
pub enum RewardsDelta {
    Grant(u64, BatchId, Address, U256),
    Claim(u64, BatchId, Address),
    RevertBatch(u64, BatchId),
}

impl RewardsCache {
    fn new(
        total_rewards_tx: mpsc::UnboundedSender<RewardsDelta>,
        mut rewards: Vec<RewardsDbEntry>,
    ) -> Result<Self, error::Error> {
        rewards.sort_by(|l, r| l.id.cmp(&r.id));

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

        Ok(Self {
            total_rewards_tx,
            total_rewards: Arc::new(RwLock::new(total_rewards)),
            available_rewards_by_wallets: Arc::new(RwLock::new(available_rewards_by_wallet)),
            unclaimed_rewards: Arc::new(RwLock::new(unclaimed_rewards)),
        })
    }

    pub fn try_spawn(rewards: Vec<RewardsDbEntry>) -> Result<Self, error::Error> {
        let (total_rewards_tx, mut total_rewards_rx) = mpsc::unbounded_channel();

        let cache = Self::new(total_rewards_tx, rewards)?;

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
                            if unclaimed_rewards
                                .entry(id)
                                .or_default()
                                .insert(wallet, Reward::new(amount, block_number))
                                .is_none()
                            {
                                total_rewards.add(amount, block_number);

                                available_rewards_by_wallets
                                    .entry(wallet)
                                    .or_default()
                                    .add(amount, block_number);
                            }
                        }
                        RewardsDelta::Claim(block_number, id, wallet) => {
                            unclaimed_rewards.entry(id).and_modify(|entry| {
                                let Some(claimed_reward) = entry.remove(&wallet) else {
                                    return;
                                };

                                if let Some(available_reward) =
                                    available_rewards_by_wallets.get_mut(&wallet)
                                {
                                    available_reward.sub(claimed_reward.amount, block_number);
                                }
                            });

                            unclaimed_rewards.retain(|_, entry| !entry.is_empty());
                        }
                        RewardsDelta::RevertBatch(block_number, id) => {
                            let Some(unclaimed_rewards_by_wallets) = unclaimed_rewards.remove(&id)
                            else {
                                continue;
                            };

                            let mut total_reverted = U256::zero();

                            for (wallet, reward) in unclaimed_rewards_by_wallets {
                                if let Some(available_reward) =
                                    available_rewards_by_wallets.get_mut(&wallet)
                                {
                                    available_reward.sub(reward.amount, block_number);
                                }

                                total_reverted = total_reverted.saturating_add(reward.amount);
                            }

                            total_rewards.sub(total_reverted, block_number);
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

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use ethereum_types::{Address, U256};
    use ethers::utils::parse_ether;
    use std::{str::FromStr, time::Duration};

    use super::RewardsCache;
    use crate::rewards_manager::rewards_cache::{Reward, RewardsDelta};
    use shared::common::{BatchId, RewardsDbEntry};

    #[tokio::test]
    async fn test_cache() {
        let rewards_json = r#"[
            {
                "id": 2732965,
                "rewardsByWallet": {
                    "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d": {
                        "id": 2732965,
                        "grantor": "0xd283e63f1058bc47caae25f930b32e8f46485190",
                        "wallet": "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d",
                        "amount": "0x4563918244f40000",
                        "timestamp": 1733239765,
                        "eventName": "37",
                        "region": "Middle-East",
                        "community": "China"
                    }
                },
                "timestamp": 1733239765
            },
            {
                "id": 2732962,
                "rewardsByWallet": {
                    "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d": {
                        "id": 2732962,
                        "grantor": "0xd283e63f1058bc47caae25f930b32e8f46485190",
                        "wallet": "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d",
                        "amount": "0x29a2241af62c0000",
                        "timestamp": 1733239750,
                        "eventName": "355",
                        "region": "Europe",
                        "community": "French"
                    }
                },
                "timestamp": 1733239750
            },
            {
                "id": 2732723,
                "rewardsByWallet": {
                    "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d": {
                        "id": 2732723,
                        "grantor": "0xd283e63f1058bc47caae25f930b32e8f46485190",
                        "wallet": "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d",
                        "amount": "0xde0b6b3a7640000",
                        "timestamp": 1733237910,
                        "eventName": "15",
                        "region": "Europe",
                        "community": "China",
                        "status": "claimed"
                    }
                },
                "timestamp": 1733237910
            },
            {
                "id": 2732596,
                "rewardsByWallet": {
                    "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d": {
                        "id": 2732596,
                        "grantor": "0xd283e63f1058bc47caae25f930b32e8f46485190",
                        "wallet": "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d",
                        "amount": "0xde0b6b3a7640000",
                        "timestamp": 1733236950,
                        "eventName": "31",
                        "region": "LATAM",
                        "community": "French",
                        "status": "claimed"
                    }
                },
                "timestamp": 1733236950
            },
            {
                "id": 2732525,
                "rewardsByWallet": {
                    "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d": {
                        "id": 2732525,
                        "grantor": "0xd283e63f1058bc47caae25f930b32e8f46485190",
                        "wallet": "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d",
                        "amount": "0x29a2241af62c0000",
                        "timestamp": 1733236395,
                        "eventName": "Summer Winter 123 321 test long text 123 ",
                        "region": "Europe",
                        "community": "Global",
                        "pseudo": "test1",
                        "status": "claimed"
                    }
                },
                "timestamp": 1733236395
            },
            {
                "id": 2732520,
                "rewardsByWallet": {
                    "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d": {
                        "id": 2732520,
                        "grantor": "0xd283e63f1058bc47caae25f930b32e8f46485190",
                        "wallet": "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d",
                        "amount": "0xde0b6b3a7640000",
                        "timestamp": 1733236350,
                        "eventName": "Summer",
                        "region": "Asia",
                        "community": "China",
                        "status": "claimed"
                    }
                },
                "timestamp": 1733236350
            },
            {
                "id": 2732517,
                "rewardsByWallet": {
                    "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d": {
                        "id": 2732517,
                        "grantor": "0xd283e63f1058bc47caae25f930b32e8f46485190",
                        "wallet": "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d",
                        "amount": "0xde0b6b3a7640000",
                        "timestamp": 1733236330,
                        "eventName": "125",
                        "region": "Europe",
                        "community": "French",
                        "status": "claimed"
                    }
                },
                "timestamp": 1733236330
            },
            {
                "id": 2732447,
                "rewardsByWallet": {
                    "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d": {
                        "id": 2732447,
                        "grantor": "0xd283e63f1058bc47caae25f930b32e8f46485190",
                        "wallet": "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d",
                        "amount": "0x6124fee993bc0000",
                        "timestamp": 1733235795,
                        "eventName": "Winter",
                        "region": "Europe",
                        "community": "French",
                        "status": "claimed"
                    }
                },
                "timestamp": 1733235795
            },
            {
                "id": 2732443,
                "rewardsByWallet": {
                    "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d": {
                        "id": 2732443,
                        "grantor": "0xd283e63f1058bc47caae25f930b32e8f46485190",
                        "wallet": "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d",
                        "amount": "0x29a2241af62c0000",
                        "timestamp": 1733235770,
                        "eventName": "255",
                        "region": "Global",
                        "community": "Turkey"
                    }
                },
                "timestamp": 1733235770,
                "status": "reverted"
            },
            {
                "id": 2732439,
                "rewardsByWallet": {
                    "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d": {
                        "id": 2732439,
                        "grantor": "0xd283e63f1058bc47caae25f930b32e8f46485190",
                        "wallet": "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d",
                        "amount": "0x29a2241af62c0000",
                        "timestamp": 1733235735,
                        "eventName": "21",
                        "region": "Middle-East",
                        "community": "China",
                        "status": "claimed"
                    }
                },
                "timestamp": 1733235735
            },
            {
                "id": 2732046,
                "rewardsByWallet": {
                    "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d": {
                        "id": 2732046,
                        "grantor": "0xd283e63f1058bc47caae25f930b32e8f46485190",
                        "wallet": "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d",
                        "amount": "0x4563918244f40000",
                        "timestamp": 1733232730,
                        "eventName": "Winter",
                        "region": "Europe",
                        "community": "French"
                    }
                },
                "timestamp": 1733232730,
                "status": "reverted"
            },
            {
                "id": 2732043,
                "rewardsByWallet": {
                    "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d": {
                        "id": 2732043,
                        "grantor": "0xd283e63f1058bc47caae25f930b32e8f46485190",
                        "wallet": "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d",
                        "amount": "0x29a2241af62c0000",
                        "timestamp": 1733232700,
                        "eventName": "33",
                        "region": "Middle-East",
                        "community": "Korea",
                        "status": "claimed"
                    }
                },
                "timestamp": 1733232700
            },
            {
                "id": 2732012,
                "rewardsByWallet": {
                    "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d": {
                        "id": 2732012,
                        "grantor": "0xd283e63f1058bc47caae25f930b32e8f46485190",
                        "wallet": "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d",
                        "amount": "0x4563918244f40000",
                        "timestamp": 1733232450,
                        "eventName": "17",
                        "region": "Africa",
                        "community": "Ghana",
                        "status": "claimed"
                    }
                },
                "timestamp": 1733232450
            },
            {
                "id": 2732008,
                "rewardsByWallet": {
                    "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d": {
                        "id": 2732008,
                        "grantor": "0xd283e63f1058bc47caae25f930b32e8f46485190",
                        "wallet": "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d",
                        "amount": "0xde0b6b3a7640000",
                        "timestamp": 1733232425,
                        "eventName": "17",
                        "region": "Asia",
                        "community": "China",
                        "status": "claimed"
                    }
                },
                "timestamp": 1733232425
            },
            {
                "id": 2731977,
                "rewardsByWallet": {
                    "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d": {
                        "id": 2731977,
                        "grantor": "0xd283e63f1058bc47caae25f930b32e8f46485190",
                        "wallet": "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d",
                        "amount": "0x1bc16d674ec80000",
                        "timestamp": 1733232185,
                        "eventName": "33",
                        "region": "Europe",
                        "community": "Portuguese",
                        "status": "claimed"
                    }
                },
                "timestamp": 1733232185
            },
            {
                "id": 2731972,
                "rewardsByWallet": {
                    "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d": {
                        "id": 2731972,
                        "grantor": "0xd283e63f1058bc47caae25f930b32e8f46485190",
                        "wallet": "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d",
                        "amount": "0xde0b6b3a7640000",
                        "timestamp": 1733232150,
                        "eventName": "33",
                        "region": "Middle-East",
                        "community": "India",
                        "status": "claimed"
                    }
                },
                "timestamp": 1733232150
            },
            {
                "id": 2731943,
                "rewardsByWallet": {
                    "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d": {
                        "id": 2731943,
                        "grantor": "0xd283e63f1058bc47caae25f930b32e8f46485190",
                        "wallet": "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d",
                        "amount": "0x4563918244f40000",
                        "timestamp": 1733231925,
                        "eventName": "15",
                        "region": "Europe",
                        "community": "French",
                        "status": "claimed"
                    }
                },
                "timestamp": 1733231925
            },
            {
                "id": 2731939,
                "rewardsByWallet": {
                    "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d": {
                        "id": 2731939,
                        "grantor": "0xd283e63f1058bc47caae25f930b32e8f46485190",
                        "wallet": "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d",
                        "amount": "0x4563918244f40000",
                        "timestamp": 1733231895,
                        "eventName": "15",
                        "region": "Europe",
                        "community": "French"
                    }
                },
                "timestamp": 1733231895,
                "status": "reverted"
            },
            {
                "id": 2731935,
                "rewardsByWallet": {
                    "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d": {
                        "id": 2731935,
                        "grantor": "0xd283e63f1058bc47caae25f930b32e8f46485190",
                        "wallet": "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d",
                        "amount": "0x4563918244f40000",
                        "timestamp": 1733231870,
                        "eventName": "17",
                        "region": "Europe",
                        "community": "French",
                        "status": "claimed"
                    }
                },
                "timestamp": 1733231870
            },
            {
                "id": 2731902,
                "rewardsByWallet": {
                    "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d": {
                        "id": 2731902,
                        "grantor": "0xd283e63f1058bc47caae25f930b32e8f46485190",
                        "wallet": "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d",
                        "amount": "0x29a2241af62c0000",
                        "timestamp": 1733231610,
                        "eventName": "15",
                        "region": "Asia",
                        "community": "China",
                        "status": "claimed"
                    }
                },
                "timestamp": 1733231610
            },
            {
                "id": 2731898,
                "rewardsByWallet": {
                    "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d": {
                        "id": 2731898,
                        "grantor": "0xd283e63f1058bc47caae25f930b32e8f46485190",
                        "wallet": "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d",
                        "amount": "0xde0b6b3a7640000",
                        "timestamp": 1733231575,
                        "eventName": "15",
                        "region": "Europe",
                        "community": "French",
                        "status": "claimed"
                    }
                },
                "timestamp": 1733231575
            },
            {
                "id": 2731881,
                "rewardsByWallet": {
                    "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d": {
                        "id": 2731881,
                        "grantor": "0xd283e63f1058bc47caae25f930b32e8f46485190",
                        "wallet": "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d",
                        "amount": "0xd02ab486cedc0000",
                        "timestamp": 1733231445,
                        "eventName": "10",
                        "region": "LATAM",
                        "community": "Ghana",
                        "status": "claimed"
                    }
                },
                "timestamp": 1733231445
            },
            {
                "id": 2731875,
                "rewardsByWallet": {
                    "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d": {
                        "id": 2731875,
                        "grantor": "0xd283e63f1058bc47caae25f930b32e8f46485190",
                        "wallet": "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d",
                        "amount": "0x6124fee993bc0000",
                        "timestamp": 1733231400,
                        "eventName": "17",
                        "region": "Asia",
                        "community": "China",
                        "status": "claimed"
                    }
                },
                "timestamp": 1733231400
            },
            {
                "id": 2731873,
                "rewardsByWallet": {
                    "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d": {
                        "id": 2731873,
                        "grantor": "0xd283e63f1058bc47caae25f930b32e8f46485190",
                        "wallet": "0xd1f3ce9e92be95fb0086f4853d1a8ec4dd883d6d",
                        "amount": "0x4563918244f40000",
                        "timestamp": 1733231385,
                        "eventName": "123",
                        "region": "Global",
                        "community": "Global",
                        "status": "claimed"
                    }
                },
                "timestamp": 1733231385
            }
        ]"#;

        let rewards = serde_json::from_str::<Vec<shared::common::Rewards>>(rewards_json)
            .unwrap()
            .into_iter()
            .map(RewardsDbEntry::from)
            .collect::<Vec<_>>();

        let cache = RewardsCache::try_spawn(rewards).unwrap();

        let wallet = "0xd1F3ce9E92BE95fb0086F4853d1a8EC4Dd883d6D"
            .parse::<Address>()
            .unwrap();

        let wallet2 = "0xd1F3ce9E92BE95fb0086F4853d1a8EC4Dd883d6E"
            .parse::<Address>()
            .unwrap();

        assert_eq!(cache.total_rewards.read().updated_at_block, 2732965);
        assert_eq!(
            cache.total_rewards.read().amount,
            U256::from_str("0x43A77AABD00780000").unwrap()
        );
        assert_matches!(cache.available_rewards_by_wallets.read().get(&wallet), Some(&Reward { updated_at_block, amount }) if updated_at_block == 2732965 && amount == U256::from_str("0x6F05B59D3B200000").unwrap() );
        assert_eq!(cache.unclaimed_rewards.read().len(), 2);

        cache
            .total_rewards_tx
            .send(RewardsDelta::RevertBatch(2732966, BatchId(2732965)))
            .unwrap();

        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            cache.total_rewards.read().amount,
            U256::from_str("0x3F514193ABB840000").unwrap()
        );

        cache
            .total_rewards_tx
            .send(RewardsDelta::Claim(2732967, BatchId(2732962), wallet))
            .unwrap();
        cache
            .total_rewards_tx
            .send(RewardsDelta::Grant(
                2732969,
                BatchId(2732969),
                wallet,
                parse_ether("1.0").unwrap(),
            ))
            .unwrap();

        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            cache.total_rewards.read().amount,
            U256::from_str("0x402F4CFEE62E80000").unwrap()
        );

        cache
            .total_rewards_tx
            .send(RewardsDelta::RevertBatch(2732970, BatchId(2732969)))
            .unwrap();

        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            cache.total_rewards.read().amount,
            U256::from_str("0x3F514193ABB840000").unwrap()
        );

        cache
            .total_rewards_tx
            .send(RewardsDelta::Grant(
                2732971,
                BatchId(2732971),
                wallet,
                parse_ether("2.0").unwrap(),
            ))
            .unwrap();

        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            cache.total_rewards.read().amount,
            U256::from_str("0x410D586A20A4C0000").unwrap()
        );

        cache
            .total_rewards_tx
            .send(RewardsDelta::Grant(
                2732971,
                BatchId(2732971),
                wallet2,
                parse_ether("3.0").unwrap(),
            ))
            .unwrap();

        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            cache.total_rewards.read().amount,
            U256::from_str("0x43A77AABD00780000").unwrap()
        );

        cache
            .total_rewards_tx
            .send(RewardsDelta::Claim(2732972, BatchId(2732971), wallet))
            .unwrap();
        cache
            .total_rewards_tx
            .send(RewardsDelta::RevertBatch(2732973, BatchId(2732971)))
            .unwrap();

        tokio::time::sleep(Duration::from_millis(500)).await;

        assert_eq!(cache.total_rewards.read().updated_at_block, 2732973);
        assert_eq!(
            cache.total_rewards.read().amount,
            U256::from_str("0x410D586A20A4C0000").unwrap()
        );
        assert_matches!(cache.available_rewards_by_wallets.read().get(&wallet), Some(&Reward { updated_at_block, amount }) if updated_at_block == 2732972 && amount == U256::from_str("0x0").unwrap() );
        assert_matches!(cache.available_rewards_by_wallets.read().get(&wallet2), Some(&Reward { updated_at_block, amount }) if updated_at_block == 2732973 && amount == U256::from_str("0x0").unwrap() );
        assert!(cache.unclaimed_rewards.read().is_empty());
    }
}
