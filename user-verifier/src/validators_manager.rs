use chrono::{DateTime, Utc};
use ethabi::{Address, Uint};
use std::time::Duration;
use web3::{contract, transports::Http};

use crate::rpc_node_client::RpcNodeClient;

#[derive(Clone)]
pub struct ValidatorsManager {
    contract: contract::Contract<Http>,
    request_timeout: Duration,
    max_allowed_time_since_last_reward: Duration,
}

impl ValidatorsManager {
    pub fn new(
        address: Address,
        max_allowed_time_since_last_reward: Duration,
        client: RpcNodeClient,
    ) -> contract::Result<Self> {
        let validator_set_artifact = include_str!("../artifacts/ValidatorSet.json");
        let snm_contract = client.load_contract(address, validator_set_artifact)?;

        Ok(Self {
            contract: snm_contract,
            request_timeout: client.config.request_timeout,
            max_allowed_time_since_last_reward,
        })
    }

    pub async fn is_validator_node(&self, node: Address) -> contract::Result<bool> {
        tokio::time::timeout(
            self.request_timeout,
            self.contract.query(
                "latestNodeRewardTime",
                node,
                None,
                contract::Options::default(),
                None,
            ),
        )
        .await
        .map_err(|_| contract::Error::Api(web3::Error::Io(std::io::ErrorKind::TimedOut.into())))?
        .map(|last_reward_ts: Uint| {
            if let Some(last_reward_date) =
                DateTime::<Utc>::from_timestamp(last_reward_ts.as_u64() as i64, 0)
            {
                last_reward_date + self.max_allowed_time_since_last_reward > Utc::now()
            } else {
                false
            }
        })
    }
}
