use ethabi::Address;
use serde::Deserialize;
use std::collections::HashSet;
use web3::{contract, transports::Http};

use crate::validators_manager::ValidatorsManager;
use shared::{rpc_node_client::RpcNodeClient, utils};

#[derive(Clone)]
pub struct ServerNodesManager {
    pub contract: contract::Contract<Http>,
    validators_manager: ValidatorsManager,
    request_timeout: std::time::Duration,
}

#[derive(Clone, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ServerNodesManagerConfig {
    pub contract: Address,
    #[serde(deserialize_with = "utils::de_secs_duration")]
    pub max_allowed_time_since_last_reward: std::time::Duration,
}

impl ServerNodesManager {
    pub async fn new(
        config: &ServerNodesManagerConfig,
        client: RpcNodeClient,
    ) -> contract::Result<Self> {
        let server_nodes_manager_artifact = include_str!("../artifacts/ServerNodes_Manager.json");
        let request_timeout = client.config.request_timeout;
        let snm_contract = client.load_contract(config.contract, server_nodes_manager_artifact)?;

        let validators_manager_address = tokio::time::timeout(
            request_timeout,
            snm_contract.query::<ethereum_types::Address, _, _, _>(
                "validatorSet",
                (),
                None,
                contract::Options::default(),
                None,
            ),
        )
        .await
        .map_err(|_| {
            contract::Error::Api(web3::Error::Io(std::io::ErrorKind::TimedOut.into()))
        })??;

        let validators_manager = ValidatorsManager::new(
            validators_manager_address,
            config.max_allowed_time_since_last_reward,
            client,
        )?;

        Ok(Self {
            contract: snm_contract,
            validators_manager,
            request_timeout,
        })
    }

    pub async fn is_active(&self) -> contract::Result<bool> {
        tokio::time::timeout(
            self.request_timeout,
            self.contract
                .query("paused", (), None, contract::Options::default(), None),
        )
        .await
        .map_err(|_| contract::Error::Api(web3::Error::Io(std::io::ErrorKind::TimedOut.into())))?
        .map(|paused: bool| !paused)
    }

    pub async fn is_validator_node_owner(&self, wallet: Address) -> contract::Result<bool> {
        let owned_nodes = self.get_owned_nodes_by_wallet(wallet).await?;

        for node in owned_nodes {
            if matches!(
                self.validators_manager.is_validator_node(node).await,
                Ok(true)
            ) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    async fn get_owned_nodes_by_wallet(&self, wallet: Address) -> contract::Result<Vec<Address>> {
        let nodes = self.get_user_stakes_list(wallet).await?;
        let onboarding_nodes = self
            .get_onboarding_waiting_list()
            .await?
            .into_iter()
            .collect::<HashSet<_>>();

        Ok(nodes
            .into_iter()
            .filter(|node| !onboarding_nodes.contains(node))
            .collect())
    }

    async fn get_user_stakes_list(&self, owner: Address) -> contract::Result<Vec<Address>> {
        tokio::time::timeout(
            self.request_timeout,
            self.contract.query(
                "getUserStakesList",
                owner,
                None,
                contract::Options::default(),
                None,
            ),
        )
        .await
        .map_err(|_| contract::Error::Api(web3::Error::Io(std::io::ErrorKind::TimedOut.into())))?
    }

    async fn get_onboarding_waiting_list(&self) -> contract::Result<Vec<Address>> {
        tokio::time::timeout(
            self.request_timeout,
            self.contract.query(
                "getOnboardingWaitingList",
                (),
                None,
                contract::Options::default(),
                None,
            ),
        )
        .await
        .map_err(|_| contract::Error::Api(web3::Error::Io(std::io::ErrorKind::TimedOut.into())))?
    }
}
