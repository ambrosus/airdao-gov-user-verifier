use std::collections::HashSet;

use ethabi::Address;
use web3::{contract, transports::Http};

use crate::rpc_node_client::RpcNodeClient;

#[derive(Clone)]
pub struct ServerNodesManager {
    contract: contract::Contract<Http>,
    request_timeout: std::time::Duration,
}

impl ServerNodesManager {
    pub fn new(address: Address, client: RpcNodeClient) -> contract::Result<Self> {
        let server_nodes_manager_artifact = include_str!("../artifacts/ServerNodes_Manager.json");

        Ok(Self {
            contract: client.load_contract(address, server_nodes_manager_artifact)?,
            request_timeout: client.config.request_timeout,
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

    pub async fn is_node_owner(&self, wallet: Address) -> contract::Result<bool> {
        let nodes = self.get_user_stakes_list(wallet).await?;
        let onboarding_nodes = self
            .get_onboarding_waiting_list()
            .await?
            .into_iter()
            .collect::<HashSet<_>>();

        let is_node_operator = nodes
            .into_iter()
            .filter(|node| !onboarding_nodes.contains(node))
            .count()
            > 0;

        Ok(is_node_operator)
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
