use ethereum_types::Address;
use serde::Deserialize;
use std::collections::HashMap;

use crate::{
    quiz::QuizConfig,
    sbt::SBTKind,
    session_token::SessionConfig,
    users_manager::{mongo_client::MongoConfig, UsersManagerConfig},
};
use shared::rpc_node_client::RpcNodeConfig;

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AppConfig {
    /// Address for a REST server to listen on
    pub listen_address: String,
    /// Session tokens configuration to allow access to database
    pub session: SessionConfig,
    /// Users manager configuration
    pub users_manager: UsersManagerConfig,
    /// MongoDB client configuration
    pub mongo: MongoConfig,
    /// Quiz configuration
    pub quiz: QuizConfig,
    /// Rpc EVM-compatible node configuration
    pub rpc_node: RpcNodeConfig,
    /// SBT contract addresses list keyed by contract name
    pub sbt_contracts: HashMap<SBTKind, Address>,
}
