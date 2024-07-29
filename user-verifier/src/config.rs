use serde::Deserialize;

use crate::{
    explorer_client::ExplorerConfig, fractal::FractalConfig, rpc_node_client::RpcNodeConfig,
    server_nodes_manager::ServerNodesManagerConfig, signer::SignerConfig,
};

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AppConfig {
    pub listen_address: String,
    pub fractal: FractalConfig,
    pub signer: SignerConfig,
    pub users_manager_secret: String,
    pub explorer: ExplorerConfig,
    pub rpc_node: RpcNodeConfig,
    pub server_nodes_manager: ServerNodesManagerConfig,
}
