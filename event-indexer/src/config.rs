use ethereum_types::Address;
use serde::Deserialize;
use std::collections::HashMap;

use crate::gov_db_provider::GovDbConfig;

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AppConfig {
    pub redis: String,
    pub rpc_node: String,
    pub block_number: u64,
    /// Gov DB provider configuration
    pub db: GovDbConfig,
    pub contracts: HashMap<String, Address>,
}
