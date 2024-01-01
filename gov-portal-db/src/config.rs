use serde::Deserialize;

use crate::{mongo_client::MongoConfig, session_token::SessionConfig};

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AppConfig {
    pub listen_address: String,
    pub session: SessionConfig,
    pub mongo: MongoConfig,
}
