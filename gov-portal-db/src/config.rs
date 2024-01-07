use serde::Deserialize;

use crate::{
    session_token::SessionConfig,
    users_manager::{mongo_client::MongoConfig, UserRegistrationConfig},
};

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AppConfig {
    pub listen_address: String,
    pub session: SessionConfig,
    pub registration: UserRegistrationConfig,
    pub mongo: MongoConfig,
}
