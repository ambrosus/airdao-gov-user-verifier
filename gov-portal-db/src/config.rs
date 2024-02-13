use serde::Deserialize;

use crate::{
    quiz::QuizConfig,
    session_token::SessionConfig,
    users_manager::{mongo_client::MongoConfig, UserRegistrationConfig},
};

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AppConfig {
    /// Address for a REST server to listen on
    pub listen_address: String,
    /// Session tokens configuration to allow access to database
    pub session: SessionConfig,
    /// User registration configuration
    pub registration: UserRegistrationConfig,
    /// MongoDB client configuration
    pub mongo: MongoConfig,
    /// Quiz configuration
    pub quiz: QuizConfig,
}
