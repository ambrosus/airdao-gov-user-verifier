use airdao_gov_portal_db::session_manager::SessionConfig;
use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct GovDbConfig {
    /// Session tokens configuration to allow access to database
    pub session: SessionConfig,
    /// DB service request maximum timeout in seconds
    #[serde(default = "default_request_timeout")]
    pub request_timeout: u64,
}

fn default_request_timeout() -> u64 {
    10
}
