use crate::gov_db_provider::GovDbConfig;
use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AppConfig {
    /// Gov DB provider configuration
    pub db: GovDbConfig,
}
