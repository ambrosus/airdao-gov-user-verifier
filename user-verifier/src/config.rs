use serde::Deserialize;

use crate::{fractal::FractalConfig, signer::SignerConfig};
use shared::common::UserDbConfig;

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AppConfig {
    pub listen_address: String,
    pub fractal: FractalConfig,
    pub signer: SignerConfig,
    pub user_db: UserDbConfig,
}
