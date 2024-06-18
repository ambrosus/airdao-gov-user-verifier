use serde::Deserialize;

use crate::{explorer_client::ExplorerConfig, fractal::FractalConfig, signer::SignerConfig};

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AppConfig {
    pub listen_address: String,
    pub fractal: FractalConfig,
    pub signer: SignerConfig,
    pub users_manager_secret: String,
    pub explorer: ExplorerConfig,
}
