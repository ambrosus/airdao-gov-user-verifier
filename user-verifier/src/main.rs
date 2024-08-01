mod config;
mod error;
mod explorer_client;
mod fractal;
mod rpc_node_client;
mod server;
mod server_nodes_manager;
mod signer;
mod validators_manager;
mod verification;

use shared::{logger, utils::get_eth_address};

use crate::config::AppConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    logger::init();
    shared::utils::set_heavy_panic();

    // Try load environment variables from `.env` if provided
    dotenv::dotenv().ok();

    let config = shared::utils::load_config::<AppConfig>("./").await?;

    tracing::info!(
        "HumanSBT Signer's public address: 0x{}",
        hex::encode(get_eth_address(
            config
                .signer
                .keys
                .issuer_human_sbt
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
        ))
    );

    tracing::info!(
        "OGSBT Signer's public address: 0x{}",
        hex::encode(get_eth_address(
            config
                .signer
                .keys
                .issuer_og_sbt
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
        ))
    );

    tracing::info!(
        "SNOSBT Signer's public address: 0x{}",
        hex::encode(get_eth_address(
            config
                .signer
                .keys
                .issuer_sno_sbt
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
        ))
    );

    server::start(config).await?;

    Ok(())
}
