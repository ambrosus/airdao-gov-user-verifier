mod config;
mod error;
mod fractal;
mod server;
mod signer;
mod verification;

use shared::logger;

use crate::config::AppConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    logger::init();
    shared::utils::set_heavy_panic();

    // Try load environment variables from `.env` if provided
    dotenv::dotenv().ok();

    let config = shared::utils::load_config::<AppConfig>("./").await?;

    tracing::info!(
        "Signer's public address: 0x{}",
        hex::encode(
            config
                .signer
                .signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
        )
    );

    server::start(config).await?;

    Ok(())
}
