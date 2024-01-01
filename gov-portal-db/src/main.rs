mod config;
mod error;
mod mongo_client;
mod server;
mod session_token;

use shared::{logger, utils};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    logger::init();
    utils::set_heavy_panic();

    // Try load environment variables from `.env` if provided
    dotenv::dotenv().ok();

    let config = utils::load_config::<config::AppConfig>("./gov-portal-db").await?;

    server::start(config).await?;

    Ok(())
}
