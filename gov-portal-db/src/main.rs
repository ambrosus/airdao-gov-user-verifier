mod config;
mod error;
mod server;
mod session_token;
mod users_manager;

use std::sync::Arc;

use shared::{logger, utils};
use users_manager::UsersManager;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    logger::init();
    utils::set_heavy_panic();

    // Try load environment variables from `.env` if provided
    dotenv::dotenv().ok();

    let config = utils::load_config::<config::AppConfig>("./gov-portal-db").await?;

    let users_manager = Arc::new(UsersManager::new(&config).await?);

    server::start(config, users_manager.clone()).await?;

    Ok(())
}
