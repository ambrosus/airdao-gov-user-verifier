mod config;
mod gov_db_provider;

use airdao_gov_portal_db::session_manager::SessionManager;
use clap::{Args, Parser, Subcommand};
use std::{sync::Arc, time::Duration};

use shared::{logger, utils};

const ONE_YEAR: u64 = 86_400 * 365; // one year in seconds

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    logger::init();
    utils::set_heavy_panic();

    // Try load environment variables from `.env` if provided
    dotenv::dotenv().ok();

    let config = utils::load_config::<config::AppConfig>("./event-indexer").await?;

    let session_manager = SessionManager::new(config.db.session.clone());

    Ok(())
}
