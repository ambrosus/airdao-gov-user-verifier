mod config;
mod error;
mod mongo_client;
mod quiz;
mod rewards_manager;
mod sbt;
mod server;
mod session_manager;
mod users_manager;

use clap::{Args, Parser, Subcommand};
use serde::de::{value::StrDeserializer, IntoDeserializer};
use std::{sync::Arc, time::Duration};

use rewards_manager::RewardsManager;
use session_manager::SessionManager;
use shared::{logger, utils};
use users_manager::UsersManager;

const ONE_YEAR: u64 = 86_400 * 365; // one year in seconds

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    logger::init();
    utils::set_heavy_panic();

    // Try load environment variables from `.env` if provided
    dotenv::dotenv().ok();

    let config = utils::load_config::<config::AppConfig>("./gov-portal-db").await?;

    let session_manager = SessionManager::new(config.session.clone());

    let cli = Cli::parse();
    match &cli.command {
        Some(Commands::GenToken(arg)) => {
            let lifetime = arg.lifetime.unwrap_or(ONE_YEAR);
            let token = match arg.private_key.as_deref() {
                Some(private_key) => {
                    let signing_key = utils::de_secp256k1_signing_key::<
                        '_,
                        StrDeserializer<serde_json::Error>,
                    >(private_key.into_deserializer())?;
                    session_manager.acquire_token_with_signing_key(signing_key)?
                }
                None => session_manager
                    .acquire_internal_token_with_lifetime(Duration::from_secs(lifetime))?,
            };
            println!("{token}");
            return Ok(());
        }
        None => (),
    };

    let users_manager =
        Arc::new(UsersManager::new(&config.mongo, config.users_manager.clone()).await?);

    let rewards_manager =
        Arc::new(RewardsManager::new(&config.mongo, config.rewards_manager.clone()).await?);

    server::start(config, users_manager, rewards_manager, session_manager).await?;

    Ok(())
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Generates token to access /status endpoint (use -l or --lifetime for custom lifetime set, defaults to 1 year)
    GenToken(GetTokenArgs),
}

#[derive(Args)]
struct GetTokenArgs {
    /// Lifetime in seconds for an access token (defaults to 1 year)
    #[arg(short, long)]
    lifetime: Option<u64>,
    #[arg(short, long)]
    private_key: Option<String>,
}
