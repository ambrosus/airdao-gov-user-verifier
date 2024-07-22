mod config;
mod error;
mod quiz;
mod server;
mod session_token;
mod users_manager;

use clap::{Args, Parser, Subcommand};
use std::{sync::Arc, time::Duration};

use session_token::SessionManager;
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

            println!(
                "{}",
                session_manager
                    .acquire_internal_token_with_lifetime(Duration::from_secs(lifetime))?
            );
            return Ok(());
        }
        None => (),
    };

    let users_manager =
        Arc::new(UsersManager::new(&config.mongo, config.users_manager.clone()).await?);

    server::start(config, users_manager, session_manager).await?;

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
}
