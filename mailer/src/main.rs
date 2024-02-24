mod sendgrid;
mod server;
mod templates_manager;

use sendgrid::{SendGridClient, SendGridConfig};
use serde::Deserialize;
use templates_manager::TemplatesManagerConfig;

use shared::{logger, utils};

use crate::templates_manager::TemplatesManager;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppConfig {
    pub listen_address: String,
    pub sendgrid: SendGridConfig,
    pub templates: TemplatesManagerConfig,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    logger::init();
    shared::utils::set_heavy_panic();

    // Try load environment variables from `.env` if provided
    dotenv::dotenv().ok();

    let config = utils::load_config::<AppConfig>("./mailer").await?;

    let addr = config
        .listen_address
        .parse::<std::net::SocketAddr>()
        .expect("Can't parse socket address");

    let templates_manager = TemplatesManager::new(config.templates).await?;

    let sendgrid_client = SendGridClient::new(config.sendgrid);

    server::start(addr, sendgrid_client, templates_manager).await?;

    Ok(())
}
