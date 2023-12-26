use axum::{extract::State, routing::post, Json, Router};
use chrono::Utc;
use tower_http::cors::CorsLayer;

use shared::common::{VerifyAccountRequest, VerifyAccountResponse};

use crate::{
    config::AppConfig, error::AppError, fractal::FractalClient, signer::SbtRequestSigner,
    verification::create_verify_account_response,
};

#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub client: FractalClient,
    pub signer: SbtRequestSigner,
}

impl AppState {
    pub fn new(config: AppConfig) -> Result<Self, AppError> {
        Ok(Self {
            client: FractalClient::new(config.fractal.clone())?,
            signer: SbtRequestSigner::new(config.signer.clone()),
            config,
        })
    }
}

pub async fn start(config: AppConfig) -> Result<(), AppError> {
    let addr = config
        .listen_address
        .parse::<std::net::SocketAddr>()
        .expect("Can't parse socket address");

    let state = AppState::new(config.clone())?;

    let app = Router::new()
        .route("/verify", post(verify_endpoint))
        .layer(CorsLayer::permissive())
        .with_state(state);

    tracing::debug!("Server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;

    axum::serve(listener, app).await.map_err(AppError::from)
}

async fn verify_endpoint(
    State(state): State<AppState>,
    Json(req): Json<VerifyAccountRequest>,
) -> Result<Json<VerifyAccountResponse>, AppError> {
    tracing::debug!("Request: {req:?}");

    let user = state.client.fetch_user(req.token).await?;

    let result = create_verify_account_response(&state.signer, req.account, user, Utc::now());

    tracing::debug!("Response: {result:?}");

    result.map(Json)
}
