use axum::{extract::State, routing::post, Json, Router};
use chrono::Utc;
use tower_http::cors::CorsLayer;

use shared::common::{UserProfile, UserProfileStatus, VerifyAccountRequest, VerifyAccountResponse};

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

    let is_oauth_token = matches!(req.token, shared::common::TokenKind::OAuth { .. });
    let is_user_profile_complete = matches!(
        req.user,
        UserProfile { status: UserProfileStatus::Complete(_), .. } if req.user.is_complete(state.config.users_manager_secret.as_bytes())
    );

    if !is_oauth_token && !is_user_profile_complete {
        return Err(AppError::VerificationNotAllowed);
    }

    let result = match state
        .client
        .fetch_and_verify_user(req.token, req.user.info.wallet)
        .await
    {
        Ok(verified_user) => create_verify_account_response(
            &state.signer,
            req.user.info.wallet,
            verified_user,
            Utc::now(),
        ),
        Err(e) => {
            tracing::warn!(
                "Failed to process verify request (wallet: {}). Error: {e}",
                req.user.info.wallet
            );
            return Err(e);
        }
    };

    tracing::debug!("Response: {result:?}");

    result.map(Json)
}
