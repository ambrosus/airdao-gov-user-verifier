use axum::{extract::State, routing::post, Json, Router};
use chrono::Utc;
use ethereum_types::Address;
use std::str::FromStr;
use tower_http::cors::CorsLayer;

use shared::common::{
    User, UserProfileStatus, VerifyAccountRequest, VerifyNodeOwnerRequest, VerifyOgRequest,
    VerifyResponse, WalletSignedMessage,
};

use crate::{
    config::AppConfig,
    error::AppError,
    explorer_client::ExplorerClient,
    fractal::FractalClient,
    rpc_node_client::RpcNodeClient,
    server_nodes_manager::ServerNodesManager,
    signer::SbtRequestSigner,
    verification::{
        create_verify_account_response, create_verify_node_owner_response,
        create_verify_og_response,
    },
};

#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub client: FractalClient,
    pub signer: SbtRequestSigner,
    pub explorer_client: ExplorerClient,
    pub server_nodes_manager: ServerNodesManager,
}

impl AppState {
    pub fn new(config: AppConfig) -> Result<Self, AppError> {
        Ok(Self {
            client: FractalClient::new(config.fractal.clone())?,
            signer: SbtRequestSigner::new(config.signer.clone()),
            explorer_client: ExplorerClient::new(config.explorer.clone())?,
            server_nodes_manager: ServerNodesManager::new(
                config.server_nodes_manager_address,
                RpcNodeClient::new(config.rpc_node.clone())?,
            )?,
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
        .route("/verify_og", post(verify_og_endpoint))
        .route("/verify_node_owner", post(verify_node_owner_endpoint))
        .layer(CorsLayer::permissive())
        .with_state(state);

    tracing::debug!("Server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;

    axum::serve(listener, app).await.map_err(AppError::from)
}

async fn verify_endpoint(
    State(state): State<AppState>,
    Json(req): Json<VerifyAccountRequest>,
) -> Result<Json<VerifyResponse>, AppError> {
    tracing::debug!("Request: {req:?}");

    let is_oauth_token = matches!(req.fractal_token, shared::common::TokenKind::OAuth { .. });
    let is_user_profile_complete = matches!(
        req.user,
        User { status: UserProfileStatus::Complete(_), .. } if req.user.is_complete(state.config.users_manager_secret.as_bytes())
    );

    if !is_oauth_token && !is_user_profile_complete {
        return Err(AppError::VerificationNotAllowed);
    }

    let wallet = req.user.wallet;
    let result = match state
        .client
        .fetch_and_verify_user(req.fractal_token, wallet)
        .await
    {
        Ok(verified_user) => {
            create_verify_account_response(&state.signer, wallet, verified_user, Utc::now())
        }
        Err(e) => {
            tracing::warn!("Failed to process verify request (wallet: {wallet}). Error: {e}",);
            return Err(e);
        }
    };

    tracing::debug!("Response: {result:?}");

    result.map(Json)
}

async fn verify_og_endpoint(
    State(state): State<AppState>,
    Json(req): Json<VerifyOgRequest>,
) -> Result<Json<VerifyResponse>, AppError> {
    tracing::debug!("Request: {req:?}");

    let og_wallet =
        try_wallet_from_verify_og_request(&req, state.config.users_manager_secret.as_bytes())?;

    let result = state
        .explorer_client
        .find_first_transaction_before(og_wallet, state.config.signer.og_eligible_before)
        .await
        .map_err(AppError::from)
        .and_then(|tx_hash| match tx_hash {
            Some(tx_hash) => create_verify_og_response(
                &state.signer,
                req.user.wallet,
                og_wallet,
                tx_hash,
                Utc::now(),
            ),
            None => Err(AppError::OGVerificationNotAllowed),
        });

    tracing::debug!("Response: {result:?}");

    result.map(Json)
}

async fn verify_node_owner_endpoint(
    State(state): State<AppState>,
    Json(req): Json<VerifyNodeOwnerRequest>,
) -> Result<Json<VerifyResponse>, AppError> {
    tracing::debug!("Request: {req:?}");

    let is_user_profile_complete = matches!(
        req.user,
        User { status: UserProfileStatus::Complete(_), .. } if req.user.is_complete(state.config.users_manager_secret.as_bytes())
    );

    if !is_user_profile_complete {
        return Err(AppError::SNOVerificationNotAllowed);
    }

    let wallet = req.user.wallet;

    let result = match state.server_nodes_manager.is_node_owner(wallet).await {
        Ok(true) => create_verify_node_owner_response(&state.signer, wallet, Utc::now()),
        Ok(false) => Err(AppError::SNOVerificationNotAllowed),
        Err(e) => Err(e.into()),
    };

    tracing::debug!("Response: {result:?}");

    result.map(Json)
}

fn try_wallet_from_verify_og_request(
    req: &VerifyOgRequest,
    secret: &[u8],
) -> Result<Address, AppError> {
    let is_user_profile_complete = matches!(
        req.user,
        User { status: UserProfileStatus::Complete(_), .. } if req.user.is_complete(secret)
    );

    if !is_user_profile_complete {
        return Err(AppError::ProfileIncomplete);
    }

    match req.data.as_deref() {
        Some(encoded_message) => WalletSignedMessage::from_str(encoded_message)
            .and_then(shared::utils::recover_eth_address)
            .map_err(|_| AppError::WalletMatchFailure),
        None => Ok(req.user.wallet),
    }
}
