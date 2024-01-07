use axum::{extract::State, routing::post, Json, Router};
use serde::Deserialize;
use std::sync::Arc;
use tower_http::cors::CorsLayer;

use shared::common::{SessionToken, User, UserRegistrationToken};

use crate::{
    config::AppConfig, error::AppError, session_token::SessionManager, users_manager::UsersManager,
};

#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub session_manager: SessionManager,
    pub users_manager: Arc<UsersManager>,
}

impl AppState {
    pub async fn new(
        config: AppConfig,
        users_manager: Arc<UsersManager>,
    ) -> Result<Self, AppError> {
        Ok(Self {
            session_manager: SessionManager::new(config.session.clone()),
            users_manager,
            config,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum TokenQuery {
    Message { data: String },
    NoMessage {},
}

#[derive(Debug, Deserialize)]
pub struct VerifyEmailReguest {
    pub email: serde_email::Email,
    #[serde(flatten)]
    pub session: SessionToken,
}

pub async fn start(config: AppConfig, users_manager: Arc<UsersManager>) -> Result<(), AppError> {
    let addr = config
        .listen_address
        .parse::<std::net::SocketAddr>()
        .expect("Can't parse socket address");

    let state = AppState::new(config, users_manager).await?;

    let app = Router::new()
        .route("/token", post(token_route))
        .route("/user", post(user_route))
        .route("/verify-email", post(verify_email_route))
        .route("/register", post(register_route))
        .layer(CorsLayer::permissive())
        .with_state(state);

    tracing::debug!("Server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;

    axum::serve(listener, app).await.map_err(AppError::from)
}

async fn token_route(
    State(state): State<AppState>,
    Json(req): Json<TokenQuery>,
) -> Result<Json<SessionToken>, String> {
    tracing::debug!("[/token] Request {req:?}");

    let res = match req {
        TokenQuery::Message { data } => state
            .session_manager
            .acquire_token(&data)
            .map_err(|e| e.to_string()),
        TokenQuery::NoMessage {} => Err("Resource Not Found".to_owned()),
    };

    tracing::debug!("[/token] Response {res:?}");

    res.map(Json)
}

async fn user_route(
    State(state): State<AppState>,
    Json(token): Json<SessionToken>,
) -> Result<Json<User>, String> {
    tracing::debug!("[/user] Request {token:?}");

    let res = match state.session_manager.verify_token(&token) {
        Ok(wallet) => state
            .users_manager
            .get_user_by_wallet(wallet)
            .await
            .map_err(|e| format!("Unable to acquire user information. Error: {e}")),

        Err(e) => Err(format!("User request failure. Error: {e}")),
    };

    tracing::debug!("[/user] Response {res:?}");

    res.map(Json)
}

async fn verify_email_route(
    State(state): State<AppState>,
    Json(req): Json<VerifyEmailReguest>,
) -> Result<Json<UserRegistrationToken>, String> {
    tracing::debug!("[/verify-email] Request {req:?}");

    // TODO: fetch user information from MongoDB
    let user = state
        .session_manager
        .verify_token(&req.session)
        .and_then(|wallet| {
            state
                .users_manager
                .acquire_registration_token(wallet, req.email)
        })
        .map_err(|e| format!("Verify email request failure. Error: {e}"));

    tracing::debug!("[/verify-email] Response {user:?}");

    user.map(Json)
}

async fn register_route(
    State(state): State<AppState>,
    Json(reg_token): Json<UserRegistrationToken>,
) -> Result<Json<User>, String> {
    tracing::debug!("[/register] Request {reg_token:?}");

    // TODO: fetch user information from MongoDB
    let res = match state.users_manager.verify_registration_token(&reg_token) {
        Ok(user) => {
            state
                .users_manager
                .register_user(&user)
                .await
                .map_err(|e| format!("User registration failure. Error: {e}"))?;
            Ok(user)
        }

        Err(e) => Err(format!("Wrong registration request. Error: {e}")),
    };

    tracing::debug!("[/register] Response {res:?}");

    res.map(Json)
}
