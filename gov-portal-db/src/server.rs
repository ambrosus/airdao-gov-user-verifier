use axum::{extract::State, routing::post, Json, Router};
use serde::Deserialize;
use shared::common::{SessionToken, User};
use tower_http::cors::CorsLayer;

use crate::{config::AppConfig, error::AppError, session_token::SessionManager};

#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub session_manager: SessionManager,
}

impl AppState {
    pub fn new(config: AppConfig) -> Result<Self, AppError> {
        Ok(Self {
            session_manager: SessionManager::new(config.session.clone()),
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

pub async fn start(config: AppConfig) -> Result<(), AppError> {
    let addr = config
        .listen_address
        .parse::<std::net::SocketAddr>()
        .expect("Can't parse socket address");

    let state = AppState::new(config.clone())?;

    let app = Router::new()
        .route("/token", post(token_route))
        .route("/user", post(user_route))
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
    tracing::debug!("Request {req:?}");

    let res = match req {
        TokenQuery::Message { data } => state
            .session_manager
            .acquire_token(&data)
            .map_err(|e| e.to_string()),
        TokenQuery::NoMessage {} => Err("Resource Not Found".to_owned()),
    };

    tracing::debug!("Response {res:?}");

    res.map(Json)
}

async fn user_route(
    State(state): State<AppState>,
    Json(token): Json<SessionToken>,
) -> Result<Json<User>, String> {
    tracing::debug!("Request {token:?}");

    // TODO: fetch user information from MongoDB
    let user = state
        .session_manager
        .verify_token(&token)
        .map(|wallet| User { wallet })
        .map_err(|e| e.to_string());

    tracing::debug!("Response {user:?}");

    user.map(Json)
}
