use axum::{extract::State, routing::post, Json, Router};
use chrono::Utc;
use ethereum_types::Address;
use serde::Deserialize;
use std::sync::Arc;
use tower_http::cors::CorsLayer;

use shared::common::{
    SessionToken, UserInfo, UserProfile, UserProfileStatus, UserRegistrationToken,
};

use crate::{
    config::AppConfig,
    error::AppError,
    quiz::{Quiz, QuizAnswer, QuizQuestion},
    session_token::SessionManager,
    users_manager::UsersManager,
};

/// State shared between route handlers
#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub session_manager: SessionManager,
    pub users_manager: Arc<UsersManager>,
    pub quiz: Quiz,
}

impl AppState {
    pub async fn new(
        config: AppConfig,
        users_manager: Arc<UsersManager>,
    ) -> Result<Self, AppError> {
        Ok(Self {
            quiz: Quiz {
                config: config.quiz.clone(),
            },
            session_manager: SessionManager::new(config.session.clone()),
            users_manager,
            config,
        })
    }
}

/// JSON-serialized request passed as POST-data to `/token` endpoint and contains signed message by User's wallet secret
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum TokenQuery {
    Message { data: String },
    NoMessage {},
}

/// JSON-serialized request passed as POST-data to `/quiz` endpoint and contains quiz answers
/// which should be verified and then updates User's profile in MongoDB
#[derive(Debug, Deserialize)]
pub struct VerifyQuizRequest {
    pub answers: Vec<QuizAnswer>,
    #[serde(flatten)]
    pub session: SessionToken,
}

/// JSON-serialized request passed as POST-data to `/update-user` endpoint and contains User's profile
/// info which should be updated in MongoDB
#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub telegram: Option<String>,
    #[serde(default)]
    pub twitter: Option<String>,
    #[serde(default)]
    pub bio: Option<String>,
    #[serde(default)]
    pub avatar: Option<url::Url>,
    #[serde(flatten)]
    pub session: SessionToken,
}

/// JSON-serialized request passed as POST-data to `/verify-email` endpoint to generate registration JWT token
#[derive(Debug, Deserialize)]
pub struct VerifyEmailRequest {
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
        .route("/update-user", post(update_user_route))
        .route("/verify-email", post(verify_email_route))
        .route("/quiz", post(quiz_route))
        .route("/verify-quiz", post(verify_quiz_route))
        .route("/register", post(register_route))
        .layer(CorsLayer::permissive())
        .with_state(state);

    tracing::debug!("Server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;

    axum::serve(listener, app).await.map_err(AppError::from)
}

/// Route handler to acquire session JWT token for MongoDB access
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

/// Route handler to read User's profile from MongoDB
async fn user_route(
    State(state): State<AppState>,
    Json(token): Json<SessionToken>,
) -> Result<Json<UserProfile>, String> {
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

/// Route handler to request quiz questions
async fn quiz_route(
    State(state): State<AppState>,
    Json(session): Json<SessionToken>,
) -> Result<Json<Vec<QuizQuestion>>, String> {
    tracing::debug!("[/quiz] Request {:?}", session);

    let res = match state.session_manager.verify_token(&session) {
        Ok(_) => Ok(state.quiz.config.questions),
        Err(e) => Err(format!("Quiz request failure. Error: {e}")),
    };

    tracing::debug!("[/quiz] Response {res:?}");

    res.map(Json)
}

/// Route handler to provide & verify quiz answers for User's profile
async fn verify_quiz_route(
    State(state): State<AppState>,
    Json(quiz_req): Json<VerifyQuizRequest>,
) -> Result<Json<()>, String> {
    tracing::debug!("[/verify-quiz] Request {:?}", quiz_req);

    let user_res = match state.session_manager.verify_token(&quiz_req.session) {
        Ok(wallet) => state
            .users_manager
            .get_user_by_wallet(wallet)
            .await
            .map_err(anyhow::Error::from),
        Err(e) => Err(anyhow::anyhow!("Verify quiz request failure. Error: {e}")),
    };

    let res = match user_res {
        // Do not need to verify quiz if already solved
        Ok(UserProfile {
            status:
                UserProfileStatus::Incomplete {
                    quiz_solved: true, ..
                }
                | UserProfileStatus::Complete(_),
            ..
        }) => Ok(()),
        // Do not allow to solve quiz if temporarily blocked
        Ok(UserProfile {
            status: UserProfileStatus::Blocked { blocked_until },
            ..
        }) if blocked_until > Utc::now().timestamp_millis() as u64 => {
            Err("User is temporarily blocked!".to_string())
        }
        Ok(user) => state
            .users_manager
            .update_user_quiz_result(
                user.info.wallet,
                state.quiz.verify_answers(quiz_req.answers),
            )
            .await
            .map_err(|e| format!("Update user profile with quiz results failure. Error: {e}")),
        Err(e) => Err(format!("Verify quiz request failure. Error: {e}")),
    };

    tracing::debug!("[/verify-quiz] Response {res:?}");

    res.map(Json)
}

/// Route handler to update User's profile in MongoDB
async fn update_user_route(
    State(state): State<AppState>,
    Json(update_req): Json<UpdateUserRequest>,
) -> Result<Json<()>, String> {
    tracing::debug!("[/update-user] Request {:?}", update_req);

    let res = match state.session_manager.verify_token(&update_req.session) {
        Ok(wallet) => state
            .users_manager
            .update_user(update_req.into_user(wallet))
            .await
            .map_err(|e| format!("Unable to update user profile. Error: {e}")),

        Err(e) => Err(format!("User update request failure. Error: {e}")),
    };

    tracing::debug!("[/update-user] Response {res:?}");

    res.map(Json)
}

/// Route handler to generate registration JWT token for User which could be send to an email
async fn verify_email_route(
    State(state): State<AppState>,
    Json(req): Json<VerifyEmailRequest>,
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

/// Route handler to register new User with basic profile
async fn register_route(
    State(state): State<AppState>,
    Json(reg_token): Json<UserRegistrationToken>,
) -> Result<Json<UserInfo>, String> {
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

impl UpdateUserRequest {
    fn into_user(self, wallet: Address) -> UserInfo {
        UserInfo {
            wallet,
            name: self.name,
            role: self.role,
            email: None,
            telegram: self.telegram,
            twitter: self.twitter,
            bio: self.bio,
            avatar: self.avatar,
        }
    }
}
