use axum::{extract::State, routing::post, Json, Router};
use chrono::{DateTime, Utc};
use ethereum_types::Address;
use futures_util::{future, FutureExt, TryFutureExt};
use jsonwebtoken::TokenData;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tower_http::cors::CorsLayer;

use shared::{
    common::{
        Rewards, SBTInfo, SendEmailRequest, SendEmailRequestKind, SessionToken,
        UpdateRewardRequest, UpdateSBTKind, UpdateUserSBTRequest, User, UserEmailConfirmationToken,
        UserProfile, UserProfileStatus,
    },
    rpc_node_client::RpcNodeClient,
};

use crate::{
    config::AppConfig,
    error::AppError,
    mongo_client::MongoClient,
    quiz::{Quiz, QuizAnswer, QuizQuestion},
    rewards_manager::RewardsManager,
    sbt::{HumanSBT, NonExpiringSBT, SBTContract, SBTKind, SBT},
    session_manager::SessionManager,
    users_manager::{QuizResult, UsersManager},
};

/// State shared between route handlers
#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub session_manager: SessionManager,
    pub users_manager: Arc<UsersManager>,
    pub rewards_manager: Arc<RewardsManager>,
    pub quiz: Quiz,
    pub sbt_contracts: Arc<HashMap<SBTKind, SBTContract>>,
}

/// Maximum number of wallets are allowed at once to request with `/users` endpoint to fetch users profiles
const USERS_MAX_WALLETS_REQ_LIMIT: usize = 50;

impl AppState {
    pub async fn new(
        config: AppConfig,
        users_manager: Arc<UsersManager>,
        rewards_manager: Arc<RewardsManager>,
        session_manager: SessionManager,
    ) -> Result<Self, AppError> {
        let rpc_node_client =
            RpcNodeClient::new(config.rpc_node.clone()).map_err(AppError::from)?;

        Ok(Self {
            quiz: Quiz {
                config: config.quiz.clone(),
            },
            session_manager,
            users_manager,
            rewards_manager,
            sbt_contracts: Arc::new(
                Self::load_sbt_contracts(&rpc_node_client, &config.sbt_contracts).await?,
            ),
            config,
        })
    }

    async fn load_sbt_contracts(
        rpc_node_client: &RpcNodeClient,
        sbt_addresses: &HashMap<SBTKind, Address>,
    ) -> Result<HashMap<SBTKind, SBTContract>, AppError> {
        let mut sbt_contracts = HashMap::with_capacity(sbt_addresses.len());

        for (sbt_kind, contract) in sbt_addresses {
            let contract = match sbt_kind {
                SBTKind::HumanSBT => {
                    SBTContract::HumanSBT(HumanSBT::new(*contract, rpc_node_client).await?)
                }
                SBTKind::NonExpiring(_) => SBTContract::NonExpiringSBT(
                    NonExpiringSBT::new(*contract, rpc_node_client).await?,
                ),
            };

            sbt_contracts.insert(sbt_kind.clone(), contract);
        }

        Ok(sbt_contracts)
    }
}

/// Token request passed as POST-data to `/token` endpoint
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum TokenQuery {
    /// Variant contains Base64-encoded JSON-serialized [`shared::common::WalletSignedMessage`] data struct
    Message {
        data: String,
    },
    NoMessage {},
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub token: SessionToken,
}

/// JSON-serialized request passed as POST-data to `/rewards` endpoint
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RewardsRequest {
    pub token: SessionToken,
    pub wallet: Option<Address>,
    pub start: Option<u64>,
    pub limit: Option<u64>,
    pub from: Option<u64>,
    pub to: Option<u64>,
    pub community: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RewardsResponse {
    pub data: Vec<Rewards>,
    pub total: u64,
}

/// JSON-serialized request passed as POST-data to `/users` endpoint
#[derive(Debug, Deserialize)]
pub struct UsersRequest {
    wallets: Vec<Address>,
    pub token: SessionToken,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedQuizResponse {
    pub questions: Vec<QuizQuestion>,
    pub expires_at: u64,
    pub quiz_token: String,
}

/// JSON-serialized request passed as POST-data to `/user` endpoint
#[derive(Debug, Deserialize)]
pub struct UserRequest {
    pub token: SessionToken,
}

/// JSON-serialized request passed as POST-data to `/status` endpoint
#[derive(Debug, Deserialize)]
pub struct StatusRequest {
    pub token: SessionToken,
}

/// JSON-serialized request passed as POST-data to `/sbt-report` endpoint
#[derive(Debug, Deserialize)]
pub struct SBTReportRequest {
    pub token: SessionToken,
    pub start: Option<u64>,
    pub limit: Option<u64>,
}

/// JSON-serialized request passed as POST-data to `/sbt-list` endpoint
#[derive(Debug, Deserialize)]
pub struct SBTListRequest {
    pub token: SessionToken,
    pub wallet: Address,
}

/// JSON-serialized request passed as POST-data to `/quiz` endpoint
#[derive(Debug, Deserialize)]
pub struct QuizRequest {
    pub token: SessionToken,
}

/// JSON-serialized request passed as POST-data to `/quiz` endpoint and contains quiz answers
/// which should be verified and then updates User's profile in MongoDB
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyQuizRequest {
    pub answers: Vec<QuizAnswer>,
    pub quiz_token: String,
    pub token: SessionToken,
}

/// JSON-serialized request passed as POST-data to `/update-user` endpoint and contains User's profile
/// info which should be updated in MongoDB
#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    #[serde(flatten)]
    pub profile: UserProfile,
    pub token: SessionToken,
}

/// JSON-serialized request passed as POST-data to `/check-email` endpoint
#[derive(Debug, Deserialize)]
pub struct CheckEmailRequest {
    email: serde_email::Email,
    pub token: SessionToken,
}

/// JSON-serialized request passed as POST-data to `/verify-email` endpoint to send email verification link to user's email
#[derive(Debug, Deserialize)]
pub struct VerifyEmailRequest {
    #[serde(flatten)]
    pub kind: VerifyEmailRequestKind,
    pub token: SessionToken,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum VerifyEmailRequestKind {
    EmailChange {
        old_email: serde_email::Email,
        email: serde_email::Email,
    },
    EmailVerification {
        email: serde_email::Email,
    },
}

impl VerifyEmailRequest {
    fn old_email(&self) -> Option<&serde_email::Email> {
        match &self.kind {
            VerifyEmailRequestKind::EmailChange { old_email, .. } => Some(old_email),
            _ => None,
        }
    }

    fn email(&self) -> &serde_email::Email {
        match &self.kind {
            VerifyEmailRequestKind::EmailChange { email, .. } => email,
            VerifyEmailRequestKind::EmailVerification { email } => email,
        }
    }
}

pub async fn start(
    config: AppConfig,
    users_manager: Arc<UsersManager>,
    rewards_manager: Arc<RewardsManager>,
    session_manager: SessionManager,
) -> Result<(), AppError> {
    let addr = config
        .listen_address
        .parse::<std::net::SocketAddr>()
        .expect("Can't parse socket address");

    let state = AppState::new(config, users_manager, rewards_manager, session_manager).await?;

    let app = Router::new()
        .route("/token", post(token_route))
        .route("/status", post(status_route))
        .route("/sbt-report", post(sbt_report_route))
        .route("/sbt-list", post(sbt_list_route))
        .route("/user", post(user_route))
        .route("/users", post(users_route))
        .route("/update-user", post(update_user_route))
        .route("/update-user-sbt", post(update_user_sbt_route))
        .route("/update-reward", post(update_reward_route))
        .route("/rewards", post(rewards_route))
        .route("/check-email", post(check_email_route))
        .route("/verify-email", post(verify_email_route))
        .route("/quiz", post(quiz_route))
        .route("/verify-quiz", post(verify_quiz_route))
        .route("/update-email", post(update_email_route))
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
) -> Result<Json<TokenResponse>, String> {
    tracing::debug!("[/token] Request {req:?}");

    let res = match req {
        TokenQuery::Message { data } => state
            .session_manager
            .acquire_token_with_wallet_signed_message(&data)
            .map_err(|e| e.to_string())
            .map(|token| TokenResponse { token }),
        TokenQuery::NoMessage {} => Err("Resource Not Found".to_owned()),
    };

    tracing::debug!("[/token] Response {res:?}");

    res.map(Json)
}

/// Route handler to read User's profile from MongoDB
async fn status_route(
    State(state): State<AppState>,
    Json(req): Json<StatusRequest>,
) -> Result<Json<()>, String> {
    tracing::debug!("[/status] Request {req:?}");

    let res = match state.session_manager.verify_internal_token(&req.token) {
        Ok(_) => state
            .users_manager
            .db_client
            .server_status()
            .await
            .map(|_| ())
            .map_err(|e| e.to_string()),

        Err(e) => Err(format!("Request failure. Error: {e}")),
    };

    tracing::debug!("[/status] Response {res:?}");

    res.map(Json)
}

/// Route handler to request User's SBT report from RPC node
async fn sbt_report_route(
    State(state): State<AppState>,
    Json(req): Json<SBTReportRequest>,
) -> Result<Json<Vec<UserSBTReport>>, String> {
    tracing::debug!("[/sbt-report] Request {req:?}");

    let res = match state.session_manager.verify_internal_token(&req.token) {
        Ok(_) => get_sbt_report(state, req).await.map_err(|e| e.to_string()),

        Err(e) => Err(format!("Request failure. Error: {e}")),
    };

    tracing::debug!("[/sbt-report] Response {res:?}");

    res.map(Json)
}

/// Route handler to read User's SBT list from MongoDB
async fn sbt_list_route(
    State(state): State<AppState>,
    Json(req): Json<SBTListRequest>,
) -> Result<Json<Vec<SBTInfo>>, String> {
    tracing::debug!("[/sbt-list] Request {req:?}");

    let res = match state.session_manager.verify_internal_token(&req.token) {
        Ok(_) => state
            .users_manager
            .get_user_sbt_list_by_wallet(req.wallet)
            .await
            .map_err(|e| format!("Unable to acquire user SBT list. Error: {e}")),

        Err(e) => Err(format!("Request failure. Error: {e}")),
    };

    tracing::debug!("[/sbt-report] Response {res:?}");

    res.map(Json)
}

/// Route handler to read User's profile from MongoDB
async fn user_route(
    State(state): State<AppState>,
    Json(req): Json<UserRequest>,
) -> Result<Json<User>, String> {
    tracing::debug!("[/user] Request {req:?}");

    let res = match state.session_manager.verify_token(&req.token) {
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

/// Route handler to read multiple User's profiles from MongoDB
async fn users_route(
    State(state): State<AppState>,
    Json(req): Json<UsersRequest>,
) -> Result<Json<Vec<User>>, String> {
    tracing::debug!(
        "[/users] Request (session: {session:?}, wallets: {wallets})",
        session = req.token,
        wallets = req.wallets.len()
    );

    let wallets_max_count = std::cmp::min(req.wallets.len(), USERS_MAX_WALLETS_REQ_LIMIT);

    let res = match state.session_manager.verify_token(&req.token) {
        Ok(requestor) => state
            .users_manager
            .get_users_by_wallets(&requestor, &req.wallets[..wallets_max_count])
            .await
            .map_err(|e| format!("Unable to acquire users profiles. Error: {e}")),
        Err(e) => Err(format!("Users request failure. Error: {e}")),
    };

    tracing::debug!("[/users] Response {res:?}");

    res.map(Json)
}

/// Route handler to request quiz questions
async fn quiz_route(
    State(state): State<AppState>,
    Json(req): Json<QuizRequest>,
) -> Result<Json<SignedQuizResponse>, String> {
    tracing::debug!("[/quiz] Request {:?}", req);

    let res = match state.session_manager.verify_token(&req.token) {
        Ok(_) => {
            let questions = state.quiz.get_random_quiz_questions();

            SignedQuizResponse::new(
                questions,
                Utc::now() + state.config.quiz.time_to_solve,
                state.config.quiz.secret.as_bytes(),
            )
            .map_err(|e| format!("Failed to sign random quiz questions. Error: {e}"))
        }
        Err(e) => Err(format!("Quiz request failure. Error: {e}")),
    };

    tracing::debug!("[/quiz] Response {res:?}");

    res.map(Json)
}

/// Route handler to provide & verify quiz answers for User's profile
async fn verify_quiz_route(
    State(state): State<AppState>,
    Json(quiz_req): Json<VerifyQuizRequest>,
) -> Result<Json<QuizResult>, String> {
    tracing::debug!("[/verify-quiz] Request {:?}", quiz_req);

    let token_res = match &quiz_req {
        req if req.verify(state.config.quiz.secret.as_bytes()) => {
            state.session_manager.verify_token(&quiz_req.token)
        }
        _ => Err(anyhow::anyhow!("Invalid quiz token")),
    };

    let user_res = match token_res {
        Ok(wallet) => state
            .users_manager
            .get_user_by_wallet(wallet)
            .await
            .map_err(anyhow::Error::from),
        Err(e) => Err(anyhow::anyhow!("Verify quiz request failure. Error: {e}")),
    };

    let res = match user_res {
        // Do not need to verify quiz if already solved
        Ok(User {
            status:
                UserProfileStatus::Incomplete {
                    quiz_solved: true, ..
                }
                | UserProfileStatus::Complete(_),
            ..
        }) => Ok(QuizResult::AlreadySolved),
        // Do not allow to solve quiz if temporarily blocked
        Ok(User {
            status: UserProfileStatus::Blocked { blocked_until },
            ..
        }) if blocked_until > Utc::now().timestamp_millis() as u64 => {
            Err("User is temporarily blocked!".to_string())
        }
        Ok(user) => {
            let quiz_result = state.quiz.verify_answers(quiz_req.answers);

            state
                .users_manager
                .update_user_quiz_result(user.wallet, &quiz_result)
                .await
                .map_err(|e| format!("Update user profile with quiz results failure. Error: {e}"))
                .map(|_| quiz_result)
        }
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

    let res = match state.session_manager.verify_token(&update_req.token) {
        Ok(wallet) => state
            .users_manager
            .update_user_profile(wallet, update_req.profile)
            .await
            .map_err(|e| format!("Unable to update user profile. Error: {e}")),

        Err(e) => Err(format!("User update request failure. Error: {e}")),
    };

    tracing::debug!("[/update-user] Response {res:?}");

    res.map(Json)
}

/// Route handler to update User's SBT in MongoDB
async fn update_user_sbt_route(
    State(state): State<AppState>,
    Json(update_req): Json<UpdateUserSBTRequest>,
) -> Result<Json<()>, String> {
    tracing::debug!("[/update-user] Request {:?}", update_req);

    let res = match state
        .session_manager
        .verify_internal_token(&update_req.token)
        .map(|_| (update_req.wallet, update_req.kind))
    {
        Ok((wallet, UpdateSBTKind::Upsert(sbt))) => state
            .users_manager
            .upsert_user_sbt(wallet, sbt)
            .await
            .map_err(|e| format!("Unable to update user profile. Error: {e}")),
        Ok((wallet, UpdateSBTKind::Remove { sbt_address })) => state
            .users_manager
            .remove_user_sbt(wallet, sbt_address)
            .await
            .map_err(|e| format!("Unable to update user profile. Error: {e}")),

        Err(e) => Err(format!("User update request failure. Error: {e}")),
    };

    tracing::debug!("[/update-user-sbt] Response {res:?}");

    res.map(Json)
}

/// Route handler to update rewards in MongoDB
async fn update_reward_route(
    State(state): State<AppState>,
    Json(update_req): Json<UpdateRewardRequest>,
) -> Result<Json<()>, String> {
    tracing::debug!("[/update-reward] Request {:?}", update_req);

    let res = match state
        .session_manager
        .verify_internal_token(&update_req.token)
        .map(|_| update_req.kind)
    {
        Ok(update_req) => state
            .rewards_manager
            .update_reward(update_req)
            .await
            .map_err(|e| format!("Unable to update user profile. Error: {e}")),

        Err(e) => Err(format!("Update reward request failure. Error: {e}")),
    };

    tracing::debug!("[/update-user-sbt] Response {res:?}");

    res.map(Json)
}

/// Route handler to get rewards history from MongoDB
async fn rewards_route(
    State(state): State<AppState>,
    Json(req): Json<RewardsRequest>,
) -> Result<Json<RewardsResponse>, String> {
    tracing::debug!("[/rewards] Request {:?}", req);

    let res = match state
        .session_manager
        .verify_token(&req.token)
        .map(|wallet| (wallet, req))
    {
        // Request all rewards history
        Ok((
            requestor,
            RewardsRequest {
                wallet: None,
                start,
                limit,
                from,
                to,
                community,
                ..
            },
        )) => state
            .rewards_manager
            .count_rewards(&requestor, from, to, community.as_deref())
            .and_then(|total| {
                let manager = Arc::clone(&state.rewards_manager);
                let community = community.as_deref();

                async move {
                    manager
                        .get_rewards(&requestor, start, limit, from, to, community)
                        .await
                        .map(|data| RewardsResponse { data, total })
                }
            })
            .await
            .map_err(|e| format!("Unable to get rewards. Error: {e}")),

        // Request rewards history related to specific wallet
        Ok((
            requestor,
            RewardsRequest {
                wallet: Some(wallet),
                start,
                limit,
                from,
                to,
                community,
                ..
            },
        )) => state
            .rewards_manager
            .count_rewards_by_wallet(&requestor, &wallet, from, to, community.as_deref())
            .and_then(|total| {
                let manager = Arc::clone(&state.rewards_manager);
                let community = community.as_deref();

                async move {
                    manager
                        .get_rewards_by_wallet(
                            &requestor, &wallet, start, limit, from, to, community,
                        )
                        .await
                        .map(|data| RewardsResponse { data, total })
                }
            })
            .await
            .map_err(|e| format!("Unable to get rewards. Error: {e}")),
        Err(e) => Err(format!("Rewards request failure. Error: {e}")),
    };

    tracing::debug!("[/update-user-sbt] Response {res:?}");

    res.map(Json)
}

/// Route handler to check if an email is already in database
async fn check_email_route(
    State(state): State<AppState>,
    Json(req): Json<CheckEmailRequest>,
) -> Result<Json<bool>, String> {
    tracing::debug!("[/check-email] Request {req:?}");

    let res = match state.session_manager.verify_token(&req.token) {
        Ok(_) => state.users_manager.is_email_being_used(&req.email).await,
        Err(e) => Err(e),
    }
    .map_err(|e| format!("Check email request failure. Error: {e}"));

    tracing::debug!("[/check-email] Response {res:?}");

    res.map(Json)
}

/// Route handler to generate email verification JWT token and send it to user's email address
async fn verify_email_route(
    State(state): State<AppState>,
    Json(req): Json<VerifyEmailRequest>,
) -> Result<Json<()>, String> {
    let old_email = req.old_email();
    let email = req.email();
    if old_email == Some(email) {
        return Err("Email shouldn't be the same".to_string());
    }

    let kind = match old_email {
        Some(_) => SendEmailRequestKind::EmailChange,
        None => SendEmailRequestKind::EmailVerification,
    };

    tracing::debug!("[/verify-email] Request {req:?}");

    let res = match state
        .session_manager
        .verify_token(&req.token)
        .and_then(|wallet| {
            state
                .users_manager
                .acquire_email_confirmation_token(wallet, old_email, email)
        })
        .map_err(|e| format!("Verify email request failure. Error: {e}"))
        .and_then(|UserEmailConfirmationToken { token }| {
            url::Url::try_from(
                state
                    .config
                    .users_manager
                    .email_verification
                    .template_url
                    .replace("{{VERIFICATION_TOKEN}}", &token)
                    .as_str(),
            )
            .map_err(|e| format!("Failed to create verification link. Error: {e:?}"))
        }) {
        Ok(url) => {
            state
                .users_manager
                .send_email_verification(SendEmailRequest {
                    kind,
                    from: state.config.users_manager.email_verification.from.clone(),
                    to: email.clone(),
                    subject: state
                        .config
                        .users_manager
                        .email_verification
                        .subject
                        .clone(),
                    verification_url: url,
                })
                .await
        }
        Err(e) => Err(e),
    };

    tracing::debug!("[/verify-email] Response {res:?}");

    res.map(Json)
}

/// Route handler to register a user or update User profile with new email
async fn update_email_route(
    State(state): State<AppState>,
    Json(reg_token): Json<UserEmailConfirmationToken>,
) -> Result<Json<()>, String> {
    tracing::debug!("[/update-email] Request {reg_token:?}");

    let res = match state
        .users_manager
        .verify_email_confirmation_token(&reg_token)
    {
        Ok(req) => state
            .users_manager
            .upsert_user(req.wallet, req.email)
            .await
            .map_err(|e| {
                if req.old_email.is_none() {
                    format!("User registration failure. Error: {e}")
                } else {
                    format!("User email update failure. Error: {e}")
                }
            }),

        Err(e) => Err(format!("Wrong email update request. Error: {e}")),
    };

    tracing::debug!("[/update-email] Response {res:?}");

    res.map(Json)
}

impl SignedQuizResponse {
    fn new(
        questions: Vec<QuizQuestion>,
        expires_at: DateTime<Utc>,
        secret: &[u8],
    ) -> anyhow::Result<Self> {
        jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &serde_json::json!({
                "questions": questions.iter().map(|question| question.title.as_str()).collect::<Vec<_>>(),
                "exp": expires_at.timestamp(),
            }),
            &jsonwebtoken::EncodingKey::from_secret(secret),
        )
        .map_err(anyhow::Error::from)
        .map(|token| Self {
            questions,
            expires_at: expires_at.timestamp_millis() as u64,
            quiz_token: token,
        })
    }
}

impl VerifyQuizRequest {
    fn verify(&self, secret: &[u8]) -> bool {
        let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::default());

        let Ok(TokenData {
            claims: serde_json::Value::Object(object),
            ..
        }) = jsonwebtoken::decode::<serde_json::Value>(
            &self.quiz_token,
            &jsonwebtoken::DecodingKey::from_secret(secret),
            &validation,
        )
        else {
            return false;
        };

        let Some(questions) = object
            .get("questions")
            .cloned()
            .and_then(|maybe_questions| {
                serde_json::from_value::<Vec<String>>(maybe_questions).ok()
            })
        else {
            tracing::debug!(
                "Verify quiz request token doesn't contain valid questions list: {object:?}"
            );
            return false;
        };

        // Verify if number of answers is the same as number of questions given
        if questions.len() != self.answers.len() {
            return false;
        }

        // Verify that all answers corresponds to the questions given
        for question in questions {
            if !self
                .answers
                .iter()
                .any(|answer| answer.question.as_str() == question.as_str())
            {
                return false;
            }
        }

        true
    }
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct UserSBTReport {
    wallet: Address,
    reports: Vec<SBTReportKind>,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
enum SBTReportKind {
    Success(SBTReport),
    Failure(SBTReportError),
    Unavailable,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SBTReport {
    name: String,
    address: Address,
    issued_at: DateTime<Utc>,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SBTReportError {
    name: String,
    address: Address,
    error: String,
}

async fn get_sbt_reports_by_wallet(
    sbt_contracts: &HashMap<SBTKind, SBTContract>,
    wallet: Address,
) -> Vec<SBTReportKind> {
    let futures = sbt_contracts.iter().map(|(sbt_kind, contract)| {
        let address = contract.address();
        let name = sbt_kind.to_string();

        contract
            .sbt_issued_at(wallet)
            .then(move |result| async move {
                match result {
                    Ok(Some(issued_at)) => SBTReportKind::Success(SBTReport {
                        name,
                        address,
                        issued_at,
                    }),
                    Ok(None) => SBTReportKind::Unavailable,
                    Err(e) => SBTReportKind::Failure(SBTReportError {
                        name,
                        address,
                        error: e.to_string(),
                    }),
                }
            })
    });

    future::join_all(futures).await
}

async fn get_sbt_report(
    state: AppState,
    req: SBTReportRequest,
) -> anyhow::Result<Vec<UserSBTReport>> {
    let users = state.users_manager.get_users(req.start, req.limit).await?;
    let mut results = Vec::with_capacity(users.len());

    for user in users.into_iter() {
        let wallet = user.wallet;
        let sbt_reports = get_sbt_reports_by_wallet(&state.sbt_contracts, user.wallet).await;

        results.push(UserSBTReport {
            wallet,
            reports: sbt_reports,
        })
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::quiz::{QuizQuestionDifficultyLevel, QuizVariant};
    use axum::response::IntoResponse;
    use shared::rpc_node_client::{RpcNodeClient, RpcNodeConfig};

    #[test]
    fn test_() {
        println!("{:?}", Json::into_response(Json(())).body());
    }

    #[tokio::test]
    #[ignore]
    async fn test_fetch_sbt_reports_for_user() {
        let rpc_node_client = RpcNodeClient::new(RpcNodeConfig {
            url: "https://network.ambrosus.io".to_owned(),
            request_timeout: std::time::Duration::from_secs(10),
        })
        .unwrap();

        let sbt_addresses = serde_json::from_str(
            r#"{
                "HumanSBT": "0x2d41b52C0683bed2C43727521493246256bD5B02",
                "SNOSBT": "0x012aA16B3D38FeB48ACe7067e6926953A9471865",
                "OGSBT": "0xddE1BFab19d6dF8B965FC57471Ee49D5CAaAdbf0",
                "CouncilSBT": "0x98dD1A1f1bA74E7503B028075cD8dA99ee3aABd3",
                "ExCouncilSBT": "0x60802408cA35805d1fF24500De9c3A1aE9dE207d",
                "TokenHolderSBT": "0x4923Ec0A4819A14E6E44B5E67EC48e155E4f21FB",
                "AmbassadorSBT": "0x2EDb4423Ea84611eA891a9FD583dAC8F4bb211c5",
                "ExternalDevSBT": "0x23ad94E997d9E473b9048056Ba1765F3Be5041C8",
                "InHouseDevSBT": "0x88769714b6AD81C44414d60C6b795a5edc0f27B6",
                "GWGMemberSBT": "0x26f2eC55587b71eB4ac67140F33814f8EfF593ef",
                "InvestorSBT": "0xa58b7aD1a4046A9C4275bB0393E0cEC5C4D1EeF0",
                "PartnerSBT": "0x2ae170F66e251273CBD8f040555C04C86E40d600",
                "TeamSBT": "0x835c7E75003a502d0Dd4f0eb158104671478845f"
            }"#,
        )
        .unwrap();

        let sbt_contracts = AppState::load_sbt_contracts(&rpc_node_client, &sbt_addresses)
            .await
            .unwrap();

        let wallet = "0x787afc1E7a61af49D7B94F8E774aC566D1B60e99"
            .parse()
            .unwrap();
        let sbt_reports = get_sbt_reports_by_wallet(&sbt_contracts, wallet)
            .await
            .into_iter()
            .filter_map(|sbt_report_kind| {
                if matches!(sbt_report_kind, SBTReportKind::Unavailable) {
                    None
                } else {
                    Some(sbt_report_kind)
                }
            })
            .collect::<Vec<_>>();

        println!("{sbt_reports:?}");
    }

    #[test]
    fn test_verify_quiz_answers() {
        struct TestCase {
            title: &'static str,
            input: VerifyQuizRequest,
            expected: bool,
        }

        let test_cases = [
            TestCase {
                title: "Request with 1 question is valid",
                input: SignedQuizResponse::new(
                    vec![QuizQuestion::new(
                        "Q1",
                        QuizQuestionDifficultyLevel::Easy,
                        vec![
                            QuizVariant::new("V1", false),
                            QuizVariant::new("V2", true),
                            QuizVariant::new("V3", false),
                        ],
                    )],
                    Utc::now() + Duration::from_secs(300),
                    "test".as_bytes(),
                )
                .map(|quiz_response| VerifyQuizRequest {
                    answers: vec![QuizAnswer::new("Q1", "V2")],
                    quiz_token: quiz_response.quiz_token,
                    token: SessionToken::default(),
                })
                .unwrap(),
                expected: true,
            },
            TestCase {
                title: "Request with mixed difficulty levels is valid",
                input: SignedQuizResponse::new(
                    vec![
                        QuizQuestion::new(
                            "Q1",
                            QuizQuestionDifficultyLevel::Easy,
                            vec![QuizVariant::new("V1", false), QuizVariant::new("V2", true)],
                        ),
                        QuizQuestion::new(
                            "Q2",
                            QuizQuestionDifficultyLevel::Moderate,
                            vec![QuizVariant::new("V1", true), QuizVariant::new("V2", false)],
                        ),
                        QuizQuestion::new(
                            "Q3",
                            QuizQuestionDifficultyLevel::Easy,
                            vec![QuizVariant::new("V1", true), QuizVariant::new("V2", false)],
                        ),
                        QuizQuestion::new(
                            "Q4",
                            QuizQuestionDifficultyLevel::Moderate,
                            vec![QuizVariant::new("V1", false), QuizVariant::new("V2", true)],
                        ),
                    ],
                    Utc::now() + Duration::from_secs(300),
                    "test".as_bytes(),
                )
                .map(|quiz_response| VerifyQuizRequest {
                    answers: vec![
                        QuizAnswer::new("Q4", "V2"),
                        QuizAnswer::new("Q3", "V1"),
                        QuizAnswer::new("Q2", "V1"),
                        QuizAnswer::new("Q1", "V2"),
                    ],
                    quiz_token: quiz_response.quiz_token,
                    token: SessionToken::default(),
                })
                .unwrap(),
                expected: true,
            },
            TestCase {
                title: "Request is invalid (different answer given)",
                input: SignedQuizResponse::new(
                    vec![
                        QuizQuestion::new(
                            "Q1",
                            QuizQuestionDifficultyLevel::Easy,
                            vec![QuizVariant::new("V1", false), QuizVariant::new("V2", true)],
                        ),
                        QuizQuestion::new(
                            "Q2",
                            QuizQuestionDifficultyLevel::Moderate,
                            vec![QuizVariant::new("V1", true), QuizVariant::new("V2", false)],
                        ),
                        QuizQuestion::new(
                            "Q3",
                            QuizQuestionDifficultyLevel::Easy,
                            vec![QuizVariant::new("V1", true), QuizVariant::new("V2", false)],
                        ),
                        QuizQuestion::new(
                            "Q4",
                            QuizQuestionDifficultyLevel::Moderate,
                            vec![QuizVariant::new("V1", false), QuizVariant::new("V2", true)],
                        ),
                    ],
                    Utc::now() + Duration::from_secs(300),
                    "test".as_bytes(),
                )
                .map(|quiz_response| VerifyQuizRequest {
                    answers: vec![
                        QuizAnswer::new("Q5", "V2"),
                        QuizAnswer::new("Q4", "V1"),
                        QuizAnswer::new("Q3", "V1"),
                        QuizAnswer::new("Q2", "V2"),
                    ],
                    quiz_token: quiz_response.quiz_token,
                    token: SessionToken::default(),
                })
                .unwrap(),
                expected: false,
            },
            TestCase {
                title: "Request is invalid (expired)",
                input: SignedQuizResponse::new(
                    vec![QuizQuestion::new(
                        "Q1",
                        QuizQuestionDifficultyLevel::Easy,
                        vec![QuizVariant::new("V1", false), QuizVariant::new("V2", true)],
                    )],
                    Utc::now() - Duration::from_secs(300),
                    "test".as_bytes(),
                )
                .map(|quiz_response| VerifyQuizRequest {
                    answers: vec![QuizAnswer::new("Q1", "V2")],
                    quiz_token: quiz_response.quiz_token,
                    token: SessionToken::default(),
                })
                .unwrap(),
                expected: false,
            },
            TestCase {
                title: "Request is invalid (secret doesn't match)",
                input: SignedQuizResponse::new(
                    vec![QuizQuestion::new(
                        "Q1",
                        QuizQuestionDifficultyLevel::Easy,
                        vec![QuizVariant::new("V1", false), QuizVariant::new("V2", true)],
                    )],
                    Utc::now() - Duration::from_secs(300),
                    "unknown_secret".as_bytes(),
                )
                .map(|quiz_response| VerifyQuizRequest {
                    answers: vec![QuizAnswer::new("Q1", "V2")],
                    quiz_token: quiz_response.quiz_token,
                    token: SessionToken::default(),
                })
                .unwrap(),
                expected: false,
            },
        ];

        for (
            i,
            TestCase {
                title,
                input,
                expected,
            },
        ) in test_cases.into_iter().enumerate()
        {
            assert_eq!(
                input.verify("test".as_bytes()),
                expected,
                "Test case #{i} '{title}' failed!"
            );
        }
    }

    impl QuizQuestion {
        fn new(
            title: &str,
            difficulty: QuizQuestionDifficultyLevel,
            variants: Vec<QuizVariant>,
        ) -> Self {
            Self {
                title: title.to_string(),
                difficulty,
                variants,
            }
        }
    }

    impl QuizVariant {
        fn new(text: &str, is_correct: bool) -> Self {
            Self {
                text: text.to_string(),
                is_correct,
            }
        }
    }

    impl QuizAnswer {
        fn new(question: &str, answer: &str) -> Self {
            Self {
                question: question.to_string(),
                variant: answer.to_string(),
            }
        }
    }
}
