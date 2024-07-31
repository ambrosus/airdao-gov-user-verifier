use axum::{extract::State, routing::post, Json, Router};
use chrono::{DateTime, Utc};
use ethereum_types::Address;
use jsonwebtoken::TokenData;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::cors::CorsLayer;

use shared::common::{
    SendEmailRequest, SendEmailRequestKind, SessionToken, User, UserEmailConfirmationToken,
    UserProfile, UserProfileStatus,
};

use crate::{
    config::AppConfig,
    error::AppError,
    quiz::{Quiz, QuizAnswer, QuizQuestion},
    session_token::SessionManager,
    users_manager::{QuizResult, UsersManager},
};

/// State shared between route handlers
#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub session_manager: SessionManager,
    pub users_manager: Arc<UsersManager>,
    pub quiz: Quiz,
}

/// Maximum number of wallets are allowed at once to request with `/users` endpoint to fetch users profiles
const USERS_MAX_WALLETS_REQ_LIMIT: usize = 50;

impl AppState {
    pub async fn new(
        config: AppConfig,
        users_manager: Arc<UsersManager>,
        session_manager: SessionManager,
    ) -> Result<Self, AppError> {
        Ok(Self {
            quiz: Quiz {
                config: config.quiz.clone(),
            },
            session_manager,
            users_manager,
            config,
        })
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
    session_manager: SessionManager,
) -> Result<(), AppError> {
    let addr = config
        .listen_address
        .parse::<std::net::SocketAddr>()
        .expect("Can't parse socket address");

    let state = AppState::new(config, users_manager, session_manager).await?;

    let app = Router::new()
        .route("/token", post(token_route))
        .route("/status", post(status_route))
        .route("/user", post(user_route))
        .route("/users", post(users_route))
        .route("/update-user", post(update_user_route))
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
            .mongo_client
            .server_status()
            .await
            .map(|_| ())
            .map_err(|e| e.to_string()),

        Err(e) => Err(format!("Request failure. Error: {e}")),
    };

    tracing::debug!("[/status] Response {res:?}");

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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::quiz::{QuizQuestionDifficultyLevel, QuizVariant};

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
