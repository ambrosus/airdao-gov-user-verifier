use axum::{extract::State, routing::post, Json, Router};
use chrono::{DateTime, Utc};
use ethereum_types::Address;
use jsonwebtoken::TokenData;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::cors::CorsLayer;

use shared::common::{
    EmailVerificationRequest, SessionToken, UserInfo, UserProfile, UserProfileStatus,
    UserRegistrationToken,
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedQuizResponse {
    pub questions: Vec<QuizQuestion>,
    pub expires_at: u64,
    pub quiz_token: String,
}

/// JSON-serialized request passed as POST-data to `/quiz` endpoint and contains quiz answers
/// which should be verified and then updates User's profile in MongoDB
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyQuizRequest {
    pub answers: Vec<QuizAnswer>,
    pub quiz_token: String,
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
) -> Result<Json<SignedQuizResponse>, String> {
    tracing::debug!("[/quiz] Request {:?}", session);

    let res = match state.session_manager.verify_token(&session) {
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
) -> Result<Json<()>, String> {
    tracing::debug!("[/verify-quiz] Request {:?}", quiz_req);

    let token_res = match &quiz_req {
        req if req.verify(state.config.quiz.secret.as_bytes()) => {
            state.session_manager.verify_token(&quiz_req.session)
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
) -> Result<Json<()>, String> {
    tracing::debug!("[/verify-email] Request {req:?}");

    let res = match state
        .session_manager
        .verify_token(&req.session)
        .and_then(|wallet| {
            state
                .users_manager
                .acquire_registration_token(wallet, req.email.clone())
        })
        .map_err(|e| format!("Verify email request failure. Error: {e}"))
        .and_then(|UserRegistrationToken { token }| {
            url::Url::try_from(
                state
                    .config
                    .users_manager
                    .email_verification
                    .template_url
                    .replace("{{REGISTRATION_TOKEN}}", &token)
                    .as_str(),
            )
            .map_err(|e| format!("Failed to create verification link. Error: {e:?}"))
        })
        .map(|url| EmailVerificationRequest {
            from: state.config.users_manager.email_verification.from.clone(),
            to: req.email,
            subject: state
                .config
                .users_manager
                .email_verification
                .subject
                .clone(),
            verification_url: url,
        }) {
        Ok(req) => state.users_manager.send_email_verification(req).await,
        Err(e) => Err(e),
    };

    tracing::debug!("[/verify-email] Response {res:?}");

    res.map(Json)
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
                    session: default_session_token(),
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
                    session: default_session_token(),
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
                    session: default_session_token(),
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
                    session: default_session_token(),
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
                    session: default_session_token(),
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

    fn default_session_token() -> SessionToken {
        SessionToken {
            token: "".to_string(),
        }
    }
}
