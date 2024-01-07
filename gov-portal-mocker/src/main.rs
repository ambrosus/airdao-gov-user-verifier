use axum::{
    extract::{Query, State},
    response::Html,
    routing::get,
    Router,
};
use base64::{engine::general_purpose, Engine};
use ethabi::Address;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use tower_http::cors::CorsLayer;

use shared::{
    common::{
        ApprovedResponse, PendingResponse, SBTRequest, SessionToken, SignedSBTRequest, User,
        UserRegistrationToken, VerifyAccountResponse,
    },
    logger, utils,
};

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AppConfig {
    pub listen_address: String,
    pub web: WebConfig,
    pub signer: SignerConfig,
    pub user_db: UserDbConfig,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignerConfig {
    pub url: String,
    pub redirect_uri: String,
    pub fractal_client_id: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct WebConfig {
    pub pages: HashMap<String, String>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UserDbConfig {
    pub base_url: String,
}

#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub pages: HashMap<String, String>,
    pub client: Client,
}

#[derive(Debug, Deserialize)]
pub struct AuthQuery {
    pub wallet: Option<Address>,
    #[serde(flatten)]
    pub result: AuthResult,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum AuthResult {
    Success {
        code: String,
    },
    Retry {
        token: String,
    },
    Failure {
        error: String,
        error_description: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum IndexQuery {
    WithJwtToken { session: String },
    NoJwtToken {},
}

#[derive(Debug, Deserialize)]
pub struct VerifyEmailQuery {
    email: serde_email::Email,
    session: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum RegisterQuery {
    WithJwtToken { token: String },
    NoJwtToken {},
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum VerifyWalletQuery {
    WalletSignedMessage { data: String },
    NoWallet {},
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum AuthResponse {
    Approved(SBTRequest),
    Pending(PendingResponse),
}

#[derive(Debug, Deserialize)]
pub struct VerificationError {
    error: String,
}

impl AppState {
    pub async fn new(config: AppConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let mut pages = HashMap::new();

        for (page, path) in &config.web.pages {
            let content = tokio::fs::read_to_string(path).await.map_err(|e| {
                format!("Failed to read `{page}` (path: `{path}`) content. Error: {e}")
            })?;
            pages.insert(page.clone(), content);
        }

        Ok(Self {
            config,
            pages,
            client: Client::new(),
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    logger::init();
    utils::set_heavy_panic();

    let config = utils::load_config::<AppConfig>("./gov-portal-mocker").await?;

    let addr = config
        .listen_address
        .parse::<std::net::SocketAddr>()
        .expect("Can't parse socket address");

    let state = AppState::new(config.clone()).await?;

    let app = Router::new()
        .route("/", get(index_route))
        .route("/auth", get(auth_route))
        .route("/verify-email", get(verify_email_route))
        .route("/register", get(register_route))
        .route("/verify-wallet", get(verify_wallet_route))
        .layer(CorsLayer::permissive())
        .with_state(state);

    tracing::info!("Server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;

    axum::serve(listener, app).await?;

    Ok(())
}

async fn index_route(
    State(state): State<AppState>,
    Query(req): Query<IndexQuery>,
) -> Result<Html<String>, String> {
    let (page_name, session_token) = match req {
        IndexQuery::WithJwtToken { session: token } => match state.get_user(&token).await {
            Ok(User { wallet: _, .. }) => ("index.html", None),
            Err(e) => {
                tracing::warn!(
                    "Failed to get user by session token `{token}`. Error: {}",
                    e
                );
                ("no-user.html", Some(token))
            }
        },
        IndexQuery::NoJwtToken {} => ("no-session.html", None),
    };

    state
        .pages
        .get(page_name)
        .map(|content| {
            Html(
                content
                    .replace("{{SESSION}}", &session_token.unwrap_or_default())
                    .replace("{{CLIENT_ID}}", &state.config.signer.fractal_client_id),
            )
        })
        .ok_or_else(|| "Resource Not Found".to_owned())
}

async fn verify_wallet_route(
    State(state): State<AppState>,
    Query(req): Query<VerifyWalletQuery>,
) -> Result<Html<String>, String> {
    let (page_name, session_token) = match req {
        VerifyWalletQuery::WalletSignedMessage { data } => {
            match state.acquire_session_token(data).await {
                Ok(SessionToken { token }) => ("valid-message.html", Some(token)),
                Err(e) => {
                    tracing::warn!("Failed to acquire session token. Error: {}", e);
                    ("no-wallet.html", None)
                }
            }
        }
        VerifyWalletQuery::NoWallet {} => ("no-wallet.html", None),
    };

    state
        .pages
        .get(page_name)
        .map(|content| Html(content.replace("{{SESSION}}", &session_token.unwrap_or_default())))
        .ok_or_else(|| "Resource Not Found".to_owned())
}

async fn auth_route(
    State(state): State<AppState>,
    Query(req): Query<AuthQuery>,
) -> Result<Html<String>, String> {
    tracing::debug!("Request {:?}", req);

    match req {
        // If result from Fractal was Success or Pending and if no wallet in query string, response with HTML
        AuthQuery {
            wallet: None,
            result: AuthResult::Success { .. } | AuthResult::Retry { .. },
        } => state
            .pages
            .get("auth-redirect.html")
            .cloned()
            .map(Html)
            .ok_or_else(|| "Resource Not Found".to_owned()),
        AuthQuery {
            wallet: Some(wallet),
            result: AuthResult::Success { code },
        } => state
            .get_sbt_request_by_auth_code(wallet, code)
            .await
            .map_err(|e| {
                tracing::warn!("Failed to verify Fractal auth code. Error: {e:?}");
                format!("Internal Error: {e}")
            }),
        AuthQuery {
            wallet: Some(wallet),
            result: AuthResult::Retry { token },
        } => state
            .get_sbt_request_by_token(wallet, token)
            .await
            .map_err(|e| {
                tracing::warn!("Failed to retry user verification with Fractal. Error: {e:?}");
                format!("Internal Error: {e}")
            }),
        AuthQuery {
            wallet: _,
            result:
                AuthResult::Failure {
                    error,
                    error_description,
                },
        } => {
            tracing::warn!(
                "Fractal verification failure. Error: {error} (description: {error_description})"
            );
            Err(format!(
                "Internal Error: {error} (description: {error_description})"
            ))
        }
    }
}

async fn verify_email_route(
    State(state): State<AppState>,
    Query(req): Query<VerifyEmailQuery>,
) -> Result<Html<String>, String> {
    let (page_name, token) = match state.verify_email(&req.email, &req.session).await {
        Ok(UserRegistrationToken { token, .. }) => ("confirm-registration.html", Some(token)),
        Err(e) => {
            tracing::warn!(
                "Failed to register user ({}) by session token `{}`. Error: {}",
                req.email,
                req.session,
                e
            );
            ("no-session.html", None)
        }
    };

    state
        .pages
        .get(page_name)
        .map(|content| Html(content.replace("{{REGISTRATION_TOKEN}}", &token.unwrap_or_default())))
        .ok_or_else(|| "Resource Not Found".to_owned())
}

async fn register_route(
    State(state): State<AppState>,
    Query(req): Query<RegisterQuery>,
) -> Result<Html<String>, String> {
    let page_name = match req {
        RegisterQuery::WithJwtToken { token } => match state.register_user(&token).await {
            Ok(User { wallet: _, .. }) => "no-session.html", // at this point we don't have session token, so user should connect wallet again
            Err(e) => {
                tracing::warn!(
                    "Failed to register user by registration token `{token}`. Error: {}",
                    e
                );
                "no-session.html"
            }
        },
        RegisterQuery::NoJwtToken {} => "no-session.html",
    };

    state
        .pages
        .get(page_name)
        .map(|content| {
            Html(content.replace("{{CLIENT_ID}}", &state.config.signer.fractal_client_id))
        })
        .ok_or_else(|| "Resource Not Found".to_owned())
}

impl AppState {
    async fn acquire_session_token(
        &self,
        encoded_msg: String,
    ) -> Result<SessionToken, anyhow::Error> {
        let raw_data = self
            .client
            .post(&[&self.config.user_db.base_url, "/token"].concat())
            .json(&json!({"data": &encoded_msg}))
            .send()
            .await?
            .text()
            .await?;

        serde_json::from_str::<SessionToken>(&raw_data).map_err(|_| anyhow::Error::msg(raw_data))
    }

    async fn verify_email(
        &self,
        email: &serde_email::Email,
        token: &str,
    ) -> Result<UserRegistrationToken, anyhow::Error> {
        let raw_data = self
            .client
            .post(&[&self.config.user_db.base_url, "/verify-email"].concat())
            .json(&json!({"token": token, "email": email}))
            .send()
            .await?
            .text()
            .await?;

        serde_json::from_str::<UserRegistrationToken>(&raw_data)
            .map_err(|_| anyhow::Error::msg(raw_data))
    }

    async fn register_user(&self, token: &str) -> Result<User, anyhow::Error> {
        let raw_data = self
            .client
            .post(&[&self.config.user_db.base_url, "/register"].concat())
            .json(&json!({"token": token}))
            .send()
            .await?
            .text()
            .await?;

        serde_json::from_str::<User>(&raw_data).map_err(|_| anyhow::Error::msg(raw_data))
    }

    async fn get_user(&self, token: &str) -> Result<User, anyhow::Error> {
        let raw_data = self
            .client
            .post(&[&self.config.user_db.base_url, "/user"].concat())
            .json(&json!({"token": token}))
            .send()
            .await?
            .text()
            .await?;

        serde_json::from_str::<User>(&raw_data).map_err(|_| anyhow::Error::msg(raw_data))
    }

    async fn get_sbt_request_by_auth_code(
        &self,
        wallet: Address,
        auth_code: String,
    ) -> Result<Html<String>, anyhow::Error> {
        let response = self
            .client
            .post(format!("{}/verify", self.config.signer.url))
            .json(&json!({
                "wallet": wallet,
                "auth_code": auth_code,
                "redirect_uri": self.config.signer.redirect_uri,
            }))
            .send()
            .await?
            .text()
            .await?;

        self.generate_html_response(response)
    }

    async fn get_sbt_request_by_token(
        &self,
        wallet: Address,
        token: String,
    ) -> Result<Html<String>, anyhow::Error> {
        let response = self
            .client
            .post(format!("{}/verify", self.config.signer.url))
            .json(&json!({
                "wallet": wallet,
                "token": token,
                "redirect_uri": self.config.signer.redirect_uri,
            }))
            .send()
            .await?
            .text()
            .await?;

        self.generate_html_response(response)
    }

    fn generate_html_response(&self, response: String) -> Result<Html<String>, anyhow::Error> {
        tracing::debug!("User verifier raw response: {}", response);

        match serde_json::from_str(&response) {
            Ok(VerifyAccountResponse::Approved(ApprovedResponse {
                msg: base64_encoded_result,
            })) => {
                let page_content = self
                    .pages
                    .get("success.html")
                    .ok_or_else(|| anyhow::Error::msg("Page content `success.html` not found!"))?;

                let signed_sbt_request = serde_json::from_slice::<SignedSBTRequest>(
                    &general_purpose::STANDARD.decode(base64_encoded_result)?,
                )?;

                let sbt_req = SBTRequest::try_from(signed_sbt_request)?;

                Ok(Html(
                    page_content.replace("{{RESULT}}", &serde_json::to_string(&sbt_req)?),
                ))
            }
            Ok(VerifyAccountResponse::Pending(PendingResponse { token })) => {
                let page_content = self
                    .pages
                    .get("pending.html")
                    .ok_or_else(|| anyhow::Error::msg("Page content `pending.html` not found!"))?;

                Ok(Html(page_content.replace(
                    "{{TOKEN}}",
                    &serde_json::to_string(&token)?.replace('"', ""),
                )))
            }
            Err(_) => {
                let VerificationError { error } = serde_json::from_str(&response)?;
                Err(anyhow::Error::msg(error))
            }
        }
    }
}
