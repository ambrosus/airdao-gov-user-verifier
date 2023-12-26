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
        ApprovedResponse, PendingResponse, SBTRequest, SignedSBTRequest, VerifyAccountResponse,
    },
    logger, utils,
};

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AppConfig {
    pub listen_address: String,
    pub web: WebConfig,
    pub signer: SignerConfig,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignerConfig {
    pub url: String,
    pub redirect_uri: String,
    pub fractal_client_id: String,
    pub fake_amb_wallet_address: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct WebConfig {
    pub pages: HashMap<String, String>,
}

#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub pages: HashMap<String, String>,
    pub client: Client,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum AuthQuery {
    Success {
        #[serde(rename = "state")]
        caller: Address,
        code: String,
    },
    Retry {
        #[serde(rename = "state")]
        caller: Address,
        token: String,
    },
    Failure {
        error: String,
        error_description: String,
    },
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
        .route("/", get(index_endpoint))
        .route("/auth", get(auth_endpoint))
        .layer(CorsLayer::permissive())
        .with_state(state);

    tracing::info!("Server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;

    axum::serve(listener, app).await?;

    Ok(())
}

async fn index_endpoint(State(state): State<AppState>) -> Result<Html<String>, String> {
    state
        .pages
        .get("index.html")
        .map(|content| {
            Html(
                content
                    .replace(
                        "{{CALLER_ADDRESS}}",
                        &state.config.signer.fake_amb_wallet_address,
                    )
                    .replace("{{CLIENT_ID}}", &state.config.signer.fractal_client_id),
            )
        })
        .ok_or_else(|| "Resource Not Found".to_owned())
}

async fn auth_endpoint(
    State(state): State<AppState>,
    Query(req): Query<AuthQuery>,
) -> Result<Html<String>, String> {
    tracing::debug!("Request {:?}", req);

    match req {
        AuthQuery::Success { caller, code } => state
            .get_sbt_request_by_auth_code(caller, code)
            .await
            .map_err(|e| {
                tracing::warn!("Failed to verify Fractal auth code. Error: {e:?}");
                "Internal Error".to_owned()
            }),
        AuthQuery::Retry { caller, token } => state
            .get_sbt_request_by_token(caller, token)
            .await
            .map_err(|e| {
                tracing::warn!("Failed to retry user verification with Fractal. Error: {e:?}");
                "Internal Error".to_owned()
            }),
        AuthQuery::Failure {
            error,
            error_description,
        } => {
            tracing::warn!(
                "Fractal verification failure. Error: {error} (description: {error_description})"
            );
            Err("Internal Error".to_owned())
        }
    }
}

impl AppState {
    async fn get_sbt_request_by_auth_code(
        &self,
        caller: Address,
        auth_code: String,
    ) -> Result<Html<String>, anyhow::Error> {
        let response = self
            .client
            .post(format!("{}/verify", self.config.signer.url))
            .json(&json!({
                "account": caller,
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
        caller: Address,
        token: String,
    ) -> Result<Html<String>, anyhow::Error> {
        let response = self
            .client
            .post(format!("{}/verify", self.config.signer.url))
            .json(&json!({
                "account": caller,
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

                Ok(Html(
                    page_content
                        .replace(
                            "{{TOKEN}}",
                            &serde_json::to_string(&token)?.replace(r#"""#, ""),
                        )
                        .replace(
                            "{{CALLER_ADDRESS}}",
                            &self.config.signer.fake_amb_wallet_address,
                        ),
                ))
            }
            Err(_) => {
                let VerificationError { error } = serde_json::from_str(&response)?;
                Err(anyhow::Error::msg(error))
            }
        }
    }
}
