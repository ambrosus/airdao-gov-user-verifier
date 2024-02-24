use axum::{extract::State, routing::post, Json, Router};
use std::sync::Arc;

use crate::{sendgrid::SendGridClient, templates_manager::TemplatesManager};
use shared::common::EmailVerificationRequest;

/// State shared between route handlers
#[derive(Clone)]
pub struct AppState {
    sendgrid_client: Arc<SendGridClient>,
    templates_manager: Arc<TemplatesManager>,
}

pub async fn start(
    addr: std::net::SocketAddr,
    sendgrid_client: SendGridClient,
    templates_manager: TemplatesManager,
) -> anyhow::Result<()> {
    let state = AppState {
        sendgrid_client: Arc::new(sendgrid_client),
        templates_manager: Arc::new(templates_manager),
    };

    let app = Router::new()
        .route("/send-verification-email", post(send_verification_email))
        .with_state(state);

    tracing::debug!("Server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;

    axum::serve(listener, app)
        .await
        .map_err(anyhow::Error::from)
}

async fn send_verification_email(
    State(state): State<AppState>,
    Json(req): Json<EmailVerificationRequest>,
) -> Result<Json<()>, String> {
    tracing::debug!("[/send-verification-email] Request {req:?}");

    let res = match state
        .templates_manager
        .templates
        .get("email_verification")
        .map(|template| template.replace("{{VERIFICATION_LINK}}", req.verification_url.as_str()))
    {
        Some(template) => state
            .sendgrid_client
            .send(req.from, template, req.subject, req.to)
            .await
            .map_err(|e| format!("Send verification email failure. Error: {e:?}")),
        None => Err("Email verification template is missed".to_string()),
    };

    tracing::debug!("[/send-verification-email] Response {res:?}");

    res.map(Json)
}
