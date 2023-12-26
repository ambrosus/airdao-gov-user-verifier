use axum::{http::StatusCode, response::IntoResponse, Json};
use serde_json::json;

#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error("Face verification were rejected")]
    VerificationRejected,
    #[error("Face verification wasn't completed")]
    VerificationNotCompleted,
    #[error("Http request timed out: {0}")]
    TimeoutError(String),
    #[error("JSON parse failure: {0}")]
    ParseError(#[from] serde_json::Error),
    #[error("Generic error: {0}")]
    Generic(String),
    #[error("Server error: {0}")]
    ServerError(#[from] std::io::Error),
    #[error("Signing error: {0}")]
    SigningError(#[from] k256::ecdsa::Error),
    #[error("Http request failed: {0}")]
    ReqwestError(#[from] reqwest::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, err_msg) = match self {
            Self::ParseError(_)
            | Self::ServerError(_)
            | Self::SigningError(_)
            | Self::ReqwestError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_owned(),
            ),
            Self::VerificationRejected | Self::VerificationNotCompleted => {
                (StatusCode::UNAUTHORIZED, self.to_string())
            }
            Self::Generic(e) | Self::TimeoutError(e) => (
                StatusCode::UNAUTHORIZED,
                format!("Verification failure: {e}"),
            ),
        };
        (status, Json(json!({ "error": err_msg }))).into_response()
    }
}

impl From<String> for AppError {
    fn from(error_str: String) -> Self {
        Self::Generic(error_str)
    }
}
