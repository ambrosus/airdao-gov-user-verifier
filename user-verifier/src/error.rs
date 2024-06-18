use axum::{http::StatusCode, response::IntoResponse, Json};
use serde_json::json;

#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error("Wallet doesn't match or missed")]
    WalletMatchFailure,
    #[error("Wallet is not eligible for OG SBT")]
    OgVerificationNotAllowed,
    #[error("Wallet is not eligible yet for face verification")]
    VerificationNotAllowed,
    #[error("Face verification were rejected")]
    VerificationRejected,
    #[error("Face verification wasn't completed")]
    VerificationNotCompleted,
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
    #[error("Fractal error: {0}")]
    FractalError(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, err_msg) = match self {
            Self::ParseError(_)
            | Self::ServerError(_)
            | Self::SigningError(_)
            | Self::ReqwestError(_)
            | Self::FractalError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_owned(),
            ),
            Self::VerificationRejected
            | Self::OgVerificationNotAllowed
            | Self::VerificationNotAllowed
            | Self::VerificationNotCompleted
            | Self::WalletMatchFailure => (StatusCode::UNAUTHORIZED, self.to_string()),
            Self::Generic(e) => (
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
