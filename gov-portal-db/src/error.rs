use axum::{http::StatusCode, response::IntoResponse, Json};
use serde_json::json;

use crate::users_manager;

#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error("JSON parse failure: {0}")]
    ParseError(#[from] serde_json::Error),
    #[error("Generic error: {0}")]
    Generic(String),
    #[error("Server error: {0}")]
    ServerError(#[from] std::io::Error),
    #[error("{0}")]
    InvalidInput(#[from] users_manager::error::Error),
    #[error("Web3 error: {0}")]
    Web3(#[from] web3::Error),
    #[error("Web3 contract error: {0}")]
    Contract(#[from] web3::contract::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, err_msg) = match self {
            Self::ParseError(_) | Self::ServerError(_) | Self::Web3(_) | Self::Contract(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_owned(),
            ),
            Self::Generic(e) => (StatusCode::UNAUTHORIZED, format!("Request failure: {e}")),
            Self::InvalidInput(e) => (StatusCode::NOT_ACCEPTABLE, format!("Invalid input: {e}")),
        };
        (status, Json(json!({ "error": err_msg }))).into_response()
    }
}

impl From<String> for AppError {
    fn from(error_str: String) -> Self {
        Self::Generic(error_str)
    }
}
