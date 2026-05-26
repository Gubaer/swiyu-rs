use axum::Json;
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use swiyu_registries::common::RegistryError;

use crate::upstream::CallError;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("upstream call failed: {0}")]
    Upstream(#[from] CallError),
    #[error("identifier registry call failed: {0}")]
    Registry(#[from] RegistryError),
    #[error("issuer record has no DID")]
    MissingDid,
    #[error("issuer DID could not be parsed")]
    InvalidDid,
    #[error("DID log could not be parsed")]
    InvalidDidLog,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        tracing::error!(error = %self, "request failed");
        match self {
            // Forward the upstream status and body verbatim so the SPA can tell
            // a 404/400 apart from a gateway failure. Upstream bodies are JSON.
            Self::Upstream(CallError::Status { status, body }) => {
                let status = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
                (status, [(CONTENT_TYPE, "application/json")], body).into_response()
            }
            Self::Upstream(CallError::Transport(_)) => gateway_error("upstream call failed"),
            // Forward the registry's HTTP status (notably 404 for an unknown
            // identifier); treat transport/decode failures as a gateway error.
            Self::Registry(RegistryError::HttpStatus { status, .. }) => {
                let status = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
                (
                    status,
                    Json(json!({ "error": "identifier registry error" })),
                )
                    .into_response()
            }
            Self::Registry(_) => gateway_error("identifier registry unavailable"),
            // The mgmt API or registry handed us data we could not use.
            Self::MissingDid | Self::InvalidDid | Self::InvalidDidLog => {
                gateway_error("could not resolve the DID log")
            }
        }
    }
}

fn gateway_error(message: &str) -> Response {
    (StatusCode::BAD_GATEWAY, Json(json!({ "error": message }))).into_response()
}
