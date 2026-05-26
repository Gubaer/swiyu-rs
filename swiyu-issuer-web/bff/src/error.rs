use axum::Json;
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::upstream::CallError;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("upstream call failed: {0}")]
    Upstream(#[from] CallError),
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
            Self::Upstream(CallError::Transport(_)) => (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": "upstream call failed" })),
            )
                .into_response(),
        }
    }
}
