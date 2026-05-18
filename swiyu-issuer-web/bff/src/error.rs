use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("upstream call failed: {0}")]
    Upstream(#[from] crate::upstream::CallError),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Self::Upstream(_) => (StatusCode::BAD_GATEWAY, "upstream call failed"),
        };
        tracing::error!(error = %self, "request failed");
        (status, Json(json!({ "error": message }))).into_response()
    }
}
