use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use thiserror::Error;

use crate::domain::DomainError;
use crate::persistence::PersistenceError;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("not found")]
    NotFound,
    #[error("unauthorised")]
    Unauthorised,
    #[error("forbidden")]
    Forbidden,
    #[error("unknown vct: {vct}")]
    UnknownVct { vct: String },
    #[error("claims validation failed")]
    ClaimsValidationFailed { errors: Vec<String> },
    #[error("invalid input: {details}")]
    InvalidInput { details: String },
    #[error("conflict: {details}")]
    Conflict { details: String },
    #[error("not yet implemented: {what}")]
    NotImplemented { what: &'static str },
    #[error("internal error")]
    Internal(#[source] Box<dyn std::error::Error + Send + Sync>),
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
    details: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, details) = match &self {
            ApiError::NotFound => (
                StatusCode::NOT_FOUND,
                "not_found",
                "resource not found".to_string(),
            ),
            ApiError::Unauthorised => (
                StatusCode::UNAUTHORIZED,
                "unauthorised",
                "authentication required".to_string(),
            ),
            ApiError::Forbidden => (
                StatusCode::FORBIDDEN,
                "forbidden",
                "access denied".to_string(),
            ),
            ApiError::UnknownVct { vct } => (
                StatusCode::BAD_REQUEST,
                "unknown_vct",
                format!("no schema bundled for vct {vct}"),
            ),
            ApiError::ClaimsValidationFailed { errors } => (
                StatusCode::BAD_REQUEST,
                "claims_validation_failed",
                errors.join("; "),
            ),
            ApiError::InvalidInput { details } => {
                (StatusCode::BAD_REQUEST, "invalid_input", details.clone())
            }
            ApiError::Conflict { details } => (StatusCode::CONFLICT, "conflict", details.clone()),
            ApiError::NotImplemented { what } => (
                StatusCode::NOT_IMPLEMENTED,
                "not_implemented",
                (*what).to_string(),
            ),
            ApiError::Internal(err) => {
                tracing::error!(error = %err, "internal server error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "an internal error occurred".to_string(),
                )
            }
        };
        (
            status,
            Json(ErrorBody {
                error: code,
                details,
            }),
        )
            .into_response()
    }
}

impl From<DomainError> for ApiError {
    fn from(err: DomainError) -> Self {
        match err {
            DomainError::InvalidInput { details } => ApiError::InvalidInput { details },
            DomainError::StateTransitionNotAllowed => ApiError::Conflict {
                details: "state transition not allowed".to_string(),
            },
        }
    }
}

impl From<PersistenceError> for ApiError {
    fn from(err: PersistenceError) -> Self {
        match err {
            PersistenceError::NotFound => ApiError::NotFound,
            PersistenceError::UniqueViolation { what } => ApiError::Conflict {
                details: format!("unique constraint violated: {what}"),
            },
            PersistenceError::Db(err) => ApiError::Internal(Box::new(err)),
        }
    }
}
