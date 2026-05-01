use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use thiserror::Error;

use crate::persistence::PersistenceError;

/// Error variants surfaced by the wallet-facing OIDC binary.
///
/// The token and credential endpoints emit OAuth-shaped error
/// bodies (`{ error, error_description }`); the metadata and offer-
/// uri endpoints emit the management API's `{ error, details }`
/// shape (per `impl_api_oidc.md` Error mapping). The `IntoResponse`
/// impl below renders the management shape — token and credential
/// endpoints will reach for an OAuth-shaped sibling once those
/// handlers land.
#[derive(Debug, Error)]
pub enum OidcError {
    #[error("not found")]
    NotFound,
    #[error("expired")]
    Expired,
    #[error("invalid input: {details}")]
    InvalidInput { details: String },
    #[error("internal error")]
    Internal(#[source] Box<dyn std::error::Error + Send + Sync>),
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
    details: String,
}

impl IntoResponse for OidcError {
    fn into_response(self) -> Response {
        let (status, code, details) = match &self {
            OidcError::NotFound => (
                StatusCode::NOT_FOUND,
                "not_found",
                "resource not found".to_string(),
            ),
            OidcError::Expired => (
                StatusCode::GONE,
                "expired",
                "the requested resource has expired".to_string(),
            ),
            OidcError::InvalidInput { details } => {
                (StatusCode::BAD_REQUEST, "invalid_input", details.clone())
            }
            OidcError::Internal(err) => {
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

impl From<PersistenceError> for OidcError {
    fn from(err: PersistenceError) -> Self {
        match err {
            PersistenceError::NotFound => OidcError::NotFound,
            PersistenceError::DataIntegrity { details } => {
                tracing::error!(details, "data integrity violation in persistence layer");
                OidcError::Internal(Box::new(std::io::Error::other(details)))
            }
            PersistenceError::Db(err) => OidcError::Internal(Box::new(err)),
            PersistenceError::UniqueViolation { what } => {
                // The OIDC binary should never see a unique-violation in the
                // metadata read path. If it ever does, something is structurally
                // wrong; bubble up as Internal so the operator notices.
                tracing::error!(what, "unexpected unique violation in OIDC layer");
                OidcError::Internal(Box::new(std::io::Error::other(format!(
                    "unique constraint violated: {what}"
                ))))
            }
        }
    }
}
