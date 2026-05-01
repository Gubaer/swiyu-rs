//! OAuth / OID4VCI error responses for the token and credential
//! endpoints.
//!
//! Distinct from [`super::error::OidcError`] because the OAuth surface
//! emits `{ error, error_description }` per RFC 6749 / OID4VCI, not
//! the management API's `{ error, details }` shape. The metadata and
//! offer-uri endpoints continue to use `OidcError` per the spec
//! (`impl_api_oidc.md` Error mapping).

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use thiserror::Error;

use crate::persistence::PersistenceError;

#[derive(Debug, Error)]
pub enum OAuthError {
    /// Pre-auth code unknown, expired, already redeemed, or attached
    /// to an offer that is not currently `pending`.
    #[error("invalid grant: {description}")]
    InvalidGrant { description: String },
    /// Malformed token-endpoint request — missing fields, wrong
    /// content type, garbled values.
    #[error("invalid request: {description}")]
    InvalidRequest { description: String },
    /// `grant_type` is something other than the pre-authorised-code
    /// grant. v0.1.x supports nothing else.
    #[error("unsupported grant type: {grant_type}")]
    UnsupportedGrantType { grant_type: String },
    /// Catch-all for unexpected server-side failures. Logged with
    /// the underlying error; response body says only "server error".
    #[error("internal error")]
    Internal(#[source] Box<dyn std::error::Error + Send + Sync>),
}

#[derive(Serialize)]
struct OAuthErrorBody {
    error: &'static str,
    error_description: String,
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let (status, code, description) = match &self {
            OAuthError::InvalidGrant { description } => (
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                description.clone(),
            ),
            OAuthError::InvalidRequest { description } => (
                StatusCode::BAD_REQUEST,
                "invalid_request",
                description.clone(),
            ),
            OAuthError::UnsupportedGrantType { grant_type } => (
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                format!("grant_type {grant_type:?} is not supported"),
            ),
            OAuthError::Internal(err) => {
                tracing::error!(error = %err, "internal server error on OAuth surface");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "an internal error occurred".to_string(),
                )
            }
        };
        (
            status,
            Json(OAuthErrorBody {
                error: code,
                error_description: description,
            }),
        )
            .into_response()
    }
}

impl From<PersistenceError> for OAuthError {
    fn from(err: PersistenceError) -> Self {
        match err {
            // A persistence-layer NotFound on the OAuth surface always
            // means "the wallet's credential cannot be honoured here";
            // OAuth's nearest standard reason is invalid_grant.
            PersistenceError::NotFound => OAuthError::InvalidGrant {
                description: "no offer matches the presented pre-authorised code".to_string(),
            },
            // Unique violations on the access-token table mean a
            // second /token request races for the same offer; the
            // pre-auth code is single-use.
            PersistenceError::UniqueViolation { what: _ } => OAuthError::InvalidGrant {
                description: "the pre-authorised code has already been redeemed".to_string(),
            },
            PersistenceError::DataIntegrity { details } => {
                tracing::error!(details, "data integrity violation in persistence layer");
                OAuthError::Internal(Box::new(std::io::Error::other(details)))
            }
            PersistenceError::Db(err) => OAuthError::Internal(Box::new(err)),
        }
    }
}
