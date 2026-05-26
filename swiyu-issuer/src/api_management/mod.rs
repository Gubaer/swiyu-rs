mod auth;
mod credential_offers;
mod credential_types;
mod cursor;
mod dto;
mod error;
mod issued_credentials;
mod issuers;
mod operation_tasks;
mod state;

pub use error::ApiError;
pub use state::{AppState, Config};

use crate::domain::{CredentialTypeId, IssuerId};

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/api/v1/issuers", post(issuers::create).get(issuers::list))
        .route("/api/v1/issuers/{issuer_id}", get(issuers::get))
        .route(
            "/api/v1/issuers/{issuer_id}/deactivate",
            post(issuers::deactivate),
        )
        .route(
            "/api/v1/issuers/{issuer_id}/rotate-keys",
            post(issuers::rotate_keys),
        )
        .route(
            "/api/v1/operation-tasks/{task_id}",
            get(operation_tasks::get),
        )
        .route(
            "/api/v1/issuers/{issuer_id}/credential-offers",
            post(credential_offers::create).get(credential_offers::list_offers),
        )
        .route(
            "/api/v1/issuers/{issuer_id}/credential-offers/{offer_id}",
            get(credential_offers::get_offer),
        )
        .route(
            "/api/v1/issuers/{issuer_id}/credential-offers/{offer_id}/cancel",
            post(credential_offers::cancel_offer),
        )
        .route(
            "/api/v1/issuers/{issuer_id}/credential-offers/{offer_id}/status",
            get(credential_offers::get_offer_status),
        )
        .route(
            "/api/v1/issuers/{issuer_id}/credentials",
            get(issued_credentials::list),
        )
        .route(
            "/api/v1/issuers/{issuer_id}/credentials/{credential_id}",
            get(issued_credentials::get),
        )
        .route(
            "/api/v1/issuers/{issuer_id}/credentials/{credential_id}/suspend",
            post(issued_credentials::suspend),
        )
        .route(
            "/api/v1/issuers/{issuer_id}/credentials/{credential_id}/unsuspend",
            post(issued_credentials::unsuspend),
        )
        .route(
            "/api/v1/issuers/{issuer_id}/credentials/{credential_id}/revoke",
            post(issued_credentials::revoke),
        )
        .route(
            "/api/v1/credential-types",
            post(credential_types::create).get(credential_types::list),
        )
        .route(
            "/api/v1/credential-types/{credential_type_id}",
            get(credential_types::get).patch(credential_types::patch),
        )
        .route(
            "/api/v1/credential-types/{credential_type_id}/retire",
            post(credential_types::retire),
        )
        .route(
            "/api/v1/credential-types/{credential_type_id}/schema",
            get(credential_types::get_schema).put(credential_types::put_schema),
        )
        .route(
            "/api/v1/credential-types/{credential_type_id}/display",
            get(credential_types::get_display).put(credential_types::put_display),
        )
        .route(
            "/api/v1/credential-types/{credential_type_id}/claims",
            get(credential_types::get_claims).put(credential_types::put_claims),
        )
        .route(
            "/api/v1/issuers/{issuer_id}/credential-types",
            get(credential_types::list_assignments),
        )
        .route(
            "/api/v1/issuers/{issuer_id}/credential-types/{credential_type_id}",
            post(credential_types::assign).delete(credential_types::unassign),
        )
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}

/// Default page size for list endpoints. Fits a typical operator UI page
/// without forcing a follow-up request.
const DEFAULT_LIST_LIMIT: u32 = 25;

/// Lower bound on `limit`. Zero would return an empty page with a
/// `next_cursor` that never advances, so the smallest legal page is one row.
const MIN_LIST_LIMIT: u32 = 1;

/// Upper bound on `limit`. Caps per-request work against the database and the
/// JSON response size; clients that need more rows must paginate.
const MAX_LIST_LIMIT: u32 = 100;

fn resolve_list_limit(requested: Option<u32>) -> Result<u32, ApiError> {
    let limit = requested.unwrap_or(DEFAULT_LIST_LIMIT);
    if !(MIN_LIST_LIMIT..=MAX_LIST_LIMIT).contains(&limit) {
        return Err(ApiError::InvalidInput {
            details: format!(
                "limit must be between {MIN_LIST_LIMIT} and {MAX_LIST_LIMIT}, got {limit}"
            ),
        });
    }
    Ok(limit)
}

fn parse_issuer_id(raw: &str) -> Result<IssuerId, ApiError> {
    IssuerId::from_bare(raw).map_err(|err| ApiError::InvalidInput {
        details: format!("issuer_id path parameter: {err}"),
    })
}

fn parse_credential_type_id(raw: &str) -> Result<CredentialTypeId, ApiError> {
    CredentialTypeId::from_bare(raw).map_err(|err| ApiError::InvalidInput {
        details: format!("credential_type_id path parameter: {err}"),
    })
}

/// Trims and length-checks a required BA-supplied field.
///
/// Returns `InvalidInput` if `raw` is blank after trim or if the
/// trimmed value exceeds `max_len` bytes. Each caller passes its
/// own `max_len` since legitimate caps differ (e.g. short display
/// names vs URI-style identifiers).
fn normalise_required(name: &'static str, raw: &str, max_len: usize) -> Result<String, ApiError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ApiError::InvalidInput {
            details: format!("{name} must not be blank"),
        });
    }
    if trimmed.len() > max_len {
        return Err(ApiError::InvalidInput {
            details: format!(
                "{name} must be at most {max_len} bytes (got {})",
                trimmed.len()
            ),
        });
    }
    Ok(trimmed.to_string())
}

/// Trims and length-checks an optional BA-supplied field.
///
/// Returns `Ok(None)` when the field is missing or trims to empty
/// (the caller substitutes a default in that case). `Ok(Some(...))`
/// is returned when the field has content; oversized values surface
/// as `InvalidInput`.
fn normalise_optional(
    name: &'static str,
    raw: Option<&str>,
    max_len: usize,
) -> Result<Option<String>, ApiError> {
    let Some(value) = raw else {
        return Ok(None);
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.len() > max_len {
        return Err(ApiError::InvalidInput {
            details: format!(
                "{name} must be at most {max_len} bytes (got {})",
                trimmed.len()
            ),
        });
    }
    Ok(Some(trimmed.to_string()))
}

async fn healthz() -> &'static str {
    "ok"
}

async fn readyz(State(state): State<AppState>) -> Result<&'static str, StatusCode> {
    state
        .pool
        .acquire()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok("ok")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_list_limit_uses_default_when_unset() {
        assert_eq!(resolve_list_limit(None).unwrap(), DEFAULT_LIST_LIMIT);
    }

    #[test]
    fn resolve_list_limit_accepts_value_in_range() {
        assert_eq!(resolve_list_limit(Some(50)).unwrap(), 50);
        assert_eq!(
            resolve_list_limit(Some(MIN_LIST_LIMIT)).unwrap(),
            MIN_LIST_LIMIT
        );
        assert_eq!(
            resolve_list_limit(Some(MAX_LIST_LIMIT)).unwrap(),
            MAX_LIST_LIMIT
        );
    }

    #[test]
    fn resolve_list_limit_rejects_zero() {
        assert!(resolve_list_limit(Some(0)).is_err());
    }

    #[test]
    fn resolve_list_limit_rejects_above_max() {
        assert!(resolve_list_limit(Some(MAX_LIST_LIMIT + 1)).is_err());
    }

    #[test]
    fn parse_issuer_id_accepts_valid_base58() {
        assert!(parse_issuer_id("9hXq2vRtL8pK7f").is_ok());
    }

    #[test]
    fn parse_issuer_id_rejects_invalid_character() {
        assert!(matches!(
            parse_issuer_id("notValid0").unwrap_err(),
            ApiError::InvalidInput { .. }
        ));
    }

    #[test]
    fn parse_credential_type_id_accepts_valid_base58() {
        assert!(parse_credential_type_id("9hXq2vRtL8pK7f").is_ok());
    }

    #[test]
    fn parse_credential_type_id_rejects_invalid_character() {
        assert!(matches!(
            parse_credential_type_id("notValid0").unwrap_err(),
            ApiError::InvalidInput { .. }
        ));
    }

    // Arbitrary cap used by the normalise_* tests; the helpers
    // take max_len as a parameter so the test value doesn't need
    // to match any production constant.
    const TEST_MAX: usize = 16;

    #[test]
    fn normalise_required_accepts_trimmed_value() {
        let v = normalise_required("name", "  Padded  ", TEST_MAX).unwrap();
        assert_eq!(v, "Padded");
    }

    #[test]
    fn normalise_required_rejects_blank() {
        assert!(matches!(
            normalise_required("name", "   \t\n", TEST_MAX),
            Err(ApiError::InvalidInput { .. })
        ));
    }

    #[test]
    fn normalise_required_rejects_oversized() {
        let too_long = "a".repeat(TEST_MAX + 1);
        let err = normalise_required("name", &too_long, TEST_MAX).unwrap_err();
        match err {
            ApiError::InvalidInput { details } => {
                assert!(details.contains("name"));
                assert!(details.contains("at most"));
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn normalise_optional_returns_none_for_missing() {
        let v = normalise_optional("name", None, TEST_MAX).unwrap();
        assert!(v.is_none());
    }

    #[test]
    fn normalise_optional_returns_none_for_blank() {
        let v = normalise_optional("name", Some("   \t\n"), TEST_MAX).unwrap();
        assert!(v.is_none());
    }

    #[test]
    fn normalise_optional_trims_whitespace() {
        let v = normalise_optional("name", Some("  Padded  "), TEST_MAX).unwrap();
        assert_eq!(v.as_deref(), Some("Padded"));
    }

    #[test]
    fn normalise_optional_rejects_oversized() {
        let too_long = "a".repeat(TEST_MAX + 1);
        assert!(matches!(
            normalise_optional("name", Some(&too_long), TEST_MAX),
            Err(ApiError::InvalidInput { .. })
        ));
    }

    #[test]
    fn normalise_optional_accepts_at_max_length() {
        let exact = "a".repeat(TEST_MAX);
        let v = normalise_optional("name", Some(&exact), TEST_MAX).unwrap();
        assert_eq!(v.unwrap().len(), TEST_MAX);
    }
}
