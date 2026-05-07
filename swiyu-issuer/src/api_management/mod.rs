mod auth;
mod credential_offers;
mod cursor;
mod dto;
mod error;
mod issued_credentials;
mod issuers;
mod operation_tasks;
mod schemas;
mod state;

pub use error::ApiError;
pub use state::{AppState, Config};

use crate::domain::IssuerId;

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
}
