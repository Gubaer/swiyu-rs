mod auth;
mod credential_offers;
mod dto;
mod error;
mod issued_credentials;
mod issuers;
mod operation_tasks;
mod schemas;
mod state;

pub use error::ApiError;
pub use state::{AppState, Config};

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
            post(credential_offers::create).get(credential_offers::list),
        )
        .route(
            "/api/v1/issuers/{issuer_id}/credential-offers/{offer_id}",
            get(credential_offers::get),
        )
        .route(
            "/api/v1/issuers/{issuer_id}/credential-offers/{offer_id}/cancel",
            post(credential_offers::cancel),
        )
        .route(
            "/api/v1/issuers/{issuer_id}/credential-offers/{offer_id}/status",
            get(credential_offers::status),
        )
        .route(
            "/api/v1/issued-credentials/{credential_id}/suspend",
            post(issued_credentials::suspend),
        )
        .route(
            "/api/v1/issued-credentials/{credential_id}/unsuspend",
            post(issued_credentials::unsuspend),
        )
        .route(
            "/api/v1/issued-credentials/{credential_id}/revoke",
            post(issued_credentials::revoke),
        )
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
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
