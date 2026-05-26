mod issuers;
mod me;
mod operation_tasks;

use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};
use tower_http::trace::TraceLayer;

use swiyu_registries::identifier::IdentifierRegistryClient;

use crate::config::Config;
use crate::upstream::MgmtApiClient;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub mgmt_api: MgmtApiClient,
    pub identifier_registry: Arc<IdentifierRegistryClient>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/me", get(me::get_me))
        .route(
            "/api/issuers",
            get(issuers::list_issuers).post(issuers::create_issuer),
        )
        .route("/api/issuers/{issuer_id}", get(issuers::get_issuer))
        .route(
            "/api/issuers/{issuer_id}/did-log",
            get(issuers::get_did_log),
        )
        .route(
            "/api/issuers/{issuer_id}/deactivate",
            post(issuers::deactivate_issuer),
        )
        .route(
            "/api/issuers/{issuer_id}/rotate-keys",
            post(issuers::rotate_keys),
        )
        .route(
            "/api/operation-tasks/{task_id}",
            get(operation_tasks::get_task),
        )
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}
