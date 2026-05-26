mod issuers;
mod me;
mod operation_tasks;

use std::sync::Arc;

use axum::Router;
use axum::routing::get;
use tower_http::trace::TraceLayer;

use crate::config::Config;
use crate::upstream::MgmtApiClient;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub mgmt_api: MgmtApiClient,
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
            "/api/operation-tasks/{task_id}",
            get(operation_tasks::get_task),
        )
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}
