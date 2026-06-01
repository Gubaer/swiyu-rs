mod credential_offers;
mod credential_types;
mod issuers;
mod me;
mod operation_tasks;

use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};
use tower_http::services::{ServeDir, ServeFile};
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
    let spa_dir = state.config.spa_dir.clone();

    let api = Router::new()
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
        .route(
            "/api/issuers/{issuer_id}/credential-offers",
            get(credential_offers::list_credential_offers)
                .post(credential_offers::create_credential_offer),
        )
        .route(
            "/api/issuers/{issuer_id}/credential-offers/{offer_id}",
            get(credential_offers::get_credential_offer),
        )
        .route(
            "/api/issuers/{issuer_id}/credential-types",
            get(credential_types::list_credential_types),
        )
        .route(
            "/api/credential-types/{credential_type_id}/schema",
            get(credential_types::get_credential_type_schema),
        )
        .with_state(state);

    // With SPA_DIR set, the BFF also serves the built SPA (single-container
    // prod), falling back to index.html for client-side routes. Unset means
    // `ng serve` owns the SPA and only `/api` is served here.
    let app = match spa_dir {
        Some(dir) => {
            let index = format!("{dir}/index.html");
            api.fallback_service(ServeDir::new(&dir).fallback(ServeFile::new(index)))
        }
        None => api,
    };

    app.layer(TraceLayer::new_for_http())
}
