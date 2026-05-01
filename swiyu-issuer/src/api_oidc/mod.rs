mod error;
mod metadata;
mod state;

pub use error::OidcError;
pub use state::{AppState, Config};

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route(
            "/i/{issuer_id}/.well-known/openid-credential-issuer",
            get(metadata::credential_issuer_metadata),
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
