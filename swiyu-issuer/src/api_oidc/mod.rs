mod credential_offer;
mod error;
mod metadata;
mod oauth_error;
mod state;
mod token;

pub use error::OidcError;
pub use oauth_error::OAuthError;
pub use state::{AppState, Config};

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route(
            "/i/{issuer_id}/.well-known/openid-credential-issuer",
            get(metadata::credential_issuer_metadata),
        )
        .route(
            "/i/{issuer_id}/.well-known/oauth-authorization-server",
            get(metadata::oauth_authorization_server_metadata),
        )
        .route(
            "/i/{issuer_id}/credential-offer/{offer_id}",
            get(credential_offer::credential_offer),
        )
        .route("/i/{issuer_id}/token", post(token::token))
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
