mod credential;
mod credential_offer;
mod error;
mod metadata;
mod oauth_error;
mod schemas;
mod state;
mod token;

pub use error::OidcError;
pub use oauth_error::OAuthError;
pub use state::{AppState, Config, CorsAllowedOrigins};

use crate::domain::{CredentialTypeId, IssuerId};

pub(super) const PRE_AUTHORIZED_GRANT_TYPE: &str =
    "urn:ietf:params:oauth:grant-type:pre-authorized_code";

use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::{Method, StatusCode, header};
use axum::routing::{get, post};
use tower_http::cors::{AllowOrigin, CorsLayer};

pub fn router(state: AppState) -> Router {
    let cors = build_cors_layer(&state.config.cors_allowed_origins);
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
        .route("/i/{issuer_id}/credential", post(credential::credential))
        .route(
            "/schemas/{credential_type_id}",
            get(schemas::get_public_schema),
        )
        .layer(cors)
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}

fn build_cors_layer(allowed_origins: &CorsAllowedOrigins) -> CorsLayer {
    let allow_origin = match allowed_origins {
        CorsAllowedOrigins::Any => AllowOrigin::any(),
        CorsAllowedOrigins::List(origins) => AllowOrigin::list(origins.iter().cloned()),
    };
    // Named explicitly because the Fetch `*` wildcard does not cover
    // `Authorization`, which the credential endpoint requires.
    let allow_headers = [header::AUTHORIZATION, header::CONTENT_TYPE];
    // No `allow_credentials`: the flow's bearer token rides in the
    // `Authorization` header, not cookies, which keeps `Any` safe.
    CorsLayer::new()
        .allow_origin(allow_origin)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(allow_headers)
        .max_age(Duration::from_secs(600))
}

pub(super) fn parse_issuer_id(raw: &str) -> Result<IssuerId, OidcError> {
    IssuerId::from_bare(raw).map_err(|err| OidcError::InvalidInput {
        details: format!("issuer_id path parameter: {err}"),
    })
}

pub(super) fn parse_credential_type_id(raw: &str) -> Result<CredentialTypeId, OidcError> {
    CredentialTypeId::from_bare(raw).map_err(|err| OidcError::InvalidInput {
        details: format!("credential_type_id path parameter: {err}"),
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
    fn parse_issuer_id_accepts_valid_base58() {
        assert!(parse_issuer_id("9hXq2vRtL8pK7f").is_ok());
    }

    #[test]
    fn parse_issuer_id_rejects_invalid_character() {
        assert!(matches!(
            parse_issuer_id("notValid0").unwrap_err(),
            OidcError::InvalidInput { .. }
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
            OidcError::InvalidInput { .. }
        ));
    }
}
