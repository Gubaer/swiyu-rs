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
pub use state::{AppState, Config};

use crate::domain::{CredentialTypeId, IssuerId};

pub(super) const PRE_AUTHORIZED_GRANT_TYPE: &str =
    "urn:ietf:params:oauth:grant-type:pre-authorized_code";

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
        .route("/i/{issuer_id}/credential", post(credential::credential))
        .route(
            "/schemas/{credential_type_id}",
            get(schemas::get_public_schema),
        )
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
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
