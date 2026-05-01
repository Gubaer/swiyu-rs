use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chrono::{Duration, Utc};

use crate::domain::{CredentialOffer, CredentialOfferId, IssuerId, PreAuthCode};
use crate::persistence;

use super::AppState;
use super::auth::{TenantContext, require_issuer_owned_by_tenant};
use super::dto::{CreateCredentialOfferRequest, CreateCredentialOfferResponse};
use super::error::ApiError;

const DEFAULT_EXPIRES_IN_SECONDS: u32 = 600;
const MIN_EXPIRES_IN_SECONDS: u32 = 60;
const MAX_EXPIRES_IN_SECONDS: u32 = 3600;

pub async fn create(
    State(state): State<AppState>,
    Path(issuer_id_str): Path<String>,
    tenant_context: TenantContext,
    Json(payload): Json<CreateCredentialOfferRequest>,
) -> Result<(StatusCode, Json<CreateCredentialOfferResponse>), ApiError> {
    tracing::debug!(
        tenant_id = %tenant_context.tenant_id,
        issuer_id = %issuer_id_str,
        vct = %payload.vct,
        expires_in_seconds = ?payload.expires_in_seconds,
        "credential offer creation requested",
    );

    let issuer_id = IssuerId::from_bare(&issuer_id_str).map_err(|err| ApiError::InvalidInput {
        details: format!("issuer_id path parameter: {err}"),
    })?;

    validate_claims(&state, &payload)?;
    let expires_in = resolve_expires_in(payload.expires_in_seconds)?;

    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;

    require_issuer_owned_by_tenant(&mut conn, &tenant_context.tenant_id, &issuer_id).await?;

    let pre_auth_code = PreAuthCode::generate();
    let pre_auth_code_hash = pre_auth_code.hash();
    let expires_at = Utc::now() + expires_in;

    let offer = CredentialOffer::new(
        tenant_context.tenant_id.clone(),
        issuer_id,
        payload.vct,
        payload.claims,
        pre_auth_code_hash,
        expires_at,
    );

    persistence::credential_offers::insert(&mut conn, &offer).await?;

    let deeplink = build_offer_deeplink(&state.config.issuer_base_url, &offer.id);

    let response = CreateCredentialOfferResponse {
        id: offer.id.to_string(),
        pre_auth_code: pre_auth_code.into_inner(),
        offer_deeplink: deeplink,
        expires_at,
    };

    Ok((StatusCode::CREATED, Json(response)))
}

fn validate_claims(
    state: &AppState,
    payload: &CreateCredentialOfferRequest,
) -> Result<(), ApiError> {
    let validator = state
        .schemas
        .get(&payload.vct)
        .ok_or_else(|| ApiError::UnknownVct {
            vct: payload.vct.clone(),
        })?;

    let errors: Vec<String> = validator
        .iter_errors(&payload.claims)
        .map(|err| err.to_string())
        .collect();

    if errors.is_empty() {
        Ok(())
    } else {
        Err(ApiError::ClaimsValidationFailed { errors })
    }
}

fn resolve_expires_in(requested: Option<u32>) -> Result<Duration, ApiError> {
    let seconds = requested.unwrap_or(DEFAULT_EXPIRES_IN_SECONDS);
    if !(MIN_EXPIRES_IN_SECONDS..=MAX_EXPIRES_IN_SECONDS).contains(&seconds) {
        return Err(ApiError::InvalidInput {
            details: format!(
                "expires_in_seconds must be between {MIN_EXPIRES_IN_SECONDS} and {MAX_EXPIRES_IN_SECONDS}, got {seconds}"
            ),
        });
    }
    Ok(Duration::seconds(seconds.into()))
}

fn build_offer_deeplink(issuer_base_url: &str, offer_id: &CredentialOfferId) -> String {
    let credential_offer_uri = format!(
        "{}/o/{}",
        issuer_base_url.trim_end_matches('/'),
        offer_id.bare()
    );
    let encoded = urlencoding::encode(&credential_offer_uri);
    format!("openid-credential-offer://?credential_offer_uri={encoded}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deeplink_url_encodes_the_offer_uri() {
        let offer_id = CredentialOfferId::from_bare("9hXq2vRtL8pK7f").unwrap();
        let deeplink = build_offer_deeplink("https://issuer.example.com", &offer_id);
        assert_eq!(
            deeplink,
            "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example.com%2Fo%2F9hXq2vRtL8pK7f"
        );
    }

    #[test]
    fn deeplink_strips_trailing_slash_from_base_url() {
        let offer_id = CredentialOfferId::from_bare("9hXq2vRtL8pK7f").unwrap();
        let deeplink = build_offer_deeplink("https://issuer.example.com/", &offer_id);
        assert!(deeplink.contains("com%2Fo%2F9hXq2vRtL8pK7f"));
        assert!(!deeplink.contains("com%2F%2Fo"));
    }

    #[test]
    fn resolve_expires_in_uses_default_when_unset() {
        let duration = resolve_expires_in(None).unwrap();
        assert_eq!(
            duration,
            Duration::seconds(DEFAULT_EXPIRES_IN_SECONDS.into())
        );
    }

    #[test]
    fn resolve_expires_in_accepts_value_in_range() {
        let duration = resolve_expires_in(Some(120)).unwrap();
        assert_eq!(duration, Duration::seconds(120));
    }

    #[test]
    fn resolve_expires_in_rejects_below_min() {
        assert!(resolve_expires_in(Some(MIN_EXPIRES_IN_SECONDS - 1)).is_err());
    }

    #[test]
    fn resolve_expires_in_rejects_above_max() {
        assert!(resolve_expires_in(Some(MAX_EXPIRES_IN_SECONDS + 1)).is_err());
    }
}
