use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chrono::{DateTime, Duration, Utc};

use crate::domain::{
    CredentialOffer, CredentialOfferId, CredentialOfferState, IssuerId, PreAuthCode,
};
use crate::persistence;

use super::AppState;
use super::auth::{TenantContext, require_issuer_owned_by_tenant};
use super::dto::{
    CreateCredentialOfferRequest, CreateCredentialOfferResponse, GetCredentialOfferResponse,
    OfferStatusResponse,
};
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

pub async fn get(
    State(state): State<AppState>,
    Path((issuer_id_str, offer_id_str)): Path<(String, String)>,
    tenant_context: TenantContext,
) -> Result<Json<GetCredentialOfferResponse>, ApiError> {
    tracing::debug!(
        tenant_id = %tenant_context.tenant_id,
        issuer_id = %issuer_id_str,
        offer_id = %offer_id_str,
        "credential offer fetch requested",
    );

    let issuer_id = parse_issuer_id(&issuer_id_str)?;
    let offer_id = parse_offer_id(&offer_id_str)?;

    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;

    require_issuer_owned_by_tenant(&mut conn, &tenant_context.tenant_id, &issuer_id).await?;

    let offer = persistence::credential_offers::find_by_id(
        &mut conn,
        &tenant_context.tenant_id,
        &issuer_id,
        &offer_id,
    )
    .await?;

    Ok(Json(offer_to_response(offer, Utc::now())))
}

pub async fn cancel(
    State(state): State<AppState>,
    Path((issuer_id_str, offer_id_str)): Path<(String, String)>,
    tenant_context: TenantContext,
) -> Result<Json<GetCredentialOfferResponse>, ApiError> {
    tracing::debug!(
        tenant_id = %tenant_context.tenant_id,
        issuer_id = %issuer_id_str,
        offer_id = %offer_id_str,
        "credential offer cancel requested",
    );

    let issuer_id = parse_issuer_id(&issuer_id_str)?;
    let offer_id = parse_offer_id(&offer_id_str)?;

    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;

    require_issuer_owned_by_tenant(&mut conn, &tenant_context.tenant_id, &issuer_id).await?;

    let mut offer = persistence::credential_offers::find_by_id(
        &mut conn,
        &tenant_context.tenant_id,
        &issuer_id,
        &offer_id,
    )
    .await?;

    let now = Utc::now();

    match offer.state {
        CredentialOfferState::Cancelled => {
            // Idempotent: re-cancelling a cancelled offer returns the
            // existing record unchanged. The original cancelled_at
            // stamp is preserved.
        }
        CredentialOfferState::Pending => {
            offer.try_cancel(now)?;
            persistence::credential_offers::cancel(
                &mut conn,
                &tenant_context.tenant_id,
                &issuer_id,
                &offer_id,
                now,
            )
            .await?;
        }
        CredentialOfferState::Issued | CredentialOfferState::Expired => {
            // Expired is never written by this codebase but is part of the
            // enum; treat any non-Pending, non-Cancelled stored state as a
            // refusal to transition.
            return Err(ApiError::Conflict {
                details: format!("cannot cancel offer in state {}", offer.state.as_str()),
            });
        }
    }

    Ok(Json(offer_to_response(offer, now)))
}

pub async fn status(
    State(state): State<AppState>,
    Path((issuer_id_str, offer_id_str)): Path<(String, String)>,
    tenant_context: TenantContext,
) -> Result<Json<OfferStatusResponse>, ApiError> {
    tracing::debug!(
        tenant_id = %tenant_context.tenant_id,
        issuer_id = %issuer_id_str,
        offer_id = %offer_id_str,
        "credential offer status requested",
    );

    let issuer_id = parse_issuer_id(&issuer_id_str)?;
    let offer_id = parse_offer_id(&offer_id_str)?;

    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;

    require_issuer_owned_by_tenant(&mut conn, &tenant_context.tenant_id, &issuer_id).await?;

    let offer = persistence::credential_offers::find_by_id(
        &mut conn,
        &tenant_context.tenant_id,
        &issuer_id,
        &offer_id,
    )
    .await?;

    Ok(Json(offer_to_status_response(&offer, Utc::now())))
}

fn parse_issuer_id(raw: &str) -> Result<IssuerId, ApiError> {
    IssuerId::from_bare(raw).map_err(|err| ApiError::InvalidInput {
        details: format!("issuer_id path parameter: {err}"),
    })
}

fn parse_offer_id(raw: &str) -> Result<CredentialOfferId, ApiError> {
    CredentialOfferId::from_bare(raw).map_err(|err| ApiError::InvalidInput {
        details: format!("offer_id path parameter: {err}"),
    })
}

fn offer_to_response(offer: CredentialOffer, now: DateTime<Utc>) -> GetCredentialOfferResponse {
    let observed = offer.observed_state(now);
    GetCredentialOfferResponse {
        id: offer.id.to_string(),
        issuer_id: offer.issuer_id.to_string(),
        vct: offer.vct,
        claims: offer.claims,
        state: observed.as_str().to_string(),
        expires_at: offer.expires_at,
        created_at: offer.created_at,
        issued_at: offer.issued_at,
        cancelled_at: offer.cancelled_at,
    }
}

fn offer_to_status_response(offer: &CredentialOffer, now: DateTime<Utc>) -> OfferStatusResponse {
    let observed = offer.observed_state(now);
    OfferStatusResponse {
        id: offer.id.to_string(),
        state: observed.as_str().to_string(),
        expires_at: offer.expires_at,
        issued_at: offer.issued_at,
        cancelled_at: offer.cancelled_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{PreAuthCode, TenantId};
    use serde_json::json;

    fn make_pending_offer(expires_in: Duration) -> CredentialOffer {
        let pre_auth_code_hash = PreAuthCode::generate().hash();
        CredentialOffer::new(
            TenantId::from_bare("4Mk7yK5pQR7sN3").unwrap(),
            IssuerId::from_bare("9hXq2vRtL8pK7f").unwrap(),
            "urn:communal:local-residence-id".to_string(),
            json!({}),
            pre_auth_code_hash,
            Utc::now() + expires_in,
        )
    }

    #[test]
    fn offer_to_response_pending_unexpired_reports_pending() {
        let offer = make_pending_offer(Duration::minutes(10));
        let response = offer_to_response(offer, Utc::now());
        assert_eq!(response.state, "pending");
        assert!(response.issued_at.is_none());
        assert!(response.cancelled_at.is_none());
    }

    #[test]
    fn offer_to_response_pending_past_expiry_reports_expired() {
        let offer = make_pending_offer(Duration::seconds(-1));
        let response = offer_to_response(offer, Utc::now());
        assert_eq!(response.state, "expired");
        assert!(response.cancelled_at.is_none());
    }

    #[test]
    fn offer_to_response_cancelled_carries_timestamp() {
        let mut offer = make_pending_offer(Duration::minutes(10));
        let cancelled_at = Utc::now();
        offer.try_cancel(cancelled_at).unwrap();
        let response = offer_to_response(offer, Utc::now());
        assert_eq!(response.state, "cancelled");
        assert_eq!(response.cancelled_at, Some(cancelled_at));
    }

    #[test]
    fn offer_to_response_cancelled_past_expiry_still_reports_cancelled() {
        // Once cancelled, the observed-state projection must not flip
        // back to expired even if expires_at has passed.
        let mut offer = make_pending_offer(Duration::seconds(-1));
        offer.try_cancel(Utc::now()).unwrap();
        let response = offer_to_response(offer, Utc::now());
        assert_eq!(response.state, "cancelled");
    }

    #[test]
    fn offer_to_status_response_pending_unexpired_reports_pending() {
        let offer = make_pending_offer(Duration::minutes(10));
        let response = offer_to_status_response(&offer, Utc::now());
        assert_eq!(response.state, "pending");
        assert!(response.issued_at.is_none());
        assert!(response.cancelled_at.is_none());
        assert_eq!(response.id, offer.id.to_string());
    }

    #[test]
    fn offer_to_status_response_pending_past_expiry_reports_expired() {
        let offer = make_pending_offer(Duration::seconds(-1));
        let response = offer_to_status_response(&offer, Utc::now());
        assert_eq!(response.state, "expired");
        assert!(response.issued_at.is_none());
        assert!(response.cancelled_at.is_none());
    }

    #[test]
    fn offer_to_status_response_cancelled_surfaces_timestamp() {
        let mut offer = make_pending_offer(Duration::minutes(10));
        let cancelled_at = Utc::now();
        offer.try_cancel(cancelled_at).unwrap();
        let response = offer_to_status_response(&offer, Utc::now());
        assert_eq!(response.state, "cancelled");
        assert_eq!(response.cancelled_at, Some(cancelled_at));
        assert!(response.issued_at.is_none());
    }

    #[test]
    fn offer_to_status_response_issued_surfaces_timestamp() {
        let mut offer = make_pending_offer(Duration::minutes(10));
        let issued_at = Utc::now();
        offer.try_issue(issued_at).unwrap();
        let response = offer_to_status_response(&offer, Utc::now());
        assert_eq!(response.state, "issued");
        assert_eq!(response.issued_at, Some(issued_at));
        assert!(response.cancelled_at.is_none());
    }

    #[test]
    fn parse_issuer_id_accepts_valid_base58() {
        assert!(parse_issuer_id("9hXq2vRtL8pK7f").is_ok());
    }

    #[test]
    fn parse_issuer_id_rejects_invalid_character() {
        let err = parse_issuer_id("notValid0").unwrap_err();
        assert!(matches!(err, ApiError::InvalidInput { .. }));
    }

    #[test]
    fn parse_offer_id_rejects_invalid_character() {
        let err = parse_offer_id("notValid0").unwrap_err();
        assert!(matches!(err, ApiError::InvalidInput { .. }));
    }

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
