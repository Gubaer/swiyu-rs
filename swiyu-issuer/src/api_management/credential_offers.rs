use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use chrono::{DateTime, Duration, Utc};

use crate::domain::{
    CredentialOffer, CredentialOfferId, CredentialOfferState, IssuerId, PreAuthCode,
};
use crate::persistence;
use crate::persistence::credential_offers::ListPageQuery;

use super::AppState;
use super::auth::{TenantContext, acquire_pool_for_issuer};
use super::dto::{
    CreateCredentialOfferRequest, CreateCredentialOfferResponse, GetCredentialOfferResponse,
    ListCredentialOffersQuery, ListCredentialOffersResponse, OfferStatusResponse,
};
use super::error::ApiError;

/// Lifetime applied to a credential offer when the caller omits
/// `expires_in_seconds` on create. Ten minutes balances "long enough
/// for the holder to scan the QR and finish wallet onboarding"
/// against "short enough that an unredeemed offer does not linger".
const DEFAULT_EXPIRES_IN_SECONDS: u32 = 600;

/// Lower bound on `expires_in_seconds`. Anything shorter than a
/// minute risks the offer expiring before the holder can complete
/// the redemption round-trip on a slow connection.
const MIN_EXPIRES_IN_SECONDS: u32 = 60;

/// Upper bound on `expires_in_seconds`. One hour caps how long a
/// pre-authorised code can sit redeemable; longer lifetimes are a
/// product decision rather than a default the API should grant.
const MAX_EXPIRES_IN_SECONDS: u32 = 3600;

/// `POST /api/v1/issuers/{issuer_id}/credential-offers`
///
/// Validates the VCT and claims against the schema loaded at startup, then
/// persists a new offer with a freshly generated pre-authorised code. Returns
/// `201 Created` with the bare pre-auth code and an OID4VCI deeplink the
/// caller can hand to the holder's wallet.
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

    let issuer_id = super::parse_issuer_id(&issuer_id_str)?;

    validate_claims(&state, &payload)?;
    let expires_in = resolve_expires_in(payload.expires_in_seconds)?;

    let mut conn = acquire_pool_for_issuer(&state, &tenant_context.tenant_id, &issuer_id).await?;

    let pre_auth_code = PreAuthCode::generate();
    let expires_at = Utc::now() + expires_in;

    let offer = CredentialOffer::new(
        tenant_context.tenant_id.clone(),
        issuer_id,
        payload.vct,
        payload.claims,
        pre_auth_code.clone(),
        expires_at,
    );

    persistence::credential_offers::insert(&mut conn, &offer).await?;

    let deeplink = build_offer_deeplink(&state.config.issuer_base_url, &offer.issuer_id, &offer.id);

    let response = CreateCredentialOfferResponse {
        id: offer.id.bare().to_string(),
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

fn build_offer_deeplink(
    issuer_base_url: &str,
    issuer_id: &IssuerId,
    offer_id: &CredentialOfferId,
) -> String {
    // issuer-oidc serves the wallet endpoint at
    // /i/{issuer_id}/credential-offer/{offer_id}, so the
    // credential_offer_uri must resolve there. Both binaries share
    // the same external ISSUER_BASE_URL via reverse proxy.
    let credential_offer_uri = format!(
        "{}/i/{}/credential-offer/{}",
        issuer_base_url.trim_end_matches('/'),
        issuer_id.bare(),
        offer_id.bare()
    );
    let encoded = urlencoding::encode(&credential_offer_uri);
    format!("openid-credential-offer://?credential_offer_uri={encoded}")
}

pub async fn get_offer(
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

    let issuer_id = super::parse_issuer_id(&issuer_id_str)?;
    let offer_id = parse_offer_id(&offer_id_str)?;

    let mut conn = acquire_pool_for_issuer(&state, &tenant_context.tenant_id, &issuer_id).await?;

    let offer = persistence::credential_offers::find_by_id(
        &mut conn,
        &tenant_context.tenant_id,
        &issuer_id,
        &offer_id,
    )
    .await?;

    Ok(Json(offer_to_response(offer, Utc::now())))
}

/// `POST /api/v1/issuers/{issuer_id}/credential-offers/{offer_id}/cancel`
///
/// Cancels a pending offer. Re-cancelling an already-cancelled offer is
/// idempotent. Cancelling an issued or expired offer returns `409 Conflict`.
/// On success the persistence layer NULLs the pre-auth code so the wallet
/// path can no longer redeem it.
pub async fn cancel_offer(
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

    let issuer_id = super::parse_issuer_id(&issuer_id_str)?;
    let offer_id = parse_offer_id(&offer_id_str)?;

    let mut conn = acquire_pool_for_issuer(&state, &tenant_context.tenant_id, &issuer_id).await?;

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
            // The cancel UPDATE also NULLs `pre_auth_code` so the
            // wallet path can no longer fetch the bare value.
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

/// `GET /api/v1/issuers/{issuer_id}/credential-offers/{offer_id}/status`
///
/// Lightweight polling endpoint: returns the observed state and lifecycle
/// timestamps without the full claims payload. Intended for callers that
/// only need to know whether the offer has been redeemed or has expired.
pub async fn get_offer_status(
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

    let issuer_id = super::parse_issuer_id(&issuer_id_str)?;
    let offer_id = parse_offer_id(&offer_id_str)?;

    let mut conn = acquire_pool_for_issuer(&state, &tenant_context.tenant_id, &issuer_id).await?;

    let offer = persistence::credential_offers::find_by_id(
        &mut conn,
        &tenant_context.tenant_id,
        &issuer_id,
        &offer_id,
    )
    .await?;

    Ok(Json(offer_to_status_response(&offer, Utc::now())))
}

/// `GET /api/v1/issuers/{issuer_id}/credential-offers`
///
/// Returns a cursor-paginated page of offers, optionally filtered by state.
/// Pagination is keyed on `(created_at, offer_id)`; pass the `next_cursor`
/// from the previous response to advance. Expired state is computed at query
/// time from `expires_at` — it is never written to the database.
pub async fn list_offers(
    State(state): State<AppState>,
    Path(issuer_id_str): Path<String>,
    Query(query): Query<ListCredentialOffersQuery>,
    tenant_context: TenantContext,
) -> Result<Json<ListCredentialOffersResponse>, ApiError> {
    tracing::debug!(
        tenant_id = %tenant_context.tenant_id,
        issuer_id = %issuer_id_str,
        limit = ?query.limit,
        cursor_present = query.cursor.is_some(),
        state = ?query.state,
        "credential offer list requested",
    );

    let issuer_id = super::parse_issuer_id(&issuer_id_str)?;
    let limit = super::resolve_list_limit(query.limit)?;
    let state_filter = parse_state_filter(query.state.as_deref())?;
    let decoded_cursor = query
        .cursor
        .as_deref()
        .map(|raw| {
            super::cursor::decode(raw, |bare| CredentialOfferId::from_bare(bare).map(|_| ()))
        })
        .transpose()?;

    let mut conn = acquire_pool_for_issuer(&state, &tenant_context.tenant_id, &issuer_id).await?;

    let now = Utc::now();
    let page = persistence::credential_offers::list(
        &mut conn,
        &tenant_context.tenant_id,
        &issuer_id,
        ListPageQuery {
            state_filter,
            cursor: decoded_cursor.map(|c| (c.timestamp, c.bare_id)),
            limit,
            now,
        },
    )
    .await?;

    let next_cursor = if page.has_more {
        page.items
            .last()
            .map(|offer| super::cursor::encode(offer.created_at, offer.id.bare()))
    } else {
        None
    };

    let items = page
        .items
        .into_iter()
        .map(|offer| offer_to_response(offer, now))
        .collect();

    Ok(Json(ListCredentialOffersResponse { items, next_cursor }))
}

fn parse_state_filter(raw: Option<&str>) -> Result<Option<CredentialOfferState>, ApiError> {
    match raw {
        None => Ok(None),
        Some(s) => CredentialOfferState::parse(s)
            .map(Some)
            .map_err(|err| ApiError::InvalidInput {
                details: format!("state query parameter: {err}"),
            }),
    }
}

fn parse_offer_id(raw: &str) -> Result<CredentialOfferId, ApiError> {
    CredentialOfferId::from_bare(raw).map_err(|err| ApiError::InvalidInput {
        details: format!("offer_id path parameter: {err}"),
    })
}

fn offer_to_response(offer: CredentialOffer, now: DateTime<Utc>) -> GetCredentialOfferResponse {
    let observed = offer.observed_state(now);
    GetCredentialOfferResponse {
        id: offer.id.bare().to_string(),
        issuer_id: offer.issuer_id.bare().to_string(),
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
        id: offer.id.bare().to_string(),
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
        let pre_auth_code = PreAuthCode::generate();
        CredentialOffer::new(
            TenantId::from_bare("4Mk7yK5pQR7sN3").unwrap(),
            IssuerId::from_bare("9hXq2vRtL8pK7f").unwrap(),
            "urn:communal:local-residence-id".to_string(),
            json!({}),
            pre_auth_code,
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
        assert_eq!(response.id, offer.id.bare());
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
        let issuer_id = IssuerId::from_bare("4Mk7yK5pQR7sN3").unwrap();
        let offer_id = CredentialOfferId::from_bare("9hXq2vRtL8pK7f").unwrap();
        let deeplink = build_offer_deeplink("https://issuer.example.com", &issuer_id, &offer_id);
        assert_eq!(
            deeplink,
            "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example.com%2Fi%2F4Mk7yK5pQR7sN3%2Fcredential-offer%2F9hXq2vRtL8pK7f"
        );
    }

    #[test]
    fn deeplink_strips_trailing_slash_from_base_url() {
        let issuer_id = IssuerId::from_bare("4Mk7yK5pQR7sN3").unwrap();
        let offer_id = CredentialOfferId::from_bare("9hXq2vRtL8pK7f").unwrap();
        let deeplink = build_offer_deeplink("https://issuer.example.com/", &issuer_id, &offer_id);
        assert!(deeplink.contains("com%2Fi%2F4Mk7yK5pQR7sN3%2Fcredential-offer%2F9hXq2vRtL8pK7f"));
        assert!(!deeplink.contains("com%2F%2Fi"));
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

    #[test]
    fn parse_state_filter_accepts_known_values() {
        assert_eq!(parse_state_filter(None).unwrap(), None);
        assert_eq!(
            parse_state_filter(Some("pending")).unwrap(),
            Some(CredentialOfferState::Pending)
        );
        assert_eq!(
            parse_state_filter(Some("issued")).unwrap(),
            Some(CredentialOfferState::Issued)
        );
        assert_eq!(
            parse_state_filter(Some("cancelled")).unwrap(),
            Some(CredentialOfferState::Cancelled)
        );
        assert_eq!(
            parse_state_filter(Some("expired")).unwrap(),
            Some(CredentialOfferState::Expired)
        );
    }

    #[test]
    fn parse_state_filter_rejects_unknown_value() {
        let err = parse_state_filter(Some("nope")).unwrap_err();
        assert!(matches!(err, ApiError::InvalidInput { .. }));
    }
}
