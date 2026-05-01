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
use super::auth::{TenantContext, acquire_for_issuer};
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

/// Page size applied to `GET .../credential-offers` when the caller
/// omits `limit`. Sized to fit a typical operator UI page without
/// forcing a follow-up request for small issuers.
const DEFAULT_LIST_LIMIT: u32 = 25;

/// Lower bound on `limit`. Zero would return an empty page with a
/// `next_cursor` that never advances, so the smallest legal page is
/// one row.
const MIN_LIST_LIMIT: u32 = 1;

/// Upper bound on `limit`. Caps per-request work against the
/// database and the JSON response size; clients that need more rows
/// must paginate.
const MAX_LIST_LIMIT: u32 = 100;

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

    let issuer_id = parse_issuer_id(&issuer_id_str)?;

    validate_claims(&state, &payload)?;
    let expires_in = resolve_expires_in(payload.expires_in_seconds)?;

    let mut conn = acquire_for_issuer(&state, &tenant_context.tenant_id, &issuer_id).await?;

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

fn build_offer_deeplink(
    issuer_base_url: &str,
    issuer_id: &IssuerId,
    offer_id: &CredentialOfferId,
) -> String {
    // The wallet path lives on the issuer-oidc binary at
    // /i/{issuer_id}/credential-offer/{offer_id} (see
    // `specs/impl_api_oidc.md`), so the credential_offer_uri must
    // resolve there. Both binaries serve under the same external
    // ISSUER_BASE_URL via reverse proxy.
    let credential_offer_uri = format!(
        "{}/i/{}/credential-offer/{}",
        issuer_base_url.trim_end_matches('/'),
        issuer_id.bare(),
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

    let mut conn = acquire_for_issuer(&state, &tenant_context.tenant_id, &issuer_id).await?;

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

    let mut conn = acquire_for_issuer(&state, &tenant_context.tenant_id, &issuer_id).await?;

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

    let mut conn = acquire_for_issuer(&state, &tenant_context.tenant_id, &issuer_id).await?;

    let offer = persistence::credential_offers::find_by_id(
        &mut conn,
        &tenant_context.tenant_id,
        &issuer_id,
        &offer_id,
    )
    .await?;

    Ok(Json(offer_to_status_response(&offer, Utc::now())))
}

pub async fn list(
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

    let issuer_id = parse_issuer_id(&issuer_id_str)?;
    let limit = resolve_list_limit(query.limit)?;
    let state_filter = parse_state_filter(query.state.as_deref())?;
    let cursor = query.cursor.as_deref().map(decode_cursor).transpose()?;

    let mut conn = acquire_for_issuer(&state, &tenant_context.tenant_id, &issuer_id).await?;

    let now = Utc::now();
    let page = persistence::credential_offers::list(
        &mut conn,
        &tenant_context.tenant_id,
        &issuer_id,
        ListPageQuery {
            state_filter,
            cursor: cursor.map(|c| (c.created_at, c.offer_id)),
            limit,
            now,
        },
    )
    .await?;

    let next_cursor = if page.has_more {
        page.items
            .last()
            .map(|offer| encode_cursor(offer.created_at, offer.id.bare()))
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

fn resolve_list_limit(requested: Option<u32>) -> Result<u32, ApiError> {
    let limit = requested.unwrap_or(DEFAULT_LIST_LIMIT);
    if !(MIN_LIST_LIMIT..=MAX_LIST_LIMIT).contains(&limit) {
        return Err(ApiError::InvalidInput {
            details: format!(
                "limit must be between {MIN_LIST_LIMIT} and {MAX_LIST_LIMIT}, got {limit}"
            ),
        });
    }
    Ok(limit)
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

#[derive(Debug)]
struct DecodedCursor {
    created_at: DateTime<Utc>,
    offer_id: String,
}

fn encode_cursor(created_at: DateTime<Utc>, offer_id_bare: &str) -> String {
    let raw = format!("{}|{}", created_at.to_rfc3339(), offer_id_bare);
    bs58::encode(raw.as_bytes()).into_string()
}

fn decode_cursor(raw: &str) -> Result<DecodedCursor, ApiError> {
    let bytes = bs58::decode(raw).into_vec().map_err(|_| invalid_cursor())?;
    let text = String::from_utf8(bytes).map_err(|_| invalid_cursor())?;
    let (ts, id) = text.split_once('|').ok_or_else(invalid_cursor)?;
    let created_at = DateTime::parse_from_rfc3339(ts)
        .map_err(|_| invalid_cursor())?
        .with_timezone(&Utc);
    // Reject anything we did not emit ourselves; the bare id was generated
    // by the same validator on the way out.
    CredentialOfferId::from_bare(id).map_err(|_| invalid_cursor())?;
    Ok(DecodedCursor {
        created_at,
        offer_id: id.to_string(),
    })
}

fn invalid_cursor() -> ApiError {
    ApiError::InvalidInput {
        details: "cursor query parameter: malformed or not issued by this server".to_string(),
    }
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
    fn resolve_list_limit_uses_default_when_unset() {
        assert_eq!(resolve_list_limit(None).unwrap(), DEFAULT_LIST_LIMIT);
    }

    #[test]
    fn resolve_list_limit_accepts_value_in_range() {
        assert_eq!(resolve_list_limit(Some(50)).unwrap(), 50);
        assert_eq!(
            resolve_list_limit(Some(MIN_LIST_LIMIT)).unwrap(),
            MIN_LIST_LIMIT
        );
        assert_eq!(
            resolve_list_limit(Some(MAX_LIST_LIMIT)).unwrap(),
            MAX_LIST_LIMIT
        );
    }

    #[test]
    fn resolve_list_limit_rejects_zero() {
        assert!(resolve_list_limit(Some(0)).is_err());
    }

    #[test]
    fn resolve_list_limit_rejects_above_max() {
        assert!(resolve_list_limit(Some(MAX_LIST_LIMIT + 1)).is_err());
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

    #[test]
    fn cursor_round_trips() {
        let created_at = DateTime::parse_from_rfc3339("2026-05-01T12:34:56.789Z")
            .unwrap()
            .with_timezone(&Utc);
        let bare_id = "9hXq2vRtL8pK7f";
        let encoded = encode_cursor(created_at, bare_id);
        let decoded = decode_cursor(&encoded).unwrap();
        assert_eq!(decoded.created_at, created_at);
        assert_eq!(decoded.offer_id, bare_id);
    }

    #[test]
    fn decode_cursor_rejects_garbage_base58() {
        // '0' is outside the bs58 alphabet.
        let err = decode_cursor("0000").unwrap_err();
        assert!(matches!(err, ApiError::InvalidInput { .. }));
    }

    #[test]
    fn decode_cursor_rejects_non_utf8_payload() {
        // Valid base58 of bytes that are not valid UTF-8.
        let encoded = bs58::encode([0xff, 0xfe, 0xfd]).into_string();
        let err = decode_cursor(&encoded).unwrap_err();
        assert!(matches!(err, ApiError::InvalidInput { .. }));
    }

    #[test]
    fn decode_cursor_rejects_missing_separator() {
        let encoded = bs58::encode(b"no-separator-here").into_string();
        let err = decode_cursor(&encoded).unwrap_err();
        assert!(matches!(err, ApiError::InvalidInput { .. }));
    }

    #[test]
    fn decode_cursor_rejects_bad_timestamp() {
        let encoded = bs58::encode(b"not-a-timestamp|9hXq2vRtL8pK7f").into_string();
        let err = decode_cursor(&encoded).unwrap_err();
        assert!(matches!(err, ApiError::InvalidInput { .. }));
    }

    #[test]
    fn decode_cursor_rejects_bad_offer_id() {
        // 'O' is excluded from the base58 alphabet, so the offer id is invalid.
        let encoded = bs58::encode(b"2026-05-01T12:34:56+00:00|notValOd").into_string();
        let err = decode_cursor(&encoded).unwrap_err();
        assert!(matches!(err, ApiError::InvalidInput { .. }));
    }
}
