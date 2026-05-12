//! Lifecycle handlers for issued credentials: suspend, unsuspend,
//! revoke. Synchronous; each handler runs the local DB write and the
//! status-list bit flip in one transaction and returns the updated
//! record. Status Registry publication is the publish worker's job
//! (phase 2); these handlers do not block on it.

use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::Utc;

use crate::domain::{
    IssuedCredential, IssuedCredentialId, IssuedCredentialState, IssuerId, StatusValue,
};
use crate::persistence;
use crate::persistence::issued_credentials::{ListFilters, ListPageQuery};

use super::AppState;
use super::auth::{TenantContext, acquire_pool_for_issuer, require_issuer_owned_by_tenant};
use super::cursor;
use super::dto::{
    GetIssuedCredentialResponse, ListIssuedCredentialsQuery, ListIssuedCredentialsResponse,
};
use super::error::ApiError;

/// `GET /api/v1/issuers/{issuer_id}/credentials/{credential_id}`
///
/// Returns HTTP 404 for both unknown credentials and cross-issuer access
/// (right tenant, wrong issuer) to prevent ownership probing.
pub async fn get(
    State(state): State<AppState>,
    Path((issuer_id_str, credential_id_str)): Path<(String, String)>,
    tenant_context: TenantContext,
) -> Result<Json<GetIssuedCredentialResponse>, ApiError> {
    tracing::debug!(
        tenant_id = %tenant_context.tenant_id,
        issuer_id = %issuer_id_str,
        credential_id = %credential_id_str,
        "issued credential fetch requested",
    );
    let issuer_id = super::parse_issuer_id(&issuer_id_str)?;
    let credential_id = parse_credential_id(&credential_id_str)?;
    let mut conn = acquire_pool_for_issuer(&state, &tenant_context.tenant_id, &issuer_id).await?;
    let credential =
        persistence::issued_credentials::find(&mut conn, &tenant_context.tenant_id, &credential_id)
            .await?
            .ok_or(ApiError::NotFound)?;
    if credential.issuer_id != issuer_id {
        // Cross-issuer access (right tenant, wrong issuer) collapses
        // to NotFound — same probe-prevention discipline as
        // cross-tenant access.
        return Err(ApiError::NotFound);
    }
    Ok(Json(credential_to_response(credential, Utc::now())))
}

/// `GET /api/v1/issuers/{issuer_id}/credentials`
///
/// Cursor-paginated list with optional `state` and `vct` filters.
pub async fn list(
    State(state): State<AppState>,
    Path(issuer_id_str): Path<String>,
    Query(query): Query<ListIssuedCredentialsQuery>,
    tenant_context: TenantContext,
) -> Result<Json<ListIssuedCredentialsResponse>, ApiError> {
    tracing::debug!(
        tenant_id = %tenant_context.tenant_id,
        issuer_id = %issuer_id_str,
        limit = ?query.limit,
        cursor_present = query.cursor.is_some(),
        state = ?query.state,
        vct = ?query.vct,
        "issued credential list requested",
    );
    let issuer_id = super::parse_issuer_id(&issuer_id_str)?;
    let limit = super::resolve_list_limit(query.limit)?;
    let state_filter = query.state.as_deref().map(parse_state_filter).transpose()?;
    let decoded_cursor = query
        .cursor
        .as_deref()
        .map(|raw| cursor::decode(raw, |bare| IssuedCredentialId::from_bare(bare).map(|_| ())))
        .transpose()?;

    let mut conn = acquire_pool_for_issuer(&state, &tenant_context.tenant_id, &issuer_id).await?;
    let page = persistence::issued_credentials::list(
        &mut conn,
        &tenant_context.tenant_id,
        ListPageQuery {
            filters: ListFilters {
                issuer_id: Some(issuer_id),
                state: state_filter,
                vct: query.vct,
            },
            cursor: decoded_cursor.map(|c| (c.timestamp, c.bare_id)),
            limit,
        },
    )
    .await?;

    let next_cursor = if page.has_more {
        page.items
            .last()
            .map(|c| cursor::encode(c.issued_at, c.id.bare()))
    } else {
        None
    };

    let now = Utc::now();
    let items = page
        .items
        .into_iter()
        .map(|c| credential_to_response(c, now))
        .collect();
    Ok(Json(ListIssuedCredentialsResponse { items, next_cursor }))
}

/// `POST /api/v1/issuers/{issuer_id}/credentials/{credential_id}/suspend`
///
/// Transitions the credential from `active` to `suspended`. Returns `409
/// Conflict` if the credential is not currently `active`.
pub async fn suspend(
    State(state): State<AppState>,
    Path((issuer_id_str, credential_id_str)): Path<(String, String)>,
    tenant_context: TenantContext,
) -> Result<Json<GetIssuedCredentialResponse>, ApiError> {
    tracing::debug!(
        tenant_id = %tenant_context.tenant_id,
        issuer_id = %issuer_id_str,
        credential_id = %credential_id_str,
        "issued credential suspend requested",
    );
    let issuer_id = super::parse_issuer_id(&issuer_id_str)?;
    let credential_id = parse_credential_id(&credential_id_str)?;
    let updated = run_lifecycle_op(
        &state,
        &tenant_context,
        &issuer_id,
        &credential_id,
        |credential| credential.try_suspend().map_err(ApiError::from),
        StatusValue::Suspended,
        "suspend",
    )
    .await?;
    Ok(Json(credential_to_response(updated, Utc::now())))
}

/// `POST /api/v1/issuers/{issuer_id}/credentials/{credential_id}/unsuspend`
///
/// Transitions the credential from `suspended` back to `active`. Returns `409
/// Conflict` if the credential is not currently `suspended`.
pub async fn unsuspend(
    State(state): State<AppState>,
    Path((issuer_id_str, credential_id_str)): Path<(String, String)>,
    tenant_context: TenantContext,
) -> Result<Json<GetIssuedCredentialResponse>, ApiError> {
    tracing::debug!(
        tenant_id = %tenant_context.tenant_id,
        issuer_id = %issuer_id_str,
        credential_id = %credential_id_str,
        "issued credential unsuspend requested",
    );
    let issuer_id = super::parse_issuer_id(&issuer_id_str)?;
    let credential_id = parse_credential_id(&credential_id_str)?;
    let updated = run_lifecycle_op(
        &state,
        &tenant_context,
        &issuer_id,
        &credential_id,
        |credential| credential.try_unsuspend().map_err(ApiError::from),
        StatusValue::Valid,
        "unsuspend",
    )
    .await?;
    Ok(Json(credential_to_response(updated, Utc::now())))
}

/// `POST /api/v1/issuers/{issuer_id}/credentials/{credential_id}/revoke`
///
/// Permanently revokes the credential from `active` or `suspended`. Terminal —
/// revocation cannot be undone. Returns `409 Conflict` if already `revoked`.
pub async fn revoke(
    State(state): State<AppState>,
    Path((issuer_id_str, credential_id_str)): Path<(String, String)>,
    tenant_context: TenantContext,
) -> Result<Json<GetIssuedCredentialResponse>, ApiError> {
    tracing::debug!(
        tenant_id = %tenant_context.tenant_id,
        issuer_id = %issuer_id_str,
        credential_id = %credential_id_str,
        "issued credential revoke requested",
    );
    let issuer_id = super::parse_issuer_id(&issuer_id_str)?;
    let credential_id = parse_credential_id(&credential_id_str)?;
    let updated = run_lifecycle_op(
        &state,
        &tenant_context,
        &issuer_id,
        &credential_id,
        |credential| credential.try_revoke().map_err(ApiError::from),
        StatusValue::Revoked,
        "revoke",
    )
    .await?;
    Ok(Json(credential_to_response(updated, Utc::now())))
}

/// Common shape for the three lifecycle handlers. Loads the
/// credential under a tenant-scoped lookup, applies the
/// caller-supplied state-transition check on the loaded domain
/// object, and (if allowed) persists the new state plus the
/// corresponding bit flip on the status list inside one transaction.
///
/// The transition-check closure takes `&mut IssuedCredential` so the
/// returned record reflects the new state without an extra read after
/// the UPDATE.
async fn run_lifecycle_op<F>(
    state: &AppState,
    tenant_context: &TenantContext,
    issuer_id: &IssuerId,
    credential_id: &IssuedCredentialId,
    apply_transition: F,
    bit_value: StatusValue,
    audit_action: &'static str,
) -> Result<IssuedCredential, ApiError>
where
    F: FnOnce(&mut IssuedCredential) -> Result<(), ApiError>,
{
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;

    // Tenant-scoped ownership of the issuer named in the URL. The
    // existing helper is reused here inside the transaction so the
    // check and the write share the same snapshot.
    require_issuer_owned_by_tenant(&mut tx, &tenant_context.tenant_id, issuer_id).await?;

    let mut credential =
        persistence::issued_credentials::find(&mut tx, &tenant_context.tenant_id, credential_id)
            .await?
            .ok_or(ApiError::NotFound)?;
    if &credential.issuer_id != issuer_id {
        // Cross-issuer access (right tenant, wrong issuer) collapses
        // to NotFound — same probe-prevention discipline as
        // cross-tenant access.
        return Err(ApiError::NotFound);
    }

    apply_transition(&mut credential)?;

    persistence::issued_credentials::set_state(
        &mut tx,
        &tenant_context.tenant_id,
        &credential.id,
        credential.state,
    )
    .await?;
    persistence::status_lists::write_bit(
        &mut tx,
        &credential.status_list_id,
        credential.status_list_index,
        bit_value,
    )
    .await?;
    // TODO(audit): record audit entry in this transaction —
    //   action       = audit_action ("suspend" / "unsuspend" / "revoke")
    //   tenant_id    = tenant_context.tenant_id
    //   issuer_id    = credential.issuer_id
    //   target       = credential.id
    //   details      = JSONB { "to": credential.state.as_str() }
    let _ = audit_action;

    tx.commit()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;

    Ok(credential)
}

fn parse_credential_id(raw: &str) -> Result<IssuedCredentialId, ApiError> {
    IssuedCredentialId::from_bare(raw).map_err(|err| ApiError::InvalidInput {
        details: format!("credential_id path parameter: {err}"),
    })
}

fn parse_state_filter(raw: &str) -> Result<IssuedCredentialState, ApiError> {
    IssuedCredentialState::parse(raw).map_err(|err| ApiError::InvalidInput {
        details: format!("state query parameter: {err}"),
    })
}

fn credential_to_response(
    credential: IssuedCredential,
    now: chrono::DateTime<Utc>,
) -> GetIssuedCredentialResponse {
    let expired = credential.is_expired_at(now);
    GetIssuedCredentialResponse {
        id: credential.id.bare().to_string(),
        issuer_id: credential.issuer_id.bare().to_string(),
        credential_offer_id: credential.credential_offer_id.bare().to_string(),
        vct: credential.vct,
        holder_key_jkt: credential.holder_key_jkt,
        status_list_id: credential.status_list_id.bare().to_string(),
        status_list_index: credential.status_list_index.value(),
        state: credential.state.as_str().to_string(),
        expired,
        issued_at: credential.issued_at,
        expires_at: credential.expires_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_credential_id_accepts_valid_base58() {
        assert!(parse_credential_id("9hXq2vRtL8pK7f").is_ok());
    }

    #[test]
    fn parse_credential_id_rejects_invalid_character() {
        let err = parse_credential_id("notValid0").unwrap_err();
        assert!(matches!(err, ApiError::InvalidInput { .. }));
    }

    #[test]
    fn parse_state_filter_accepts_known_values() {
        assert_eq!(
            parse_state_filter("active").unwrap(),
            IssuedCredentialState::Active
        );
        assert_eq!(
            parse_state_filter("suspended").unwrap(),
            IssuedCredentialState::Suspended
        );
        assert_eq!(
            parse_state_filter("revoked").unwrap(),
            IssuedCredentialState::Revoked
        );
    }

    #[test]
    fn parse_state_filter_rejects_expired() {
        // `expired` is a derived view, not a stored state; the list
        // filter operates on stored values only.
        assert!(parse_state_filter("expired").is_err());
    }

    #[test]
    fn credential_to_response_marks_unexpired_credential_as_not_expired() {
        use crate::domain::{
            CredentialOfferId, INTEGRITY_HASH_LEN, IssuerId, StatusListId, StatusListIndex,
            TenantId,
        };
        use chrono::Duration;

        let now = Utc::now();
        let credential = IssuedCredential::new(
            TenantId::generate(),
            IssuerId::generate(),
            CredentialOfferId::generate(),
            "vc-fixture".to_string(),
            "holder_jkt".to_string(),
            StatusListId::generate(),
            StatusListIndex::try_from(0u32).unwrap(),
            [0u8; INTEGRITY_HASH_LEN],
            now,
            now + Duration::days(30),
        );
        let response = credential_to_response(credential, now);
        assert!(!response.expired);
        assert_eq!(response.state, "active");
    }

    #[test]
    fn credential_to_response_marks_past_expires_at_as_expired() {
        use crate::domain::{
            CredentialOfferId, INTEGRITY_HASH_LEN, IssuerId, StatusListId, StatusListIndex,
            TenantId,
        };
        use chrono::Duration;

        let issued_at = Utc::now() - Duration::days(10);
        let credential = IssuedCredential::new(
            TenantId::generate(),
            IssuerId::generate(),
            CredentialOfferId::generate(),
            "vc-fixture".to_string(),
            "holder_jkt".to_string(),
            StatusListId::generate(),
            StatusListIndex::try_from(0u32).unwrap(),
            [0u8; INTEGRITY_HASH_LEN],
            issued_at,
            issued_at + Duration::days(1),
        );
        let response = credential_to_response(credential, Utc::now());
        assert!(response.expired);
    }
}
