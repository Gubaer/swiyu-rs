//! Lifecycle handlers for issued credentials: suspend, unsuspend,
//! revoke. Synchronous; each handler runs the local DB write and the
//! status-list bit flip in one transaction and returns the updated
//! record. Status Registry publication is the publish worker's job
//! (phase 2); these handlers do not block on it.

use axum::Json;
use axum::extract::{Path, State};
use chrono::Utc;

use crate::domain::{IssuedCredential, IssuedCredentialId, StatusValue};
use crate::persistence;

use super::AppState;
use super::auth::TenantContext;
use super::dto::GetIssuedCredentialResponse;
use super::error::ApiError;

pub async fn suspend(
    State(state): State<AppState>,
    Path(credential_id_str): Path<String>,
    tenant_context: TenantContext,
) -> Result<Json<GetIssuedCredentialResponse>, ApiError> {
    tracing::debug!(
        tenant_id = %tenant_context.tenant_id,
        credential_id = %credential_id_str,
        "issued credential suspend requested",
    );
    let credential_id = parse_credential_id(&credential_id_str)?;
    let updated = run_lifecycle_op(
        &state,
        &tenant_context,
        &credential_id,
        |credential| credential.try_suspend().map_err(ApiError::from),
        StatusValue::Suspended,
    )
    .await?;
    // TODO(audit): record IssuedCredentialSuspended event.
    Ok(Json(credential_to_response(updated, Utc::now())))
}

pub async fn unsuspend(
    State(state): State<AppState>,
    Path(credential_id_str): Path<String>,
    tenant_context: TenantContext,
) -> Result<Json<GetIssuedCredentialResponse>, ApiError> {
    tracing::debug!(
        tenant_id = %tenant_context.tenant_id,
        credential_id = %credential_id_str,
        "issued credential unsuspend requested",
    );
    let credential_id = parse_credential_id(&credential_id_str)?;
    let updated = run_lifecycle_op(
        &state,
        &tenant_context,
        &credential_id,
        |credential| credential.try_unsuspend().map_err(ApiError::from),
        StatusValue::Valid,
    )
    .await?;
    // TODO(audit): record IssuedCredentialUnsuspended event.
    Ok(Json(credential_to_response(updated, Utc::now())))
}

pub async fn revoke(
    State(state): State<AppState>,
    Path(credential_id_str): Path<String>,
    tenant_context: TenantContext,
) -> Result<Json<GetIssuedCredentialResponse>, ApiError> {
    tracing::debug!(
        tenant_id = %tenant_context.tenant_id,
        credential_id = %credential_id_str,
        "issued credential revoke requested",
    );
    let credential_id = parse_credential_id(&credential_id_str)?;
    let updated = run_lifecycle_op(
        &state,
        &tenant_context,
        &credential_id,
        |credential| credential.try_revoke().map_err(ApiError::from),
        StatusValue::Revoked,
    )
    .await?;
    // TODO(audit): record IssuedCredentialRevoked event.
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
    credential_id: &IssuedCredentialId,
    apply_transition: F,
    bit_value: StatusValue,
) -> Result<IssuedCredential, ApiError>
where
    F: FnOnce(&mut IssuedCredential) -> Result<(), ApiError>,
{
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;

    let mut credential =
        persistence::issued_credentials::find(&mut tx, &tenant_context.tenant_id, credential_id)
            .await?
            .ok_or(ApiError::NotFound)?;

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
