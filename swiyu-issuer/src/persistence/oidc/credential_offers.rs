//! OIDC-side reads and writes on `credential_offers`.
//!
//! Lives in the `persistence::oidc` namespace separate from
//! `persistence::credential_offers` so the management binary cannot
//! accidentally call functions like the (future) `mark_issued`. The
//! lookups here serve the wallet flow, where the bare pre-auth code
//! is the lookup key rather than the offer id.

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::Row;
use sqlx::postgres::{PgConnection, PgRow};

use crate::domain::{
    CredentialOffer, CredentialOfferId, CredentialOfferState, IssuerId, PreAuthCodeHash, TenantId,
};

use super::super::PersistenceError;

/// Looks up a credential offer by its pre-auth code hash, scoped to
/// `(tenant_id, issuer_id)` for defense in depth.
///
/// Returns `Ok(None)` if no row matches the hash within the scope —
/// the handler maps this to OAuth `invalid_grant`. The caller is
/// responsible for the observed-state rule (rejecting expired /
/// non-pending offers); this function only enforces the (hash,
/// tenant, issuer) tuple match.
pub async fn find_by_pre_auth_code_hash(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    issuer_id: &IssuerId,
    pre_auth_code_hash: &PreAuthCodeHash,
) -> Result<Option<CredentialOffer>, PersistenceError> {
    let row = sqlx::query(
        r#"
        SELECT id, tenant_id, issuer_id, vct, claims, state,
               pre_auth_code_hash, expires_at, created_at,
               issued_at, cancelled_at
        FROM credential_offers
        WHERE pre_auth_code_hash = $1
          AND tenant_id = $2
          AND issuer_id = $3
        "#,
    )
    .bind(pre_auth_code_hash.as_str())
    .bind(tenant_id.bare())
    .bind(issuer_id.bare())
    .fetch_optional(conn)
    .await?;

    row.map(|row| row_to_offer(&row)).transpose()
}

fn row_to_offer(row: &PgRow) -> Result<CredentialOffer, PersistenceError> {
    let id: String = row.try_get("id")?;
    let tenant_id: String = row.try_get("tenant_id")?;
    let issuer_id: String = row.try_get("issuer_id")?;
    let vct: String = row.try_get("vct")?;
    let claims: Value = row.try_get("claims")?;
    let state_str: String = row.try_get("state")?;
    let pre_auth_code_hash: String = row.try_get("pre_auth_code_hash")?;
    let expires_at: DateTime<Utc> = row.try_get("expires_at")?;
    let created_at: DateTime<Utc> = row.try_get("created_at")?;
    let issued_at: Option<DateTime<Utc>> = row.try_get("issued_at")?;
    let cancelled_at: Option<DateTime<Utc>> = row.try_get("cancelled_at")?;

    Ok(CredentialOffer {
        id: CredentialOfferId::from_bare(id).map_err(integrity_from)?,
        tenant_id: TenantId::from_bare(tenant_id).map_err(integrity_from)?,
        issuer_id: IssuerId::from_bare(issuer_id).map_err(integrity_from)?,
        vct,
        claims,
        state: CredentialOfferState::parse(&state_str).map_err(integrity_from)?,
        pre_auth_code_hash: PreAuthCodeHash::from_stored(pre_auth_code_hash),
        expires_at,
        created_at,
        issued_at,
        cancelled_at,
    })
}

fn integrity_from(err: crate::domain::DomainError) -> PersistenceError {
    PersistenceError::DataIntegrity {
        details: err.to_string(),
    }
}
