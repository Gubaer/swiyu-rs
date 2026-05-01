//! OIDC-side reads and writes on `credential_offers`.
//!
//! Lives in the `persistence::oidc` namespace separate from
//! `persistence::credential_offers` so the management binary cannot
//! accidentally call functions like `mark_issued`. The lookups here
//! serve the wallet flow, where the bare pre-auth code is the
//! lookup key rather than the offer id.

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::Row;
use sqlx::postgres::{PgConnection, PgRow};

use crate::domain::{
    CredentialOffer, CredentialOfferId, CredentialOfferState, IssuerId, PreAuthCode, TenantId,
};

use super::super::PersistenceError;
use super::super::helpers::integrity_from;

/// Looks up a credential offer by its bare pre-auth code, scoped to
/// `(tenant_id, issuer_id)` for defense in depth.
///
/// Returns `Ok(None)` if no row matches the bare code within the
/// scope — the handler maps this to OAuth `invalid_grant`. The
/// caller is responsible for the observed-state rule (rejecting
/// expired / non-pending offers); this function only enforces the
/// (bare-code, tenant, issuer) tuple match.
///
/// Note: post-redemption rows have `pre_auth_code = NULL`, so a
/// lookup with a presented `NULL` (which can't actually happen at
/// the wire — the form decoder rejects empty grants) would never
/// match, and a presented redeemed code matches no live row.
pub async fn find_by_pre_auth_code(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    issuer_id: &IssuerId,
    pre_auth_code: &PreAuthCode,
) -> Result<Option<CredentialOffer>, PersistenceError> {
    let row = sqlx::query(
        r#"
        SELECT id, tenant_id, issuer_id, vct, claims, state,
               pre_auth_code, expires_at, created_at,
               issued_at, cancelled_at
        FROM credential_offers
        WHERE pre_auth_code = $1
          AND tenant_id = $2
          AND issuer_id = $3
        "#,
    )
    .bind(pre_auth_code.as_str())
    .bind(tenant_id.bare())
    .bind(issuer_id.bare())
    .fetch_optional(conn)
    .await?;

    row.map(|row| row_to_offer(&row)).transpose()
}

/// Persists a `Pending` → `Issued` transition for the named offer.
///
/// In the same UPDATE: `pre_auth_code` is set to `NULL` so the bare
/// code can't be re-fetched after issuance.
///
/// Caller is responsible for loading the offer, running the domain
/// state-machine guard (`CredentialOffer::try_issue`), and
/// supplying `issued_at`. The SQL `WHERE state = 'pending'` guard
/// is defence in depth: a concurrent cancel that happens between
/// the handler's load and write would leave 0 rows updated, which
/// surfaces as `PersistenceError::NotFound`. Lives in the
/// `persistence::oidc::credential_offers` namespace so the
/// management binary cannot accidentally invoke it.
pub async fn mark_issued(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    issuer_id: &IssuerId,
    offer_id: &CredentialOfferId,
    issued_at: DateTime<Utc>,
) -> Result<(), PersistenceError> {
    let result = sqlx::query(
        r#"
        UPDATE credential_offers
        SET state = 'issued',
            issued_at = $4,
            pre_auth_code = NULL
        WHERE id = $1 AND tenant_id = $2 AND issuer_id = $3
              AND state = 'pending'
        "#,
    )
    .bind(offer_id.bare())
    .bind(tenant_id.bare())
    .bind(issuer_id.bare())
    .bind(issued_at)
    .execute(conn)
    .await?;

    if result.rows_affected() == 0 {
        return Err(PersistenceError::NotFound);
    }
    Ok(())
}

fn row_to_offer(row: &PgRow) -> Result<CredentialOffer, PersistenceError> {
    let id: String = row.try_get("id")?;
    let tenant_id: String = row.try_get("tenant_id")?;
    let issuer_id: String = row.try_get("issuer_id")?;
    let vct: String = row.try_get("vct")?;
    let claims: Value = row.try_get("claims")?;
    let state_str: String = row.try_get("state")?;
    let pre_auth_code: Option<String> = row.try_get("pre_auth_code")?;
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
        pre_auth_code: pre_auth_code.map(PreAuthCode::from_stored),
        expires_at,
        created_at,
        issued_at,
        cancelled_at,
    })
}
