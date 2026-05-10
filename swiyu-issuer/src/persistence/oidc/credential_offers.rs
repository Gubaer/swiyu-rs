//! OIDC-side reads and writes on `credential_offers`.
//!
//! Lives in the `persistence::oidc` namespace separate from
//! `persistence::credential_offers` so the management binary cannot
//! accidentally call functions like [`set_issued_state`]. The lookups
//! here serve the wallet flow, where the bare pre-auth code is the
//! lookup key rather than the offer id.

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::Row;
use sqlx::postgres::{PgConnection, PgRow};

use crate::domain::{
    CredentialOffer, CredentialOfferId, CredentialOfferState, IssuerId, PreAuthCode, TenantId,
};

use super::super::PersistenceError;
use super::super::helpers::{integrity_from, map_database_error};

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

/// Returns the named offer while holding a row-level lock on it. The
/// caller is expected to be inside a transaction; the lock is
/// released when that transaction commits or rolls back.
///
/// Uses plain `FOR UPDATE` (no `SKIP LOCKED`): a single offer has at
/// most one issuance handler racing for it, so a second transaction
/// that wants the same row should block until the first completes
/// rather than skip. Pair with
/// [`try_issue`][CredentialOffer::try_issue] (to mutate the in-memory
/// aggregate) and [`set_issued_state`] (to persist) before committing
/// the transaction.
///
/// Returns [`NotFound`][PersistenceError::NotFound] if no row matches
/// the `(id, tenant_id, issuer_id)` triple. The handler treats that
/// as `invalid_token` because the access token references an offer
/// the issuer no longer owns.
pub async fn find_by_id_for_update(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    issuer_id: &IssuerId,
    offer_id: &CredentialOfferId,
) -> Result<CredentialOffer, PersistenceError> {
    let row = sqlx::query(
        r#"
        SELECT id, tenant_id, issuer_id, vct, claims, state,
               pre_auth_code, expires_at, created_at,
               issued_at, cancelled_at
        FROM credential_offers
        WHERE id = $1 AND tenant_id = $2 AND issuer_id = $3
        FOR UPDATE
        "#,
    )
    .bind(offer_id.bare())
    .bind(tenant_id.bare())
    .bind(issuer_id.bare())
    .fetch_optional(conn)
    .await?
    .ok_or(PersistenceError::NotFound)?;

    row_to_offer(&row)
}

/// Persists the post-[`try_issue`][CredentialOffer::try_issue]
/// columns of a [`CredentialOffer`]: `state`, `issued_at`, and
/// `pre_auth_code` (which the aggregate has cleared to `None`).
///
/// The caller controls the transaction; this helper does not commit.
/// Run inside the same transaction that called
/// [`find_by_id_for_update`] so the row remains locked until the
/// UPDATE commits. The aggregate is the sole source of truth for the
/// transition's validity (the `state = 'pending'` SQL guard is gone —
/// [`try_issue`][CredentialOffer::try_issue] enforces it in memory
/// before this is called); the `(id, tenant_id, issuer_id)` `WHERE`
/// triple stays as tenant scoping, not state enforcement. Lives in
/// the `persistence::oidc::credential_offers` namespace so the
/// management binary cannot accidentally invoke it.
pub async fn set_issued_state(
    conn: &mut PgConnection,
    offer: &CredentialOffer,
) -> Result<(), PersistenceError> {
    let result = sqlx::query(
        r#"
        UPDATE credential_offers
        SET state = $1,
            issued_at = $2,
            pre_auth_code = NULL
        WHERE id = $3 AND tenant_id = $4 AND issuer_id = $5
        "#,
    )
    .bind(offer.state.as_str())
    .bind(offer.issued_at)
    .bind(offer.id.bare())
    .bind(offer.tenant_id.bare())
    .bind(offer.issuer_id.bare())
    .execute(conn)
    .await
    .map_err(map_database_error)?;

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
        state: CredentialOfferState::try_from(state_str.as_str()).map_err(integrity_from)?,
        pre_auth_code: pre_auth_code.map(PreAuthCode::from_stored),
        expires_at,
        created_at,
        issued_at,
        cancelled_at,
    })
}
