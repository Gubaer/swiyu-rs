//! Single-use `c_nonce` values minted at `POST /token` and consumed
//! at `POST /credential`. Only the hash is persisted; the bare value
//! is returned to the wallet exactly once.
//!
//! No unique constraint on `offer_id`: multiple nonces may live for
//! one offer (the current spec uses one, future batch credential
//! issuance uses several).

use chrono::{DateTime, Utc};
use sqlx::Row;
use sqlx::postgres::PgConnection;

use crate::domain::{CredentialOfferId, IssuerId, NonceHash, TenantId};

use super::super::PersistenceError;
use super::super::helpers::map_database_error;

pub async fn insert(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    issuer_id: &IssuerId,
    offer_id: &CredentialOfferId,
    nonce_hash: &NonceHash,
    expires_at: DateTime<Utc>,
) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        INSERT INTO oidc_nonces
            (nonce_hash, tenant_id, issuer_id, offer_id, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(nonce_hash.as_str())
    .bind(tenant_id.bare())
    .bind(issuer_id.bare())
    .bind(offer_id.bare())
    .bind(expires_at)
    .execute(conn)
    .await
    .map_err(map_database_error)?;

    Ok(())
}

/// Atomically deletes the nonce row matching `nonce_hash` and
/// returns the `offer_id` it was bound to.
///
/// Returns `Ok(None)` if no row matches **or** the row had already
/// expired at `now`. The caller (the credential endpoint) treats
/// `None` as `invalid_proof` — same generic message regardless of
/// the underlying reason.
///
/// `DELETE … RETURNING` makes the consume atomic so a concurrent
/// second `/credential` request with the same nonce cannot
/// double-spend it.
pub async fn consume_by_hash(
    conn: &mut PgConnection,
    nonce_hash: &NonceHash,
    now: DateTime<Utc>,
) -> Result<Option<CredentialOfferId>, PersistenceError> {
    let row = sqlx::query(
        r#"
        DELETE FROM oidc_nonces
        WHERE nonce_hash = $1 AND expires_at > $2
        RETURNING offer_id
        "#,
    )
    .bind(nonce_hash.as_str())
    .bind(now)
    .fetch_optional(conn)
    .await?;

    match row {
        None => Ok(None),
        Some(row) => {
            let offer_id: String = row.try_get("offer_id")?;
            Ok(Some(CredentialOfferId::from_bare(offer_id).map_err(
                |err| PersistenceError::DataIntegrity {
                    details: err.to_string(),
                },
            )?))
        }
    }
}
