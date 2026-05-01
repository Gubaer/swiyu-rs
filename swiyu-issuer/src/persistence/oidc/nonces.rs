//! Single-use `c_nonce` values minted at `POST /token` and consumed
//! at `POST /credential`. Only the hash is persisted; the bare value
//! is returned to the wallet exactly once.
//!
//! No unique constraint on `offer_id`: multiple nonces may live for
//! one offer (the current spec uses one, future batch credential
//! issuance uses several).

use chrono::{DateTime, Utc};
use sqlx::postgres::PgConnection;

use crate::domain::{CredentialOfferId, IssuerId, NonceHash, TenantId};

use super::super::PersistenceError;

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

fn map_database_error(err: sqlx::Error) -> PersistenceError {
    if let Some(db_err) = err.as_database_error() {
        // Postgres SQLSTATE 23505: unique_violation.
        if db_err.code().as_deref() == Some("23505") {
            let constraint = db_err.constraint().unwrap_or("unknown").to_string();
            return PersistenceError::UniqueViolation { what: constraint };
        }
    }
    PersistenceError::Db(err)
}
