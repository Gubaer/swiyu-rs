//! Access tokens minted at `POST /token`.
//!
//! Only the hash is persisted; the bare value lives in the response
//! body once and is then in the wallet's hands. The `UNIQUE(offer_id)`
//! constraint on the table is the spec-mandated double-redemption
//! guard — a second `/token` request for the same offer races to
//! that constraint and loses, and the handler maps the conflict to
//! an OAuth `invalid_grant`.

use chrono::{DateTime, Utc};
use sqlx::postgres::PgConnection;

use crate::domain::{AccessTokenHash, CredentialOfferId, IssuerId, TenantId};

use super::super::PersistenceError;

pub async fn insert(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    issuer_id: &IssuerId,
    offer_id: &CredentialOfferId,
    token_hash: &AccessTokenHash,
    expires_at: DateTime<Utc>,
) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        INSERT INTO oidc_access_tokens
            (token_hash, tenant_id, issuer_id, offer_id, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(token_hash.as_str())
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
