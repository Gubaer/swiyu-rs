//! Access tokens minted at `POST /token`.
//!
//! Only the hash is persisted; the bare value lives in the response
//! body once and is then in the wallet's hands. The `UNIQUE(offer_id)`
//! constraint on the table is the spec-mandated double-redemption
//! guard — a second `/token` request for the same offer races to
//! that constraint and loses, and the handler maps the conflict to
//! an OAuth `invalid_grant`.

use chrono::{DateTime, Utc};
use sqlx::Row;
use sqlx::postgres::{PgConnection, PgRow};

use crate::domain::{AccessToken, AccessTokenHash, CredentialOfferId, IssuerId, TenantId};

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

/// Looks up an unexpired access token by its hash.
///
/// Returns `Ok(None)` if no row matches **or** the row's
/// `expires_at` has passed at `now`. Collapsing both failure modes
/// into `None` keeps the credential endpoint's `invalid_token`
/// response uniform — a wallet cannot tell "wrong token" from
/// "token expired" from this signature.
pub async fn find_valid_by_hash(
    conn: &mut PgConnection,
    token_hash: &AccessTokenHash,
    now: DateTime<Utc>,
) -> Result<Option<AccessToken>, PersistenceError> {
    let row = sqlx::query(
        r#"
        SELECT token_hash, tenant_id, issuer_id, offer_id, expires_at
        FROM oidc_access_tokens
        WHERE token_hash = $1 AND expires_at > $2
        "#,
    )
    .bind(token_hash.as_str())
    .bind(now)
    .fetch_optional(conn)
    .await?;

    row.map(|row| row_to_access_token(&row)).transpose()
}

/// Removes the access-token row for `token_hash`. Idempotent: a
/// missing row is `Ok(())`. Called from the credential endpoint's
/// success path — paired with `mark_issued` in the same
/// transaction so the offer cannot end up `issued` while the token
/// is still around.
pub async fn delete_by_hash(
    conn: &mut PgConnection,
    token_hash: &AccessTokenHash,
) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        DELETE FROM oidc_access_tokens
        WHERE token_hash = $1
        "#,
    )
    .bind(token_hash.as_str())
    .execute(conn)
    .await?;
    Ok(())
}

fn row_to_access_token(row: &PgRow) -> Result<AccessToken, PersistenceError> {
    let token_hash: String = row.try_get("token_hash")?;
    let tenant_id: String = row.try_get("tenant_id")?;
    let issuer_id: String = row.try_get("issuer_id")?;
    let offer_id: String = row.try_get("offer_id")?;
    let expires_at: DateTime<Utc> = row.try_get("expires_at")?;

    Ok(AccessToken {
        token_hash: AccessTokenHash::from_stored(token_hash),
        tenant_id: TenantId::from_bare(tenant_id).map_err(integrity_from)?,
        issuer_id: IssuerId::from_bare(issuer_id).map_err(integrity_from)?,
        offer_id: CredentialOfferId::from_bare(offer_id).map_err(integrity_from)?,
        expires_at,
    })
}

fn integrity_from(err: crate::domain::DomainError) -> PersistenceError {
    PersistenceError::DataIntegrity {
        details: err.to_string(),
    }
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
