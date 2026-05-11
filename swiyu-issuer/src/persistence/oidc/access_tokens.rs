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

use crate::domain::{AccessToken, AccessTokenHash, CredentialOfferId, IssuerId, TenantId};

use super::super::PersistenceError;
use super::super::helpers::map_database_error;

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
    .bind(token_hash)
    .bind(tenant_id)
    .bind(issuer_id)
    .bind(offer_id)
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
    sqlx::query_as::<_, AccessToken>(
        r#"
        SELECT token_hash, tenant_id, issuer_id, offer_id, expires_at
        FROM oidc_access_tokens
        WHERE token_hash = $1 AND expires_at > $2
        "#,
    )
    .bind(token_hash)
    .bind(now)
    .fetch_optional(conn)
    .await
    .map_err(PersistenceError::from)
}

/// Removes the access-token row for `token_hash`. Idempotent: a
/// missing row is `Ok(())`. Called from the credential endpoint's
/// success path — paired with
/// [`set_issued_state`][super::credential_offers::set_issued_state]
/// in the same transaction so the offer cannot end up `issued` while
/// the token is still around.
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
    .bind(token_hash)
    .execute(conn)
    .await?;
    Ok(())
}
