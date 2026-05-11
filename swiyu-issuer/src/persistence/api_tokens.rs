use chrono::{DateTime, Utc};
use sqlx::postgres::PgConnection;

use crate::domain::{ApiToken, ApiTokenHash, ApiTokenId};

use super::PersistenceError;
use super::helpers::map_database_error;

pub async fn insert(conn: &mut PgConnection, token: &ApiToken) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        INSERT INTO api_tokens (
            id, tenant_id, name, token_hash,
            created_at, expires_at, revoked_at, last_used_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
    )
    .bind(&token.id)
    .bind(&token.tenant_id)
    .bind(&token.name)
    .bind(&token.token_hash)
    .bind(token.created_at)
    .bind(token.expires_at)
    .bind(token.revoked_at)
    .bind(token.last_used_at)
    .execute(conn)
    .await
    .map_err(map_database_error)?;

    Ok(())
}

/// Looks up an unrevoked, unexpired token by its hash.
///
/// Returns `Ok(None)` if no row matches **or** the row is revoked or
/// expired at `now`. Collapsing all three failure modes into `None`
/// keeps the auth extractor's 401 response uniform: callers cannot
/// distinguish "wrong token" from "revoked" from "expired" from this
/// signature, removing a leak vector.
pub async fn find_valid_by_hash(
    conn: &mut PgConnection,
    token_hash: &ApiTokenHash,
    now: DateTime<Utc>,
) -> Result<Option<ApiToken>, PersistenceError> {
    sqlx::query_as::<_, ApiToken>(
        r#"
        SELECT id, tenant_id, name, token_hash,
               created_at, expires_at, revoked_at, last_used_at
        FROM api_tokens
        WHERE token_hash = $1
          AND revoked_at IS NULL
          AND (expires_at IS NULL OR expires_at > $2)
        "#,
    )
    .bind(token_hash)
    .bind(now)
    .fetch_optional(conn)
    .await
    .map_err(PersistenceError::from)
}

/// Bumps `last_used_at` for the named token. The auth path calls
/// this after a successful lookup so the audit slice can correlate
/// recent activity. v0.1.2 writes inline (one extra UPDATE per
/// authenticated request); throttling lands when there is a real
/// signal of contention.
pub async fn mark_used(
    conn: &mut PgConnection,
    id: &ApiTokenId,
    now: DateTime<Utc>,
) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        UPDATE api_tokens
        SET last_used_at = $2
        WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(now)
    .execute(conn)
    .await?;

    Ok(())
}
