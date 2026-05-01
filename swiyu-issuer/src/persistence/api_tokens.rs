use chrono::{DateTime, Utc};
use sqlx::Row;
use sqlx::postgres::{PgConnection, PgRow};

use crate::domain::{ApiToken, ApiTokenHash, ApiTokenId, TenantId};

use super::PersistenceError;

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
    .bind(token.id.bare())
    .bind(token.tenant_id.bare())
    .bind(&token.name)
    .bind(token.token_hash.as_str())
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
    let row = sqlx::query(
        r#"
        SELECT id, tenant_id, name, token_hash,
               created_at, expires_at, revoked_at, last_used_at
        FROM api_tokens
        WHERE token_hash = $1
          AND revoked_at IS NULL
          AND (expires_at IS NULL OR expires_at > $2)
        "#,
    )
    .bind(token_hash.as_str())
    .bind(now)
    .fetch_optional(conn)
    .await?;

    row.map(|row| row_to_token(&row)).transpose()
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
    .bind(id.bare())
    .bind(now)
    .execute(conn)
    .await?;

    Ok(())
}

fn row_to_token(row: &PgRow) -> Result<ApiToken, PersistenceError> {
    let id: String = row.try_get("id")?;
    let tenant_id: String = row.try_get("tenant_id")?;
    let name: String = row.try_get("name")?;
    let token_hash: String = row.try_get("token_hash")?;
    let created_at: DateTime<Utc> = row.try_get("created_at")?;
    let expires_at: Option<DateTime<Utc>> = row.try_get("expires_at")?;
    let revoked_at: Option<DateTime<Utc>> = row.try_get("revoked_at")?;
    let last_used_at: Option<DateTime<Utc>> = row.try_get("last_used_at")?;

    Ok(ApiToken {
        id: ApiTokenId::from_bare(id).map_err(integrity_from)?,
        tenant_id: TenantId::from_bare(tenant_id).map_err(integrity_from)?,
        name,
        token_hash: ApiTokenHash::from_stored(token_hash),
        created_at,
        expires_at,
        revoked_at,
        last_used_at,
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
