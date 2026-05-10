use chrono::{DateTime, Utc};
use sqlx::PgPool;

use crate::domain::{ApiToken, ApiTokenSecret, TenantId};
use crate::persistence::{self, PersistenceError};

#[derive(Debug, thiserror::Error)]
pub enum MintError {
    #[error(transparent)]
    Persistence(#[from] PersistenceError),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
}

/// Both halves of a freshly minted API token. The caller is expected
/// to print `secret.as_wire()` to the operator exactly once and then
/// drop it; only `token` (the persisted hash and metadata) survives
/// in storage.
pub struct Minted {
    pub secret: ApiTokenSecret,
    pub token: ApiToken,
}

/// Generates a new API token for the named tenant, persists its hash,
/// and returns both the secret (for one-time display) and the stored
/// row. The caller owns the I/O — this function does not print.
pub async fn mint(
    pool: &PgPool,
    tenant_id: TenantId,
    name: String,
    expires_at: Option<DateTime<Utc>>,
) -> Result<Minted, MintError> {
    let secret = ApiTokenSecret::generate();
    let token = ApiToken::new(tenant_id, name, secret.hash(), expires_at);

    let mut conn = pool.acquire().await?;
    persistence::api_tokens::insert(&mut conn, &token).await?;

    Ok(Minted { secret, token })
}
