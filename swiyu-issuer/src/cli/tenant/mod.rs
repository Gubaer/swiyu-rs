pub mod api_token;

use secrecy::SecretString;
use sqlx::PgPool;

use crate::domain::TenantId;
use crate::persistence::{self, PersistenceError};

#[derive(Debug, thiserror::Error)]
pub enum ImportOauthRefreshTokenError {
    #[error("tenant {0} not found")]
    TenantNotFound(String),
    #[error(transparent)]
    Persistence(#[from] PersistenceError),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
}

/// Writes a fresh refresh token into `tenants.oauth_refresh_token` for
/// the named tenant. Used by the `swiyu-issuer-cli tenant
/// import-oauth-refresh-token` operator command after the operator
/// pastes a new renewal token from the ePortal.
///
/// The check-then-write runs inside one transaction so a tenant deleted
/// between the lookup and the update cannot leave the row in an
/// unexpected state — the update would then fail with `NotFound` and
/// roll back the read.
pub async fn import_oauth_refresh_token(
    pool: &PgPool,
    tenant_id: &TenantId,
    token: SecretString,
) -> Result<(), ImportOauthRefreshTokenError> {
    let mut tx = pool.begin().await?;

    if persistence::tenants::find_by_id(&mut tx, tenant_id)
        .await?
        .is_none()
    {
        return Err(ImportOauthRefreshTokenError::TenantNotFound(
            tenant_id.bare().to_string(),
        ));
    }

    persistence::tenants::write_oauth_refresh_token(&mut tx, tenant_id, &token).await?;
    tx.commit().await?;
    Ok(())
}
