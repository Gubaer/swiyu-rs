pub mod api_token;

use secrecy::SecretString;
use sqlx::PgPool;

use crate::domain::TenantId;
use crate::domain::secret_encryption_engine::AnySecretEncryptionEngine;
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

/// Outcome of an `import_oauth_refresh_token` call. Distinguishes
/// "wrote a new value" from "the column was already populated and
/// `only_if_empty` skipped the write" so the caller can log the two
/// cases differently.
#[derive(Debug, PartialEq, Eq)]
pub enum SeedOutcome {
    Wrote,
    Skipped,
}

/// Writes a fresh refresh token into `tenants.oauth_refresh_token` for
/// the named tenant. Used by the `swiyu-issuer-cli tenant
/// import-oauth-refresh-token` operator command after the operator
/// pastes a new renewal token from the ePortal, and by the
/// `bootstrap-dev-tenant` compose service to seed a freshly migrated
/// dev database.
///
/// When `only_if_empty` is true and the tenant's existing
/// `oauth_refresh_token` is non-NULL, the call returns
/// `SeedOutcome::Skipped` and does not write — used by the dev-loop
/// auto-seed so a token the runtime has rotated never gets clobbered
/// by the bootstrap pass.
///
/// The check-then-write runs inside one transaction so a tenant
/// deletion or a competing rotation between the SELECT and the UPDATE
/// cannot leave the row in an unexpected state.
pub async fn import_oauth_refresh_token(
    pool: &PgPool,
    tenant_id: &TenantId,
    token: SecretString,
    only_if_empty: bool,
    engine: &AnySecretEncryptionEngine,
) -> Result<SeedOutcome, ImportOauthRefreshTokenError> {
    let mut tx = pool.begin().await?;

    let Some(tenant) = persistence::tenants::find_by_id(&mut tx, tenant_id).await? else {
        return Err(ImportOauthRefreshTokenError::TenantNotFound(
            tenant_id.bare().to_string(),
        ));
    };

    if only_if_empty && tenant.oauth_refresh_token.is_some() {
        return Ok(SeedOutcome::Skipped);
    }

    persistence::tenants::write_oauth_refresh_token(&mut tx, tenant_id, &token, engine).await?;
    tx.commit().await?;
    Ok(SeedOutcome::Wrote)
}

#[derive(Debug, thiserror::Error)]
pub enum SetOauthCredentialsError {
    #[error("tenant {0} not found")]
    TenantNotFound(String),
    #[error(transparent)]
    Persistence(#[from] PersistenceError),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
}

/// Writes `oauth_client_id` and `oauth_client_secret` for the named
/// tenant. Used by the `swiyu-issuer-cli tenant set-oauth-credentials`
/// operator command at onboarding (or on credential rotation at the
/// ePortal), and by the `bootstrap-dev-tenant` compose service to
/// seed the dev tenant from `.env`.
///
/// When `only_if_empty` is true and **both** existing columns are
/// non-NULL, the call returns `SeedOutcome::Skipped` and does not
/// write — used by the dev-loop auto-seed so a previously rotated
/// credential pair is never clobbered. If either column is NULL, the
/// pair is treated as empty and both are written: the all-or-none
/// rule avoids leaving the row in a partial state.
///
/// The check-then-write runs inside one transaction.
pub async fn set_oauth_credentials(
    pool: &PgPool,
    tenant_id: &TenantId,
    client_id: String,
    client_secret: SecretString,
    only_if_empty: bool,
    engine: &AnySecretEncryptionEngine,
) -> Result<SeedOutcome, SetOauthCredentialsError> {
    let mut tx = pool.begin().await?;

    let Some(tenant) = persistence::tenants::find_by_id(&mut tx, tenant_id).await? else {
        return Err(SetOauthCredentialsError::TenantNotFound(
            tenant_id.bare().to_string(),
        ));
    };

    if only_if_empty && tenant.oauth_client_id.is_some() && tenant.oauth_client_secret.is_some() {
        return Ok(SeedOutcome::Skipped);
    }

    persistence::tenants::write_oauth_client_credentials(
        &mut tx,
        tenant_id,
        &client_id,
        &client_secret,
        engine,
    )
    .await?;
    tx.commit().await?;
    Ok(SeedOutcome::Wrote)
}
