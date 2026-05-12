pub mod api_token;

use secrecy::SecretString;
use sqlx::PgPool;
use uuid::Uuid;

use crate::domain::TenantId;
use crate::domain::secret_encryption_engine::AnySecretEncryptionEngine;
use crate::persistence::tenants::UpdateOutcome;
use crate::persistence::{self, PersistenceError};

#[derive(Debug, thiserror::Error)]
pub enum CreateTenantError {
    #[error("tenant {0} already exists")]
    AlreadyExists(String),
    #[error(transparent)]
    Persistence(#[from] PersistenceError),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
}

/// `tenant_id` is minted by the caller via [`generate`][TenantId::generate].
/// The OAuth2 columns and API tokens are not touched here; they land
/// via their own subcommands.
pub async fn create(
    pool: &PgPool,
    tenant_id: &TenantId,
    partner_id: Uuid,
    display_name: Option<String>,
    description: Option<String>,
) -> Result<(), CreateTenantError> {
    let mut tx = pool.begin().await?;
    match persistence::tenants::insert(
        &mut tx,
        tenant_id,
        partner_id,
        display_name.as_deref(),
        description.as_deref(),
    )
    .await
    {
        Ok(()) => {
            tx.commit().await?;
            Ok(())
        }
        Err(PersistenceError::UniqueViolation { .. }) => {
            Err(CreateTenantError::AlreadyExists(tenant_id.bare().into()))
        }
        Err(e) => Err(e.into()),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum UpdateTenantError {
    #[error("tenant {0} not found")]
    TenantNotFound(String),
    #[error(transparent)]
    Persistence(#[from] PersistenceError),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
}

/// A `None` field is left unchanged in the row, not set to NULL.
/// There is intentionally no way to NULL `display_name` or
/// `description` through this path until a real use case appears.
pub async fn update(
    pool: &PgPool,
    tenant_id: &TenantId,
    partner_id: Option<Uuid>,
    display_name: Option<String>,
    description: Option<String>,
) -> Result<(), UpdateTenantError> {
    let mut tx = pool.begin().await?;
    let outcome = persistence::tenants::update_metadata(
        &mut tx,
        tenant_id,
        partner_id,
        display_name.as_deref(),
        description.as_deref(),
    )
    .await?;
    match outcome {
        UpdateOutcome::Updated => {
            tx.commit().await?;
            Ok(())
        }
        UpdateOutcome::NotFound => Err(UpdateTenantError::TenantNotFound(tenant_id.bare().into())),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ImportOauthRefreshTokenError {
    #[error("tenant {0} not found")]
    TenantNotFound(String),
    #[error(transparent)]
    Persistence(#[from] PersistenceError),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
}

/// Reported by the seeding operations so callers can log the
/// `--only-if-empty` skip path differently from a real write.
#[derive(Debug, PartialEq, Eq)]
pub enum SeedOutcome {
    Wrote,
    Skipped,
}

/// When `only_if_empty` is true and `oauth_refresh_token` is already
/// non-NULL, the call returns [`Skipped`][SeedOutcome::Skipped] and
/// performs no write. The operator path omits the flag and overwrites
/// unconditionally.
///
/// The check-and-write runs inside one transaction so a tenant
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

/// When `only_if_empty` is true and **both** columns are already
/// non-NULL, the call returns [`Skipped`][SeedOutcome::Skipped] and
/// performs no write. If either column is NULL, the pair is treated
/// as empty and both columns are written: the all-or-none rule keeps
/// the row from ending up in a partial state.
///
/// The check-and-write runs inside one transaction.
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
