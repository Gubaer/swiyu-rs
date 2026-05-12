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

/// Decoupled from env-var parsing so tests can construct it directly
/// instead of mutating the process environment.
#[derive(Debug)]
pub struct BootstrapDevTenantArgs {
    pub partner_id: Uuid,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<SecretString>,
    pub refresh_token: Option<SecretString>,
}

#[derive(Debug, thiserror::Error)]
pub enum BootstrapDevError {
    #[error(transparent)]
    Persistence(#[from] PersistenceError),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum DevTenantEnvError {
    #[error("required env var {0} is unset or empty")]
    Missing(&'static str),
    #[error("env var {0} is not a valid UUID: {1}")]
    InvalidUuid(&'static str, String),
}

/// Production passes `|k| std::env::var(k).ok()`; tests pass a
/// fixture closure so the process environment stays untouched.
///
/// Unset and empty are treated identically — both mean "absent".
/// `DEV_TENANT_PARTNER_ID` is the one required value and must parse
/// as a UUID; everything else is optional.
pub fn parse_dev_tenant_args(
    get: impl Fn(&str) -> Option<String>,
) -> Result<BootstrapDevTenantArgs, DevTenantEnvError> {
    fn non_empty(value: Option<String>) -> Option<String> {
        value.filter(|s| !s.is_empty())
    }

    let partner_id_str = non_empty(get("DEV_TENANT_PARTNER_ID"))
        .ok_or(DevTenantEnvError::Missing("DEV_TENANT_PARTNER_ID"))?;
    let partner_id = partner_id_str
        .parse::<Uuid>()
        .map_err(|err| DevTenantEnvError::InvalidUuid("DEV_TENANT_PARTNER_ID", err.to_string()))?;

    Ok(BootstrapDevTenantArgs {
        partner_id,
        display_name: non_empty(get("DEV_TENANT_DISPLAY_NAME")),
        description: non_empty(get("DEV_TENANT_DESCRIPTION")),
        client_id: non_empty(get("DEV_TENANT_CLIENT_ID")),
        client_secret: non_empty(get("DEV_TENANT_CLIENT_SECRET")).map(SecretString::from),
        refresh_token: non_empty(get("DEV_TENANT_REFRESH_TOKEN")).map(SecretString::from),
    })
}

/// When the row does not yet exist, every supplied field is written
/// (oauth columns only for the values that are `Some`). When the row
/// already exists, `force` decides whether to overwrite:
///
/// - `force == true` syncs the whole row from `args`: `display_name`
///   and `description` are overwritten (always), and each oauth
///   column is overwritten when its corresponding `args` field is
///   `Some`.
/// - `force == false` leaves `display_name` and `description`
///   untouched and writes each oauth column only when it is currently
///   `NULL`. Runtime-rotated refresh tokens survive an idempotent
///   re-run.
pub async fn bootstrap_dev_from_env(
    pool: &PgPool,
    args: BootstrapDevTenantArgs,
    force: bool,
    engine: &AnySecretEncryptionEngine,
) -> Result<TenantId, BootstrapDevError> {
    let mut tx = pool.begin().await?;

    let tenant_id = match persistence::tenants::find_by_partner_id(&mut tx, args.partner_id).await?
    {
        None => {
            let new_id = TenantId::generate();
            persistence::tenants::insert(
                &mut tx,
                &new_id,
                args.partner_id,
                args.display_name.as_deref(),
                args.description.as_deref(),
            )
            .await?;
            if let (Some(client_id), Some(client_secret)) = (&args.client_id, &args.client_secret) {
                persistence::tenants::write_oauth_client_credentials(
                    &mut tx,
                    &new_id,
                    client_id,
                    client_secret,
                    engine,
                )
                .await?;
            }
            if let Some(refresh_token) = &args.refresh_token {
                persistence::tenants::write_oauth_refresh_token(
                    &mut tx,
                    &new_id,
                    refresh_token,
                    engine,
                )
                .await?;
            }
            new_id
        }
        Some(existing) => {
            let existing_id = existing.id.clone();
            if force {
                persistence::tenants::update_metadata(
                    &mut tx,
                    &existing_id,
                    None,
                    args.display_name.as_deref(),
                    args.description.as_deref(),
                )
                .await?;
                if let (Some(client_id), Some(client_secret)) =
                    (&args.client_id, &args.client_secret)
                {
                    persistence::tenants::write_oauth_client_credentials(
                        &mut tx,
                        &existing_id,
                        client_id,
                        client_secret,
                        engine,
                    )
                    .await?;
                }
                if let Some(refresh_token) = &args.refresh_token {
                    persistence::tenants::write_oauth_refresh_token(
                        &mut tx,
                        &existing_id,
                        refresh_token,
                        engine,
                    )
                    .await?;
                }
            } else {
                let client_columns_empty =
                    existing.oauth_client_id.is_none() && existing.oauth_client_secret.is_none();
                if client_columns_empty
                    && let (Some(client_id), Some(client_secret)) =
                        (&args.client_id, &args.client_secret)
                {
                    persistence::tenants::write_oauth_client_credentials(
                        &mut tx,
                        &existing_id,
                        client_id,
                        client_secret,
                        engine,
                    )
                    .await?;
                }
                if existing.oauth_refresh_token.is_none()
                    && let Some(refresh_token) = &args.refresh_token
                {
                    persistence::tenants::write_oauth_refresh_token(
                        &mut tx,
                        &existing_id,
                        refresh_token,
                        engine,
                    )
                    .await?;
                }
            }
            existing_id
        }
    };

    tx.commit().await?;
    Ok(tenant_id)
}
