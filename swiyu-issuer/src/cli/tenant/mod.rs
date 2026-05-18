pub mod api_token;

use chrono::{Duration, Utc};
use secrecy::SecretString;
use sqlx::PgPool;
use std::time::{Duration as StdDuration, Instant};
use uuid::Uuid;

use crate::domain::secret_encryption_engine::AnySecretEncryptionEngine;
use crate::domain::{
    CredentialType, IssuerCredentialTypeAssignment, IssuerId, IssuerState, OperationTask,
    RevocationMode, TaskId, TaskState, TaskType, TenantId,
};
use crate::persistence::credential_types::StructuredUpdate;
use crate::persistence::issuers::ListPageQuery as IssuersListPageQuery;
use crate::persistence::tenants::UpdateOutcome;
use crate::persistence::{self, PersistenceError};

// `vct` value of the auto-seeded dev credential type. The dummy
// URI scheme makes it obvious in any wire trace that the row is a
// dev placeholder, not a real credential type.
const DEV_DUMMY_VCT: &str = "urn:dummy:dummy-credential";
const DEV_DUMMY_INTERNAL_DESCRIPTION: &str =
    "Auto-seeded dummy credential type for local development";

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
    #[error("env var {0} is not a valid integer: {1}")]
    InvalidInt(&'static str, String),
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

    seed_dev_credential_type_and_assignments(pool, &tenant_id, force).await?;

    Ok(tenant_id)
}

/// Seeds the dummy credential type and assigns it to every active
/// issuer the dev tenant currently owns. Idempotent without `force`
/// (existing row is left untouched); with `force = true` the row's
/// structured fields are rewritten and all three blob columns are
/// re-uploaded so a contributor who tweaked the row locally can
/// reset it to the dummy defaults.
///
/// Issuer creation is not part of this flow — when the dev tenant
/// has no issuers yet, the credential type is still seeded but no
/// assignment row is written. The next bootstrap run (after the
/// contributor creates an issuer via the management API) picks up
/// the new issuer and inserts the assignment row idempotently.
pub async fn seed_dev_credential_type_and_assignments(
    pool: &PgPool,
    tenant_id: &TenantId,
    force: bool,
) -> Result<(), BootstrapDevError> {
    let mut tx = pool.begin().await?;

    let existing =
        persistence::credential_types::find_by_vct_for_tenant(&mut tx, tenant_id, DEV_DUMMY_VCT)
            .await?;

    let credential_type_id = match (existing, force) {
        (Some(row), false) => {
            tracing::info!(
                credential_type_id = %row.id,
                "dev credential type already exists; skipping (pass --force to overwrite)",
            );
            row.id
        }
        (Some(row), true) => {
            persistence::credential_types::update_structured(
                &mut tx,
                tenant_id,
                &row.id,
                StructuredUpdate {
                    internal_description: Some(DEV_DUMMY_INTERNAL_DESCRIPTION),
                    default_validity_duration: Some(Duration::days(365)),
                    revocation_mode: Some(RevocationMode::RevocableAndSuspendable),
                    ..Default::default()
                },
            )
            .await?;
            let schema = dev_dummy_claim_schema();
            persistence::credential_types::update_blob_schema(&mut tx, tenant_id, &row.id, &schema)
                .await?;
            persistence::credential_types::update_blob_display(
                &mut tx,
                tenant_id,
                &row.id,
                &dev_dummy_display(),
            )
            .await?;
            persistence::credential_types::update_blob_claims(
                &mut tx,
                tenant_id,
                &row.id,
                &dev_dummy_claims(),
            )
            .await?;
            tracing::info!(
                credential_type_id = %row.id,
                "dev credential type rewritten under --force",
            );
            row.id
        }
        (None, _) => {
            let credential_type = CredentialType::new(
                tenant_id.clone(),
                DEV_DUMMY_VCT.to_string(),
                dev_dummy_display(),
                Some(DEV_DUMMY_INTERNAL_DESCRIPTION.to_string()),
                dev_dummy_claim_schema(),
                dev_dummy_claims(),
                Duration::days(365),
                RevocationMode::RevocableAndSuspendable,
            );
            persistence::credential_types::insert(&mut tx, &credential_type).await?;
            tracing::info!(
                credential_type_id = %credential_type.id,
                "dev credential type seeded",
            );
            credential_type.id
        }
    };

    let issuers = persistence::issuers::list(
        &mut tx,
        tenant_id,
        IssuersListPageQuery {
            cursor: None,
            limit: 100,
        },
    )
    .await?;

    if issuers.items.is_empty() {
        tracing::warn!(
            "dev tenant has no issuers; credential type seeded but no assignment row written",
        );
    }

    for issuer in issuers.items {
        let assignment = IssuerCredentialTypeAssignment::new(
            issuer.id.clone(),
            credential_type_id.clone(),
            tenant_id.clone(),
        );
        persistence::issuer_credential_types::assign(&mut tx, &assignment).await?;
    }

    tx.commit().await?;
    Ok(())
}

// Bundled artefacts for the dev-seeded dummy credential type. Each
// of the three blob columns the row carries (`claim_schema`,
// `display`, `claims`) has its own file under
// `swiyu-issuer/schemas/` so an operator can inspect or copy the
// contracts without reading Rust. The same files are consumed by
// the in-crate `test_support` fixture — keeps the seed shape and
// the test-time fixtures in lock-step.
const DEV_DUMMY_CLAIM_SCHEMA_JSON: &str =
    include_str!("../../../schemas/urn_dummy_dummy-credential.schema.json");
const DEV_DUMMY_DISPLAY_JSON: &str =
    include_str!("../../../schemas/urn_dummy_dummy-credential.display.json");
const DEV_DUMMY_CLAIMS_JSON: &str =
    include_str!("../../../schemas/urn_dummy_dummy-credential.claims.json");

fn dev_dummy_claim_schema() -> serde_json::Value {
    serde_json::from_str(DEV_DUMMY_CLAIM_SCHEMA_JSON)
        .expect("bundled dev dummy claim schema must be valid JSON")
}

fn dev_dummy_display() -> serde_json::Value {
    serde_json::from_str(DEV_DUMMY_DISPLAY_JSON)
        .expect("bundled dev dummy display must be valid JSON")
}

fn dev_dummy_claims() -> serde_json::Value {
    serde_json::from_str(DEV_DUMMY_CLAIMS_JSON)
        .expect("bundled dev dummy claims must be valid JSON")
}

/// Default poll cadence the production CLI uses when watching the
/// CreateIssuer task in [`ensure_dev_issuer_from_env`]. Set to 1s so
/// the bootstrap container does not hammer Postgres but still lands
/// the assignment row promptly once the worker finishes the saga.
const DEFAULT_ENSURE_DEV_ISSUER_POLL_INTERVAL_SECS: u64 = 1;

/// Default ceiling on how long [`ensure_dev_issuer_from_env`] waits
/// for the saga to terminate before giving up. 300s comfortably
/// covers the worst-case identifier-registry + status-registry
/// round-trip without leaving the bootstrap container hanging on a
/// stuck task.
const DEFAULT_ENSURE_DEV_ISSUER_TIMEOUT_SECS: u64 = 300;

/// Inputs to [`ensure_dev_issuer_from_env`]. Decoupled from env
/// parsing so tests can drive the function with small `poll_interval`
/// / `timeout` values without mutating the process environment.
#[derive(Debug)]
pub struct EnsureDevIssuerArgs {
    pub partner_id: Uuid,
    pub poll_interval: StdDuration,
    pub timeout: StdDuration,
}

/// What [`ensure_dev_issuer_from_env`] actually did.
#[derive(Debug)]
pub enum EnsureDevIssuerOutcome {
    /// Tenant already had at least one Active issuer; no provisioning
    /// performed. The credential-type seed is re-run defensively so a
    /// missing assignment row from an earlier partial run is repaired.
    AlreadyActive { issuer_id: IssuerId },
    /// Tenant had issuers but they were all Deactivated; no
    /// provisioning performed (per the dev-bootstrap design: a
    /// deactivated-only tenant is a deliberate state, recreate the
    /// DB if you want a fresh issuer). The credential-type seed is
    /// not re-run since there is no Active issuer to assign to.
    DeactivatedOnly,
    /// Saga ran to completion; new issuer is now provisioned and the
    /// credential-type seed has written the assignment row.
    Provisioned {
        issuer_id: IssuerId,
        task_id: TaskId,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum EnsureDevIssuerError {
    #[error("dev tenant with partner_id {partner_id} not found; run bootstrap-dev-from-env first")]
    TenantNotFound { partner_id: Uuid },
    #[error("create-issuer task {task_id} failed: {error_code:?} — {error_message:?}")]
    TaskFailed {
        task_id: TaskId,
        error_code: Option<String>,
        error_message: Option<String>,
    },
    #[error("create-issuer task {task_id} did not complete within {timeout_secs}s")]
    Timeout { task_id: TaskId, timeout_secs: u64 },
    #[error("create-issuer task {task_id} disappeared from operation_tasks while polling")]
    TaskVanished { task_id: TaskId },
    #[error(transparent)]
    Persistence(#[from] PersistenceError),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error(transparent)]
    Seed(#[from] BootstrapDevError),
}

/// Production passes `|k| std::env::var(k).ok()`; tests pass a
/// fixture closure so the process environment stays untouched.
///
/// `DEV_TENANT_PARTNER_ID` is required (same source of truth as
/// [`parse_dev_tenant_args`]). `DEV_BOOTSTRAP_TIMEOUT_SECS` is
/// optional with the [`DEFAULT_ENSURE_DEV_ISSUER_TIMEOUT_SECS`]
/// default. `poll_interval` is hardcoded to the production default
/// here; tests construct [`EnsureDevIssuerArgs`] directly when they
/// want a tighter loop.
pub fn parse_dev_issuer_args(
    get: impl Fn(&str) -> Option<String>,
) -> Result<EnsureDevIssuerArgs, DevTenantEnvError> {
    fn non_empty(value: Option<String>) -> Option<String> {
        value.filter(|s| !s.is_empty())
    }

    let partner_id_str = non_empty(get("DEV_TENANT_PARTNER_ID"))
        .ok_or(DevTenantEnvError::Missing("DEV_TENANT_PARTNER_ID"))?;
    let partner_id = partner_id_str
        .parse::<Uuid>()
        .map_err(|err| DevTenantEnvError::InvalidUuid("DEV_TENANT_PARTNER_ID", err.to_string()))?;

    let timeout_secs: u64 = match non_empty(get("DEV_BOOTSTRAP_TIMEOUT_SECS")) {
        Some(s) => s.parse().map_err(|err: std::num::ParseIntError| {
            DevTenantEnvError::InvalidInt("DEV_BOOTSTRAP_TIMEOUT_SECS", err.to_string())
        })?,
        None => DEFAULT_ENSURE_DEV_ISSUER_TIMEOUT_SECS,
    };

    Ok(EnsureDevIssuerArgs {
        partner_id,
        poll_interval: StdDuration::from_secs(DEFAULT_ENSURE_DEV_ISSUER_POLL_INTERVAL_SECS),
        timeout: StdDuration::from_secs(timeout_secs),
    })
}

/// Brings the dev tenant's issuer state to "one Active issuer +
/// dummy credential type assigned" by enqueueing the same
/// `CreateIssuer` operation_task `POST /api/v1/issuers` would
/// enqueue and waiting for the management binary's worker to drive
/// the saga to completion.
///
/// The caller (the `bootstrap-dev-issuer` compose service) must
/// ensure the management binary is healthy before invoking this; the
/// poll loop here does not start a worker.
///
/// # Outcomes
///
/// - [`AlreadyActive`][EnsureDevIssuerOutcome::AlreadyActive] — at
///   least one Active issuer already exists; the credential-type
///   seed is re-run defensively (writes the assignment row if a
///   previous bootstrap left it missing).
/// - [`DeactivatedOnly`][EnsureDevIssuerOutcome::DeactivatedOnly] —
///   every existing issuer is Deactivated; no provisioning is
///   performed and no warning surfaces as an error. Recreate the DB
///   if you want a fresh issuer.
/// - [`Provisioned`][EnsureDevIssuerOutcome::Provisioned] — a fresh
///   `CreateIssuer` task ran to completion; the credential-type
///   seed has written the assignment row.
pub async fn ensure_dev_issuer_from_env(
    pool: &PgPool,
    args: EnsureDevIssuerArgs,
) -> Result<EnsureDevIssuerOutcome, EnsureDevIssuerError> {
    let mut conn = pool.acquire().await?;

    let tenant = persistence::tenants::find_by_partner_id(&mut conn, args.partner_id)
        .await?
        .ok_or(EnsureDevIssuerError::TenantNotFound {
            partner_id: args.partner_id,
        })?;
    let tenant_id = tenant.id.clone();

    let issuers = persistence::issuers::list(
        &mut conn,
        &tenant_id,
        IssuersListPageQuery {
            cursor: None,
            limit: 100,
        },
    )
    .await?;
    let first_active = issuers
        .items
        .iter()
        .find(|i| i.state == Some(IssuerState::Active))
        .cloned();
    let has_deactivated = issuers
        .items
        .iter()
        .any(|i| i.state == Some(IssuerState::Deactivated));
    drop(conn);

    if let Some(issuer) = first_active {
        tracing::info!(
            tenant_id = %tenant_id,
            issuer_id = %issuer.id,
            "ensure-dev-issuer: tenant already has an Active issuer; re-running credential-type seed defensively",
        );
        seed_dev_credential_type_and_assignments(pool, &tenant_id, false).await?;
        return Ok(EnsureDevIssuerOutcome::AlreadyActive {
            issuer_id: issuer.id,
        });
    }

    if has_deactivated {
        tracing::warn!(
            tenant_id = %tenant_id,
            "ensure-dev-issuer: tenant has only Deactivated issuers; no provisioning performed (recreate the DB to start fresh)",
        );
        return Ok(EnsureDevIssuerOutcome::DeactivatedOnly);
    }

    let task = build_create_issuer_task(&tenant_id, tenant.display_name.as_deref());
    let task_id = task.id.clone();
    let issuer_id = task
        .result_issuer_id
        .clone()
        .expect("CreateIssuer task carries result_issuer_id");

    {
        let mut conn = pool.acquire().await?;
        persistence::operation_tasks::insert(&mut conn, &task).await?;
    }
    tracing::info!(
        tenant_id = %tenant_id,
        issuer_id = %issuer_id,
        task_id = %task_id,
        "ensure-dev-issuer: enqueued CreateIssuer task; waiting for the worker",
    );

    wait_for_task_terminal(pool, &tenant_id, &task_id, args.poll_interval, args.timeout).await?;

    seed_dev_credential_type_and_assignments(pool, &tenant_id, false).await?;

    Ok(EnsureDevIssuerOutcome::Provisioned { issuer_id, task_id })
}

/// Mirrors `api_management::issuers::create`'s task shape so the
/// worker treats the dev-bootstrap-enqueued task identically to one
/// posted via the API. The display name is derived from the tenant's
/// `display_name` (suffix " - dev issuer") and falls back to a fixed
/// "Dev Issuer" when the tenant row carries no name; description is
/// always empty for the dev bootstrap path.
fn build_create_issuer_task(
    tenant_id: &TenantId,
    tenant_display_name: Option<&str>,
) -> OperationTask {
    let issuer_id = IssuerId::generate();
    let task_id = TaskId::generate();
    let now = Utc::now();
    let display_name = tenant_display_name
        .map(|name| format!("{name} - dev issuer"))
        .unwrap_or_else(|| "Dev Issuer".to_string());
    OperationTask {
        id: task_id,
        tenant_id: tenant_id.clone(),
        task_type: TaskType::CreateIssuer,
        state: TaskState::Pending,
        step: None,
        attempts: 0,
        next_attempt_at: None,
        error_code: None,
        error_message: None,
        input: serde_json::json!({
            "description": "",
            "display_name": display_name,
        }),
        state_data: serde_json::json!({}),
        result_issuer_id: Some(issuer_id),
        created_at: now,
        updated_at: now,
        completed_at: None,
    }
}

/// Polls `operation_tasks.{task_id}` at `poll_interval` until its
/// `state` is terminal or `timeout` elapses. Returns `Ok(())` on
/// [`TaskState::Completed`]; surfaces [`TaskFailed`] /
/// [`Timeout`][EnsureDevIssuerError::Timeout] /
/// [`TaskVanished`][EnsureDevIssuerError::TaskVanished] otherwise.
///
/// [`TaskFailed`]: EnsureDevIssuerError::TaskFailed
async fn wait_for_task_terminal(
    pool: &PgPool,
    tenant_id: &TenantId,
    task_id: &TaskId,
    poll_interval: StdDuration,
    timeout: StdDuration,
) -> Result<(), EnsureDevIssuerError> {
    let start = Instant::now();
    loop {
        let task = {
            let mut conn = pool.acquire().await?;
            persistence::operation_tasks::find_by_id(&mut conn, tenant_id, task_id).await
        };
        let task = match task {
            Ok(task) => task,
            // The row vanished between our insert and now — the worker
            // hard-deletes nothing in the normal path, so this would
            // mean a manual DB intervention; surface it.
            Err(PersistenceError::NotFound) => {
                return Err(EnsureDevIssuerError::TaskVanished {
                    task_id: task_id.clone(),
                });
            }
            Err(other) => return Err(other.into()),
        };

        match task.state {
            TaskState::Completed => return Ok(()),
            TaskState::Failed => {
                return Err(EnsureDevIssuerError::TaskFailed {
                    task_id: task_id.clone(),
                    error_code: task.error_code,
                    error_message: task.error_message,
                });
            }
            TaskState::Pending | TaskState::InProgress => {
                if start.elapsed() >= timeout {
                    return Err(EnsureDevIssuerError::Timeout {
                        task_id: task_id.clone(),
                        timeout_secs: timeout.as_secs(),
                    });
                }
                tokio::time::sleep(poll_interval).await;
            }
        }
    }
}
