//! Dispatch-loop runner for the operation-task saga. Defines the
//! [`Worker`] type and its `run` loop: a single `tokio::spawn`-ed
//! task that polls the `operation_tasks` table for runnable rows,
//! dispatches each to the per-task-type per-step executor, and
//! applies the resulting outcome through the persistence layer.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use sqlx::PgPool;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::domain::{
    DomainError, OperationTask, ProviderRegistry, SigningEngine, StepOutcome, TaskType,
};
use crate::persistence::{self, PersistenceError};

use super::BoxedRng;
use super::create_issuer::{
    CreateIssuerInput, CreateIssuerStateData, execute_allocate_did, execute_build_initial_didlog,
    execute_create_status_list_entry, execute_generate_keys, execute_persist_issuer,
    execute_provision_status_list, execute_publish_didlog as execute_create_publish_didlog,
};
use super::deactivate_issuer::{
    DeactivateIssuerInput, DeactivateIssuerStateData,
    build_deactivation_didlog::execute_build_deactivation_didlog,
    mark_deactivated::execute_mark_deactivated,
    publish_didlog::execute_publish_didlog as execute_deactivate_publish_didlog,
};
use super::outcome::apply as apply_outcome;
use super::registry_facades::{RegistryFacade, StatusRegistryFacade};
use super::rotate_keys::{
    RotateKeysInput, RotateKeysStateData, build_rotation_didlog::execute_build_rotation_didlog,
    generate_new_keys::execute_generate_new_keys,
    publish_didlog::execute_publish_didlog as execute_rotate_publish_didlog,
    swap_keys::execute_swap_keys,
};

#[derive(Debug, thiserror::Error)]
pub enum WorkerError {
    #[error(transparent)]
    Persistence(#[from] PersistenceError),
    #[error("decode: {0}")]
    Decode(String),
}

/// Default sleep between dispatch-loop polls when no task is runnable.
/// Tests override this via [`Worker::with_poll_interval`]; the
/// `issuer-mgmt` binary may also override from an env var at startup.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(1);

pub struct WorkerConfig {
    /// How long to sleep before re-polling when no task is runnable.
    pub poll_interval: Duration,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            poll_interval: DEFAULT_POLL_INTERVAL,
        }
    }
}

/// Operation-task worker for swiyu-issuer.
///
/// One `Worker` instance per process: construct it at startup with
/// the shared dependencies (Postgres pool, registry client, signing
/// engine), then `tokio::spawn(worker.run(shutdown))` to launch the
/// dispatch loop. The loop runs until the supplied
/// [`CancellationToken`] fires, at which point it finishes the
/// in-progress poll iteration and exits.
///
/// # Type Parameters
/// - `R`: identifier-registry facade implementing [`RegistryFacade`].
///   Production passes [`swiyu_registries::identifier::IdentifierRegistryClient`];
///   tests pass an in-memory mock.
/// - `S`: signing engine implementing [`SigningEngine`]. Production
///   passes [`crate::domain::DevSigningEngine`] or
///   [`crate::domain::VaultSigningEngine`]; tests pass an in-memory
///   mock.
/// - `C`: status-registry facade implementing
///   [`StatusRegistryFacade`]. Production passes
///   [`swiyu_registries::status::StatusRegistryClient`]; tests pass
///   an in-memory mock.
pub struct Worker<R, S, C> {
    pool: PgPool,
    registry: R,
    engine: S,
    status_registry: C,
    /// Per-tenant `TokenProvider` cache. Each protected registry call
    /// resolves the provider for `task.tenant_id` once per task and
    /// passes it (as `&AnyTokenProvider`) into the per-step executor.
    providers: Arc<ProviderRegistry>,
    /// Heap-allocated [`rand_core::RngCore`] so callers can inject a
    /// deterministic implementation in tests without making the
    /// whole struct generic over a fourth parameter.
    rng: BoxedRng,
    config: WorkerConfig,
}

impl<R, S, C> Worker<R, S, C>
where
    R: RegistryFacade + 'static,
    S: SigningEngine + 'static,
    C: StatusRegistryFacade + 'static,
{
    pub fn new(
        pool: PgPool,
        registry: R,
        engine: S,
        status_registry: C,
        providers: Arc<ProviderRegistry>,
        rng: BoxedRng,
    ) -> Self {
        Self {
            pool,
            registry,
            engine,
            status_registry,
            providers,
            rng,
            config: WorkerConfig::default(),
        }
    }

    pub fn with_poll_interval(mut self, poll_interval: Duration) -> Self {
        self.config.poll_interval = poll_interval;
        self
    }

    pub async fn run(mut self, shutdown: CancellationToken) {
        info!("worker started");
        loop {
            if shutdown.is_cancelled() {
                break;
            }

            match self.acquire_next().await {
                Ok(Some(mut task)) => {
                    debug!(task_id = %task.id, step = ?task.step, "dispatching task");
                    if let Err(e) = self.execute_task(&mut task).await {
                        error!(task_id = %task.id, error = %e, "task execution failed; will retry on next poll");
                    }
                }
                Ok(None) => {
                    tokio::select! {
                        _ = sleep(self.config.poll_interval) => {}
                        _ = shutdown.cancelled() => break,
                    }
                }
                Err(e) => {
                    warn!(error = %e, "acquire_next failed; sleeping before retry");
                    tokio::select! {
                        _ = sleep(self.config.poll_interval) => {}
                        _ = shutdown.cancelled() => break,
                    }
                }
            }
        }
        info!("worker stopped");
    }

    /// Claims the next runnable task, holding it under
    /// `FOR UPDATE SKIP LOCKED` until the claim is committed.
    ///
    /// Three steps inside one transaction:
    /// [`find_next_acquirable_for_update`][persistence::operation_tasks::find_next_acquirable_for_update]
    /// selects the row with the lock,
    /// [`try_acquire`][OperationTask::try_acquire] drives the in-memory
    /// aggregate, and
    /// [`set_acquired`][persistence::operation_tasks::set_acquired]
    /// persists the new state and attempt count. The lock is held
    /// across all three so a concurrent worker either skips this row
    /// entirely or sees the committed `in_progress` value.
    async fn acquire_next(&self) -> Result<Option<OperationTask>, PersistenceError> {
        let now = Utc::now();
        let mut tx = self.pool.begin().await.map_err(PersistenceError::Db)?;
        let Some(mut task) =
            persistence::operation_tasks::find_next_acquirable_for_update(&mut tx, now).await?
        else {
            return Ok(None);
        };
        task.try_acquire(now)
            .map_err(|e: DomainError| PersistenceError::DataIntegrity {
                details: format!("try_acquire: {e}"),
            })?;
        persistence::operation_tasks::set_acquired(&mut tx, &task).await?;
        tx.commit().await.map_err(PersistenceError::Db)?;
        Ok(Some(task))
    }

    async fn execute_task(&mut self, task: &mut OperationTask) -> Result<(), WorkerError> {
        match task.task_type {
            TaskType::CreateIssuer => self.execute_create_issuer(task).await,
            TaskType::DeactivateIssuer => self.execute_deactivate_issuer(task).await,
            TaskType::RotateKeys => self.execute_rotate_keys(task).await,
        }
    }

    async fn execute_create_issuer(&mut self, task: &mut OperationTask) -> Result<(), WorkerError> {
        let input: CreateIssuerInput = serde_json::from_value(task.input.clone())
            .map_err(|e| WorkerError::Decode(format!("input: {e}")))?;
        let state: CreateIssuerStateData = serde_json::from_value(task.state_data.clone())
            .map_err(|e| WorkerError::Decode(format!("state_data: {e}")))?;

        let mut conn = self.pool.acquire().await.map_err(PersistenceError::Db)?;
        let tenant = persistence::tenants::find_by_id(&mut conn, &task.tenant_id)
            .await?
            .ok_or_else(|| WorkerError::Decode(format!("tenant {} not found", task.tenant_id)))?;
        drop(conn);

        let provider = self.providers.provider_for(&task.tenant_id).await;

        // Pin `now` for the proof construction to `task.created_at` so
        // build_initial_didlog, publish_didlog, and persist_issuer all see the
        // same value and re-runs produce byte-identical SCID/entryHash.
        let entry_now = task.created_at;

        let step_name: &str = task.step.as_deref().unwrap_or("allocate_did");
        let (outcome, next_step) = match step_name {
            "allocate_did" => (
                execute_allocate_did(&tenant, &state, &self.registry, &*provider).await,
                Some("generate_keys"),
            ),
            "generate_keys" => (
                execute_generate_keys(&state, &self.engine).await,
                Some("build_initial_didlog"),
            ),
            "build_initial_didlog" => (
                execute_build_initial_didlog(&state, &self.engine, entry_now).await,
                Some("publish_didlog"),
            ),
            "publish_didlog" => (
                execute_create_publish_didlog(
                    &tenant,
                    &state,
                    &self.registry,
                    &self.engine,
                    &*provider,
                    entry_now,
                )
                .await,
                Some("persist_issuer"),
            ),
            "persist_issuer" => {
                let issuer_id = task.result_issuer_id.as_ref().ok_or_else(|| {
                    WorkerError::Decode("task.result_issuer_id is None at persist_issuer".into())
                })?;
                (
                    execute_persist_issuer(
                        &self.pool,
                        &task.tenant_id,
                        issuer_id,
                        &input,
                        &state,
                        &self.engine,
                        entry_now,
                    )
                    .await,
                    Some("create_status_list_entry"),
                )
            }
            "create_status_list_entry" => (
                execute_create_status_list_entry(
                    &tenant,
                    &state,
                    &self.status_registry,
                    &*provider,
                )
                .await,
                Some("provision_status_list"),
            ),
            "provision_status_list" => {
                let issuer_id = task.result_issuer_id.as_ref().ok_or_else(|| {
                    WorkerError::Decode(
                        "task.result_issuer_id is None at provision_status_list".into(),
                    )
                })?;
                (
                    execute_provision_status_list(&self.pool, issuer_id, &state).await,
                    None,
                )
            }
            other => {
                return Err(WorkerError::Decode(format!("unknown step: {other}")));
            }
        };

        match &outcome {
            StepOutcome::Done(_) => {
                debug!(task_id = %task.id, step = step_name, "step done");
            }
            StepOutcome::Retry {
                error_code,
                error_message,
            } => {
                warn!(
                    task_id = %task.id,
                    step = step_name,
                    error_code = error_code.as_str(),
                    error_message = error_message.as_str(),
                    "step requested retry",
                );
            }
            StepOutcome::Terminal {
                error_code,
                error_message,
            } => {
                error!(
                    task_id = %task.id,
                    step = step_name,
                    error_code = error_code.as_str(),
                    error_message = error_message.as_str(),
                    "step terminal failure",
                );
            }
        }

        let now = Utc::now();
        let mut conn = self.pool.acquire().await.map_err(PersistenceError::Db)?;
        match (outcome, next_step) {
            (StepOutcome::Done(_), None) => {
                // Final step succeeded — task is complete. The final
                // step's StepResult patch is empty by convention
                // (`persist_issuer` returns `StepResult::default()`),
                // so nothing to merge into state_data here.
                task.try_complete(now)
                    .map_err(|e| PersistenceError::DataIntegrity {
                        details: format!("try_complete: {e}"),
                    })?;
                persistence::operation_tasks::set_terminal_state(&mut conn, task).await?;
                info!(
                    task_id = %task.id,
                    issuer_id = ?task.result_issuer_id,
                    "task completed",
                );
            }
            (outcome, next_step) => {
                apply_outcome(&mut conn, task, next_step, outcome, now, &mut *self.rng).await?;
            }
        }

        Ok(())
    }

    async fn execute_deactivate_issuer(
        &mut self,
        task: &mut OperationTask,
    ) -> Result<(), WorkerError> {
        // Validate input + state-data shapes; both are empty by
        // convention but going through `serde_json::from_value`
        // catches malformed rows early.
        let _input: DeactivateIssuerInput = serde_json::from_value(task.input.clone())
            .map_err(|e| WorkerError::Decode(format!("input: {e}")))?;
        let state: DeactivateIssuerStateData = serde_json::from_value(task.state_data.clone())
            .map_err(|e| WorkerError::Decode(format!("state_data: {e}")))?;

        let issuer_id = task.result_issuer_id.as_ref().ok_or_else(|| {
            WorkerError::Decode("task.result_issuer_id is None for DeactivateIssuer".into())
        })?;

        // Load tenant + issuer once; pass references to each step.
        let mut conn = self.pool.acquire().await.map_err(PersistenceError::Db)?;
        let tenant = persistence::tenants::find_by_id(&mut conn, &task.tenant_id)
            .await?
            .ok_or_else(|| WorkerError::Decode(format!("tenant {} not found", task.tenant_id)))?;
        let issuer =
            persistence::issuers::find_by_id_for_tenant(&mut conn, &task.tenant_id, issuer_id)
                .await?
                .ok_or_else(|| {
                    WorkerError::Decode(format!(
                        "issuer {issuer_id} not found for tenant {}",
                        task.tenant_id
                    ))
                })?;
        drop(conn);

        let provider = self.providers.provider_for(&task.tenant_id).await;

        // Pin `now` to task.created_at so a re-run after a crash
        // produces a byte-identical signed entry — same discipline
        // the create_issuer saga uses.
        let entry_now = task.created_at;

        let step_name: &str = task.step.as_deref().unwrap_or("build_deactivation_didlog");
        let (outcome, next_step) = match step_name {
            "build_deactivation_didlog" => (
                execute_build_deactivation_didlog(&issuer, &self.registry, &self.engine, entry_now)
                    .await,
                Some("publish_didlog"),
            ),
            "publish_didlog" => (
                execute_deactivate_publish_didlog(
                    &tenant,
                    &issuer,
                    &state,
                    &self.registry,
                    &self.engine,
                    &*provider,
                    entry_now,
                )
                .await,
                Some("mark_deactivated"),
            ),
            "mark_deactivated" => (
                execute_mark_deactivated(&self.pool, &task.tenant_id, issuer_id, entry_now).await,
                None,
            ),
            other => {
                return Err(WorkerError::Decode(format!("unknown step: {other}")));
            }
        };

        match &outcome {
            StepOutcome::Done(_) => {
                debug!(task_id = %task.id, step = step_name, "step done");
            }
            StepOutcome::Retry {
                error_code,
                error_message,
            } => {
                warn!(
                    task_id = %task.id,
                    step = step_name,
                    error_code = error_code.as_str(),
                    error_message = error_message.as_str(),
                    "step requested retry",
                );
            }
            StepOutcome::Terminal {
                error_code,
                error_message,
            } => {
                error!(
                    task_id = %task.id,
                    step = step_name,
                    error_code = error_code.as_str(),
                    error_message = error_message.as_str(),
                    "step terminal failure",
                );
            }
        }

        let now = Utc::now();
        let mut conn = self.pool.acquire().await.map_err(PersistenceError::Db)?;
        match (outcome, next_step) {
            (StepOutcome::Done(_), None) => {
                task.try_complete(now)
                    .map_err(|e| PersistenceError::DataIntegrity {
                        details: format!("try_complete: {e}"),
                    })?;
                persistence::operation_tasks::set_terminal_state(&mut conn, task).await?;
                info!(
                    task_id = %task.id,
                    issuer_id = ?task.result_issuer_id,
                    "task completed",
                );
            }
            (outcome, next_step) => {
                apply_outcome(&mut conn, task, next_step, outcome, now, &mut *self.rng).await?;
            }
        }

        Ok(())
    }

    async fn execute_rotate_keys(&mut self, task: &mut OperationTask) -> Result<(), WorkerError> {
        let input: RotateKeysInput = serde_json::from_value(task.input.clone())
            .map_err(|e| WorkerError::Decode(format!("input: {e}")))?;
        let state: RotateKeysStateData = serde_json::from_value(task.state_data.clone())
            .map_err(|e| WorkerError::Decode(format!("state_data: {e}")))?;

        let issuer_id = task.result_issuer_id.as_ref().ok_or_else(|| {
            WorkerError::Decode("task.result_issuer_id is None for RotateKeys".into())
        })?;

        let mut conn = self.pool.acquire().await.map_err(PersistenceError::Db)?;
        let tenant = persistence::tenants::find_by_id(&mut conn, &task.tenant_id)
            .await?
            .ok_or_else(|| WorkerError::Decode(format!("tenant {} not found", task.tenant_id)))?;
        let issuer =
            persistence::issuers::find_by_id_for_tenant(&mut conn, &task.tenant_id, issuer_id)
                .await?
                .ok_or_else(|| {
                    WorkerError::Decode(format!(
                        "issuer {issuer_id} not found for tenant {}",
                        task.tenant_id
                    ))
                })?;
        drop(conn);

        let provider = self.providers.provider_for(&task.tenant_id).await;

        // Pin `now` to task.created_at so a re-run after a crash
        // produces a byte-identical signed entry — same discipline
        // the create_issuer and deactivate_issuer sagas use.
        let entry_now = task.created_at;

        let step_name: &str = task.step.as_deref().unwrap_or("generate_new_keys");
        let (outcome, next_step) = match step_name {
            "generate_new_keys" => (
                execute_generate_new_keys(&issuer, &input, &state, &self.engine).await,
                Some("build_rotation_didlog"),
            ),
            "build_rotation_didlog" => (
                execute_build_rotation_didlog(
                    &issuer,
                    &state,
                    &self.registry,
                    &self.engine,
                    entry_now,
                )
                .await,
                Some("publish_didlog"),
            ),
            "publish_didlog" => (
                execute_rotate_publish_didlog(
                    &tenant,
                    &issuer,
                    &state,
                    &self.registry,
                    &self.engine,
                    &*provider,
                    entry_now,
                )
                .await,
                Some("swap_keys"),
            ),
            "swap_keys" => (
                execute_swap_keys(&self.pool, &task.tenant_id, issuer_id, &state).await,
                None,
            ),
            other => {
                return Err(WorkerError::Decode(format!("unknown step: {other}")));
            }
        };

        match &outcome {
            StepOutcome::Done(_) => {
                debug!(task_id = %task.id, step = step_name, "step done");
            }
            StepOutcome::Retry {
                error_code,
                error_message,
            } => {
                warn!(
                    task_id = %task.id,
                    step = step_name,
                    error_code = error_code.as_str(),
                    error_message = error_message.as_str(),
                    "step requested retry",
                );
            }
            StepOutcome::Terminal {
                error_code,
                error_message,
            } => {
                error!(
                    task_id = %task.id,
                    step = step_name,
                    error_code = error_code.as_str(),
                    error_message = error_message.as_str(),
                    "step terminal failure",
                );
            }
        }

        let now = Utc::now();
        let mut conn = self.pool.acquire().await.map_err(PersistenceError::Db)?;
        match (outcome, next_step) {
            (StepOutcome::Done(_), None) => {
                task.try_complete(now)
                    .map_err(|e| PersistenceError::DataIntegrity {
                        details: format!("try_complete: {e}"),
                    })?;
                persistence::operation_tasks::set_terminal_state(&mut conn, task).await?;
                info!(
                    task_id = %task.id,
                    issuer_id = ?task.result_issuer_id,
                    "task completed",
                );
            }
            (outcome, next_step) => {
                apply_outcome(&mut conn, task, next_step, outcome, now, &mut *self.rng).await?;
            }
        }

        Ok(())
    }
}
