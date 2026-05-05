//! `Worker` — the dispatch loop for swiyu-issuer's operation-task
//! saga.
//!
//! A single `tokio::spawn`-ed task that polls the `operation_tasks`
//! table for runnable rows, dispatches each to the per-task-type
//! per-step executor, and applies the resulting outcome through the
//! persistence layer. v1 supports only the `CreateIssuer` task type;
//! `RotateKeys` and `DeactivateIssuer` follow the same shape and
//! land in subsequent slices.

use std::time::Duration;

use chrono::Utc;
use rand_core::RngCore;
use sqlx::PgPool;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::domain::{OperationTask, SigningEngine, StepOutcome, TaskType};
use crate::persistence::{self, PersistenceError};

use super::create_issuer::{
    CreateIssuerInput, CreateIssuerStateData, execute_allocate_did, execute_build_initial_log,
    execute_generate_keys, execute_persist_issuer, execute_publish_log,
};
use super::dispatch::apply_outcome;
use super::registry::RegistryFacade;

#[derive(Debug, thiserror::Error)]
pub enum WorkerError {
    #[error(transparent)]
    Persistence(#[from] PersistenceError),
    #[error("decode: {0}")]
    Decode(String),
}

/// Default sleep between dispatch-loop polls when no task is runnable.
/// Tests override this via `Worker::with_poll_interval`; the
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
/// `R` and `S` are bound to concrete types at startup (typically
/// `IdentifierRegistryClient` and `DevSigningEngine` in v1, swapped
/// for in-memory mocks in tests). The `rng` is a heap-allocated
/// `RngCore` so callers can inject a deterministic implementation in
/// tests without making the whole struct generic over a third
/// parameter.
pub struct Worker<R, S> {
    pool: PgPool,
    registry: R,
    engine: S,
    rng: Box<dyn RngCore + Send + Sync>,
    config: WorkerConfig,
}

impl<R, S> Worker<R, S>
where
    R: RegistryFacade + 'static,
    S: SigningEngine + 'static,
{
    pub fn new(pool: PgPool, registry: R, engine: S, rng: Box<dyn RngCore + Send + Sync>) -> Self {
        Self {
            pool,
            registry,
            engine,
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
                Ok(Some(task)) => {
                    debug!(task_id = %task.id, step = ?task.step, "dispatching task");
                    if let Err(e) = self.execute_task(&task).await {
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

    async fn acquire_next(&self) -> Result<Option<OperationTask>, PersistenceError> {
        let mut conn = self.pool.acquire().await.map_err(PersistenceError::Db)?;
        persistence::operation_tasks::acquire_next(&mut conn, Utc::now()).await
    }

    async fn execute_task(&mut self, task: &OperationTask) -> Result<(), WorkerError> {
        match task.task_type {
            TaskType::CreateIssuer => self.execute_create_issuer(task).await,
            // The DeactivateIssuer task type exists in the domain (step
            // 9.1) but no endpoint can create one yet, so this arm is
            // unreachable in practice. Replaced with the real
            // dispatcher in step 9.6.
            TaskType::DeactivateIssuer => Err(WorkerError::Decode(
                "DeactivateIssuer task type not yet implemented".into(),
            )),
        }
    }

    async fn execute_create_issuer(&mut self, task: &OperationTask) -> Result<(), WorkerError> {
        let input: CreateIssuerInput = serde_json::from_value(task.input.clone())
            .map_err(|e| WorkerError::Decode(format!("input: {e}")))?;
        let state: CreateIssuerStateData = serde_json::from_value(task.state_data.clone())
            .map_err(|e| WorkerError::Decode(format!("state_data: {e}")))?;

        let mut conn = self.pool.acquire().await.map_err(PersistenceError::Db)?;
        let tenant = persistence::tenants::find_by_id(&mut conn, &task.tenant_id)
            .await?
            .ok_or_else(|| WorkerError::Decode(format!("tenant {} not found", task.tenant_id)))?;
        drop(conn);

        // Pin `now` for the proof construction to `task.created_at` so
        // build_initial_log, publish_log, and persist_issuer all see the
        // same value and re-runs produce byte-identical SCID/entryHash.
        let entry_now = task.created_at;

        let step_name: &str = task.step.as_deref().unwrap_or("allocate_did");
        let (outcome, next_step) = match step_name {
            "allocate_did" => (
                execute_allocate_did(&tenant, &state, &self.registry).await,
                Some("generate_keys"),
            ),
            "generate_keys" => (
                execute_generate_keys(&state, &self.engine).await,
                Some("build_initial_log"),
            ),
            "build_initial_log" => (
                execute_build_initial_log(&state, &self.engine, entry_now).await,
                Some("publish_log"),
            ),
            "publish_log" => (
                execute_publish_log(&tenant, &state, &self.registry, &self.engine, entry_now).await,
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
                persistence::operation_tasks::mark_completed(
                    &mut conn,
                    &task.id,
                    task.result_issuer_id.as_ref(),
                    now,
                )
                .await?;
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
