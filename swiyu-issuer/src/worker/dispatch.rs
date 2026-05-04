//! Maps a `StepOutcome` returned by an executor to the persistence
//! transitions on `operation_tasks`.
//!
//! Covers the regular-step transitions: advance to next step on
//! success, schedule the next retry on transient failure, mark
//! terminally failed otherwise. The 24-hour wall-clock cap from
//! `worker::backoff` lives here too — a `Retry` outcome past the cap
//! routes to `mark_failed` instead of `schedule_retry`. The
//! final-step `Done` (which calls `mark_completed`) is the dispatch
//! loop's responsibility, not this function's.

use chrono::{DateTime, Utc};
use rand_core::RngCore;
use sqlx::postgres::PgConnection;

use crate::domain::{OperationTask, StepOutcome};
use crate::persistence::{PersistenceError, operation_tasks};
use crate::worker::backoff::{backoff_delay, is_past_cap};

pub async fn apply_outcome(
    conn: &mut PgConnection,
    task: &OperationTask,
    next_step: Option<&str>,
    outcome: StepOutcome,
    now: DateTime<Utc>,
    rng: &mut impl RngCore,
) -> Result<(), PersistenceError> {
    match outcome {
        StepOutcome::Done(result) => {
            operation_tasks::advance_step(conn, &task.id, next_step, &result.state_data_patch, now)
                .await
        }
        StepOutcome::Retry {
            error_code,
            error_message,
        } => {
            if is_past_cap(task.created_at, now) {
                operation_tasks::mark_failed(conn, &task.id, &error_code, &error_message, now).await
            } else {
                let next_attempts = task.attempts.saturating_add(1);
                let delay = backoff_delay(next_attempts, rng);
                let next_attempt_at = now
                    + chrono::Duration::from_std(delay).expect(
                        "backoff_delay returns at most 1 hour, well within chrono::Duration",
                    );
                operation_tasks::schedule_retry(
                    conn,
                    &task.id,
                    next_attempts,
                    next_attempt_at,
                    &error_code,
                    &error_message,
                    now,
                )
                .await
            }
        }
        StepOutcome::Terminal {
            error_code,
            error_message,
        } => operation_tasks::mark_failed(conn, &task.id, &error_code, &error_message, now).await,
    }
}
