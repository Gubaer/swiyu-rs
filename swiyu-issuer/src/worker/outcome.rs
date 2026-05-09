//! Helpers around the [`StepOutcome`] boundary type.
//!
//! - [`from_token_aware_error`] lifts a [`TokenAwareError`] into a
//!   `StepOutcome` for the per-step worker functions, picking the
//!   right `Retry` / `Terminal` shape based on the inner error.
//! - [`apply`] consumes a `StepOutcome` returned by an executor and
//!   advances the corresponding `operation_tasks` row through the
//!   persistence layer.

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use rand_core::RngCore;
use sqlx::postgres::PgConnection;

use crate::domain::{OperationTask, StepOutcome, TokenAwareError, TokenProviderError};
use crate::persistence::{PersistenceError, operation_tasks};
use crate::worker::backoff::{MAX_TASK_AGE_HOURS, backoff_delay};

/// Translates a [`TokenAwareError`] into a [`StepOutcome`] for the
/// per-step worker functions.
///
/// Every protected registry call in the worker funnels through one of
/// the `*_with_refresh` helpers in [`crate::worker::registry_facades`],
/// so every caller faces the same five-arm `Err` mapping. Centralising
/// it here keeps the per-step bodies focused on their happy paths and
/// ensures the error-code vocabulary stays consistent across sagas.
///
/// The two `registry_*` codes are caller-supplied because the
/// identifier registry uses `registry_unavailable` / `registry_rejected`
/// while the status registry uses `status_registry_unavailable` /
/// `status_registry_rejected`. The token-side codes are fixed.
pub fn from_token_aware_error(
    error: TokenAwareError,
    registry_retry_code: &str,
    registry_terminal_code: &str,
) -> StepOutcome {
    match error {
        TokenAwareError::Registry(e) if e.is_retryable() => StepOutcome::Retry {
            error_code: registry_retry_code.into(),
            error_message: e.to_string(),
        },
        TokenAwareError::Registry(e) => StepOutcome::Terminal {
            error_code: registry_terminal_code.into(),
            error_message: e.to_string(),
        },
        TokenAwareError::Token(TokenProviderError::MissingCredentials(msg)) => {
            StepOutcome::Terminal {
                error_code: "tenant_missing_oauth_credentials".into(),
                error_message: msg,
            }
        }
        TokenAwareError::Token(e) if e.is_retryable() => StepOutcome::Retry {
            error_code: "token_unavailable".into(),
            error_message: e.to_string(),
        },
        TokenAwareError::Token(e) => StepOutcome::Terminal {
            error_code: "token_rejected".into(),
            error_message: e.to_string(),
        },
    }
}

/// Maps a [`StepOutcome`] returned by an executor to the persistence
/// transitions on `operation_tasks`.
///
/// Covers the regular-step transitions: advance to next step on
/// success, schedule the next retry on transient failure, mark
/// terminally failed otherwise. The 24-hour wall-clock cap from
/// [`crate::worker::backoff`] lives here too — a `Retry` outcome past
/// the cap routes to `mark_failed` instead of `schedule_retry`. The
/// final-step `Done` (which calls `mark_completed`) is the dispatch
/// loop's responsibility, not this function's.
pub async fn apply(
    conn: &mut PgConnection,
    task: &OperationTask,
    next_step: Option<&str>,
    outcome: StepOutcome,
    now: DateTime<Utc>,
    rng: &mut (impl RngCore + ?Sized),
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
            if now - task.created_at >= ChronoDuration::hours(MAX_TASK_AGE_HOURS) {
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
