use chrono::{DateTime, Utc};
use serde_json::Value;

use super::DomainError;
use super::ids::{IssuerId, TaskId, TenantId};

/// Lifecycle state of an operation task as observed by a business application.
///
/// New tasks start in `Pending` and reach one of two terminal states:
/// `Completed` on success, `Failed` after exhausting retries or on any
/// non-retryable error. The `InProgress` state covers both active
/// execution and time spent paused waiting for retry timers — the BA
/// does not distinguish the two. See `aspect-issuer.md`
/// (Asynchronous execution).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Pending,
    InProgress,
    Completed,
    Failed,
}

impl TaskState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::InProgress => "in_progress",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    pub fn parse(s: &str) -> Result<Self, DomainError> {
        match s {
            "pending" => Ok(Self::Pending),
            "in_progress" => Ok(Self::InProgress),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            _ => Err(DomainError::InvalidInput {
                details: format!("unknown task state: {s}"),
            }),
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed)
    }
}

/// The kind of long-running operation a task represents.
///
/// `RotateKeys` follows the same task model in a subsequent slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskType {
    CreateIssuer,
    DeactivateIssuer,
}

impl TaskType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CreateIssuer => "create_issuer",
            Self::DeactivateIssuer => "deactivate_issuer",
        }
    }

    pub fn parse(s: &str) -> Result<Self, DomainError> {
        match s {
            "create_issuer" => Ok(Self::CreateIssuer),
            "deactivate_issuer" => Ok(Self::DeactivateIssuer),
            _ => Err(DomainError::InvalidInput {
                details: format!("unknown task type: {s}"),
            }),
        }
    }
}

/// Intermediate data produced by a successfully executed step.
///
/// The worker merges `state_data_patch` into the task row's `state_data`
/// JSONB column before advancing to the next step. Each entry overwrites
/// the existing key with the same name; entries not in the patch are
/// preserved.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct StepResult {
    pub state_data_patch: serde_json::Map<String, Value>,
}

/// Outcome of a step function executed by the worker.
///
/// - `Done(result)` — step succeeded; `result` contributes to the
///   accumulated state and the worker advances to the next step.
/// - `Retry` — transient failure; the worker schedules another attempt
///   with exponential backoff. If the elapsed-time cap is exceeded, the
///   worker transitions the task to `Failed` instead of scheduling another
///   retry.
/// - `Terminal` — non-recoverable failure; the worker transitions the
///   task to `Failed` immediately.
#[derive(Debug, Clone, PartialEq)]
pub enum StepOutcome {
    Done(StepResult),
    Retry {
        error_code: String,
        error_message: String,
    },
    Terminal {
        error_code: String,
        error_message: String,
    },
}

/// A long-running operation initiated by a business application.
///
/// A task is created with state `Pending`, picked up by a worker, and
/// runs through a sequence of internal steps until reaching a terminal
/// state. See `aspect-issuer.md` (Asynchronous execution) and
/// `impl-issuer.md` (Worker) for the choreography.
#[derive(Debug, Clone, PartialEq)]
pub struct OperationTask {
    pub id: TaskId,
    pub tenant_id: TenantId,
    pub task_type: TaskType,
    pub state: TaskState,

    /// Internal step name identifying the sub-operation currently
    /// executing or last attempted. `None` until the worker picks the
    /// task up for the first time.
    pub step: Option<String>,

    /// Number of attempts made on the current step. Reset to `0` when
    /// the worker advances to a new step.
    pub attempts: u32,

    /// When the worker may try this task again. `None` for tasks that
    /// are runnable immediately (newly inserted or just advanced) and
    /// for tasks in a terminal state.
    pub next_attempt_at: Option<DateTime<Utc>>,

    /// Most recent error recorded for this task. Set on `Retry` and
    /// `Terminal` outcomes; cleared when a step completes with `Done`.
    pub error_code: Option<String>,
    pub error_message: Option<String>,

    /// Original request payload submitted by the BA. Persisted so the
    /// worker can re-derive parameters after a crash.
    pub input: Value,

    /// Intermediate results accumulated as steps complete (e.g. the
    /// assigned DID after `allocate_did`). Read on resume so the worker
    /// can skip steps whose side effects have already happened.
    pub state_data: Value,

    /// `IssuerId` produced by `CreateIssuer` tasks once they reach
    /// `Completed`. `None` for tasks that have not completed yet, or
    /// for task types that produce a different result.
    pub result_issuer_id: Option<IssuerId>,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,

    /// Set when the task transitions to a terminal state (`Completed`
    /// or `Failed`). `None` while the task is still active.
    pub completed_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_state_round_trips_through_strings() {
        for state in [
            TaskState::Pending,
            TaskState::InProgress,
            TaskState::Completed,
            TaskState::Failed,
        ] {
            assert_eq!(TaskState::parse(state.as_str()).unwrap(), state);
        }
    }

    #[test]
    fn task_state_parse_rejects_unknown() {
        assert!(TaskState::parse("running").is_err());
    }

    #[test]
    fn task_state_is_terminal_only_for_completed_and_failed() {
        assert!(!TaskState::Pending.is_terminal());
        assert!(!TaskState::InProgress.is_terminal());
        assert!(TaskState::Completed.is_terminal());
        assert!(TaskState::Failed.is_terminal());
    }

    #[test]
    fn task_type_round_trips_through_strings() {
        for task_type in [TaskType::CreateIssuer, TaskType::DeactivateIssuer] {
            assert_eq!(TaskType::parse(task_type.as_str()).unwrap(), task_type);
        }
    }

    #[test]
    fn task_type_parse_rejects_unknown() {
        assert!(TaskType::parse("rotate_keys").is_err());
    }

    #[test]
    fn step_result_default_is_empty() {
        let result = StepResult::default();
        assert!(result.state_data_patch.is_empty());
    }
}
