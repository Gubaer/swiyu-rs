use chrono::{DateTime, Utc};
use serde_json::Value;

use super::DomainError;
use super::ids::{IssuerId, TaskId, TenantId};

/// Lifecycle state of an operation task as observed by a business application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    /// Initial state.
    Pending,
    /// Covers both active execution and time paused waiting for retry timers.
    InProgress,
    /// Terminal. The operation succeeded.
    Completed,
    /// Terminal. The operation exhausted retries or hit a non-retryable error.
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

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed)
    }
}

impl TryFrom<&str> for TaskState {
    type Error = DomainError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
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
}

impl sqlx::Type<sqlx::Postgres> for TaskState {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <String as sqlx::Type<sqlx::Postgres>>::type_info()
    }

    fn compatible(ty: &sqlx::postgres::PgTypeInfo) -> bool {
        <String as sqlx::Type<sqlx::Postgres>>::compatible(ty)
    }
}

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for TaskState {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let s = <&str as sqlx::Decode<'r, sqlx::Postgres>>::decode(value)?;
        TaskState::try_from(s).map_err(|e| Box::new(e) as sqlx::error::BoxDynError)
    }
}

impl<'q> sqlx::Encode<'q, sqlx::Postgres> for TaskState {
    fn encode_by_ref(
        &self,
        buf: &mut sqlx::postgres::PgArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        <&str as sqlx::Encode<'q, sqlx::Postgres>>::encode_by_ref(&self.as_str(), buf)
    }
}

/// The kind of long-running operation a task represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskType {
    CreateIssuer,
    DeactivateIssuer,
    RotateKeys,
}

impl TaskType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CreateIssuer => "create_issuer",
            Self::DeactivateIssuer => "deactivate_issuer",
            Self::RotateKeys => "rotate_keys",
        }
    }
}

impl TryFrom<&str> for TaskType {
    type Error = DomainError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "create_issuer" => Ok(Self::CreateIssuer),
            "deactivate_issuer" => Ok(Self::DeactivateIssuer),
            "rotate_keys" => Ok(Self::RotateKeys),
            _ => Err(DomainError::InvalidInput {
                details: format!("unknown task type: {s}"),
            }),
        }
    }
}

impl sqlx::Type<sqlx::Postgres> for TaskType {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <String as sqlx::Type<sqlx::Postgres>>::type_info()
    }

    fn compatible(ty: &sqlx::postgres::PgTypeInfo) -> bool {
        <String as sqlx::Type<sqlx::Postgres>>::compatible(ty)
    }
}

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for TaskType {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let s = <&str as sqlx::Decode<'r, sqlx::Postgres>>::decode(value)?;
        TaskType::try_from(s).map_err(|e| Box::new(e) as sqlx::error::BoxDynError)
    }
}

impl<'q> sqlx::Encode<'q, sqlx::Postgres> for TaskType {
    fn encode_by_ref(
        &self,
        buf: &mut sqlx::postgres::PgArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        <&str as sqlx::Encode<'q, sqlx::Postgres>>::encode_by_ref(&self.as_str(), buf)
    }
}

/// Intermediate data produced by a successfully executed step.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct StepResult {
    /// Merged into the task row's `state_data` JSONB column before advancing
    /// to the next step. Each key overwrites the existing value; absent keys
    /// are preserved.
    pub state_data_patch: serde_json::Map<String, Value>,
}

/// Outcome of a step function executed by the worker.
#[derive(Debug, Clone, PartialEq)]
pub enum StepOutcome {
    /// Step succeeded. `result` is merged into accumulated state and the
    /// worker advances to the next step.
    Done(StepResult),
    /// Transient failure. The worker schedules another attempt with exponential
    /// backoff. If the elapsed-time cap is exceeded, the task transitions to
    /// `Failed` instead.
    Retry {
        error_code: String,
        error_message: String,
    },
    /// Non-recoverable failure. The worker transitions the task to `Failed`
    /// immediately without scheduling a retry.
    Terminal {
        error_code: String,
        error_message: String,
    },
}

/// A long-running operation initiated by a business application.
///
/// A task is created with state `Pending`, picked up by a worker, and
/// runs through a sequence of internal steps until reaching a terminal state.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
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
    /// the worker advances to a new step. Stored as `INTEGER` (i32)
    /// in Postgres; `try_from = "i32"` rejects negative values at
    /// decode time as a data-integrity error.
    #[sqlx(try_from = "i32")]
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

impl OperationTask {
    /// Transitions an `InProgress` task to `Completed` and stamps the
    /// terminal timestamps. The associated [`result_issuer_id`][Self::result_issuer_id]
    /// (if any) is expected to already be on the aggregate from earlier
    /// step writes.
    ///
    /// Returns [`StateTransitionNotAllowed`][DomainError::StateTransitionNotAllowed]
    /// if the task is not currently `InProgress` — calling this on a
    /// `Pending`, `Completed`, or `Failed` task is a worker-loop bug.
    pub fn try_complete(&mut self, now: DateTime<Utc>) -> Result<(), DomainError> {
        match self.state {
            TaskState::InProgress => {
                self.state = TaskState::Completed;
                self.next_attempt_at = None;
                self.error_code = None;
                self.error_message = None;
                self.updated_at = now;
                self.completed_at = Some(now);
                Ok(())
            }
            _ => Err(DomainError::StateTransitionNotAllowed),
        }
    }

    /// Transitions an `InProgress` task to `Failed`, stamps the
    /// terminal timestamps, and records the operator-visible error
    /// pair. Used both for non-recoverable step errors
    /// ([`Terminal`][StepOutcome::Terminal]) and for retry-cap exhaustion.
    ///
    /// Returns [`StateTransitionNotAllowed`][DomainError::StateTransitionNotAllowed]
    /// if the task is not currently `InProgress`.
    pub fn try_fail(
        &mut self,
        error_code: String,
        error_message: String,
        now: DateTime<Utc>,
    ) -> Result<(), DomainError> {
        match self.state {
            TaskState::InProgress => {
                self.state = TaskState::Failed;
                self.next_attempt_at = None;
                self.error_code = Some(error_code);
                self.error_message = Some(error_message);
                self.updated_at = now;
                self.completed_at = Some(now);
                Ok(())
            }
            _ => Err(DomainError::StateTransitionNotAllowed),
        }
    }

    /// Claims a runnable task for the worker. Legal from `Pending`
    /// (first pickup) and from `InProgress` (re-acquisition: either a
    /// scheduled retry whose timer has elapsed, or recovery after a
    /// worker crash mid-step).
    ///
    /// Pending → InProgress leaves [`attempts`][Self::attempts] untouched:
    /// the upcoming run is the first attempt for this step, recorded as
    /// `attempts == 0` while it executes. InProgress → InProgress
    /// increments [`attempts`][Self::attempts]: a previous attempt has
    /// already completed (failed or crashed) and the upcoming run is
    /// the next one. The aggregate cannot tell scheduled-retry from
    /// crash-recovery from row state alone, and treats them
    /// identically.
    ///
    /// Returns [`StateTransitionNotAllowed`][DomainError::StateTransitionNotAllowed]
    /// from `Completed` or `Failed`; terminal tasks are not re-acquirable.
    pub fn try_acquire(&mut self, now: DateTime<Utc>) -> Result<(), DomainError> {
        match self.state {
            TaskState::Pending => {
                self.state = TaskState::InProgress;
                self.updated_at = now;
                Ok(())
            }
            TaskState::InProgress => {
                self.attempts = self.attempts.saturating_add(1);
                self.updated_at = now;
                Ok(())
            }
            TaskState::Completed | TaskState::Failed => Err(DomainError::StateTransitionNotAllowed),
        }
    }
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
            assert_eq!(TaskState::try_from(state.as_str()).unwrap(), state);
        }
    }

    #[test]
    fn task_state_parse_rejects_unknown() {
        assert!(TaskState::try_from("running").is_err());
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
        for task_type in [
            TaskType::CreateIssuer,
            TaskType::DeactivateIssuer,
            TaskType::RotateKeys,
        ] {
            assert_eq!(TaskType::try_from(task_type.as_str()).unwrap(), task_type);
        }
    }

    #[test]
    fn task_type_parse_rejects_unknown() {
        assert!(TaskType::try_from("compress_log").is_err());
    }

    #[test]
    fn step_result_default_is_empty() {
        let result = StepResult::default();
        assert!(result.state_data_patch.is_empty());
    }

    fn fixture_task_in_state(state: TaskState) -> OperationTask {
        OperationTask {
            id: TaskId::generate(),
            tenant_id: TenantId::generate(),
            task_type: TaskType::CreateIssuer,
            state,
            step: Some("allocate_did".into()),
            attempts: 0,
            next_attempt_at: None,
            error_code: Some("prior_error".into()),
            error_message: Some("prior message".into()),
            input: serde_json::json!({}),
            state_data: serde_json::json!({}),
            result_issuer_id: None,
            created_at: chrono::DateTime::<chrono::Utc>::from_timestamp(0, 0).unwrap(),
            updated_at: chrono::DateTime::<chrono::Utc>::from_timestamp(0, 0).unwrap(),
            completed_at: None,
        }
    }

    #[test]
    fn try_complete_flips_in_progress_to_completed_and_clears_errors() {
        let mut task = fixture_task_in_state(TaskState::InProgress);
        let now = chrono::Utc::now();
        task.try_complete(now).unwrap();
        assert_eq!(task.state, TaskState::Completed);
        assert_eq!(task.next_attempt_at, None);
        assert_eq!(task.error_code, None);
        assert_eq!(task.error_message, None);
        assert_eq!(task.updated_at, now);
        assert_eq!(task.completed_at, Some(now));
    }

    #[test]
    fn try_complete_rejects_pending() {
        let mut task = fixture_task_in_state(TaskState::Pending);
        let err = task.try_complete(chrono::Utc::now()).unwrap_err();
        assert!(matches!(err, DomainError::StateTransitionNotAllowed));
        assert_eq!(task.state, TaskState::Pending);
    }

    #[test]
    fn try_complete_rejects_already_completed() {
        let mut task = fixture_task_in_state(TaskState::Completed);
        let err = task.try_complete(chrono::Utc::now()).unwrap_err();
        assert!(matches!(err, DomainError::StateTransitionNotAllowed));
    }

    #[test]
    fn try_complete_rejects_failed() {
        let mut task = fixture_task_in_state(TaskState::Failed);
        let err = task.try_complete(chrono::Utc::now()).unwrap_err();
        assert!(matches!(err, DomainError::StateTransitionNotAllowed));
    }

    #[test]
    fn try_fail_flips_in_progress_to_failed_and_records_error() {
        let mut task = fixture_task_in_state(TaskState::InProgress);
        let now = chrono::Utc::now();
        task.try_fail("op_failed".into(), "reason".into(), now)
            .unwrap();
        assert_eq!(task.state, TaskState::Failed);
        assert_eq!(task.next_attempt_at, None);
        assert_eq!(task.error_code.as_deref(), Some("op_failed"));
        assert_eq!(task.error_message.as_deref(), Some("reason"));
        assert_eq!(task.updated_at, now);
        assert_eq!(task.completed_at, Some(now));
    }

    #[test]
    fn try_fail_rejects_pending() {
        let mut task = fixture_task_in_state(TaskState::Pending);
        let err = task
            .try_fail("e".into(), "m".into(), chrono::Utc::now())
            .unwrap_err();
        assert!(matches!(err, DomainError::StateTransitionNotAllowed));
    }

    #[test]
    fn try_fail_rejects_already_failed() {
        let mut task = fixture_task_in_state(TaskState::Failed);
        let err = task
            .try_fail("e".into(), "m".into(), chrono::Utc::now())
            .unwrap_err();
        assert!(matches!(err, DomainError::StateTransitionNotAllowed));
    }

    #[test]
    fn try_acquire_pending_to_in_progress_keeps_attempts() {
        let mut task = fixture_task_in_state(TaskState::Pending);
        task.attempts = 0;
        let now = chrono::Utc::now();
        task.try_acquire(now).unwrap();
        assert_eq!(task.state, TaskState::InProgress);
        assert_eq!(task.attempts, 0);
        assert_eq!(task.updated_at, now);
    }

    #[test]
    fn try_acquire_in_progress_to_in_progress_increments_attempts() {
        let mut task = fixture_task_in_state(TaskState::InProgress);
        task.attempts = 2;
        let now = chrono::Utc::now();
        task.try_acquire(now).unwrap();
        assert_eq!(task.state, TaskState::InProgress);
        assert_eq!(task.attempts, 3);
        assert_eq!(task.updated_at, now);
    }

    #[test]
    fn try_acquire_rejects_completed() {
        let mut task = fixture_task_in_state(TaskState::Completed);
        let err = task.try_acquire(chrono::Utc::now()).unwrap_err();
        assert!(matches!(err, DomainError::StateTransitionNotAllowed));
        assert_eq!(task.state, TaskState::Completed);
    }

    #[test]
    fn try_acquire_rejects_failed() {
        let mut task = fixture_task_in_state(TaskState::Failed);
        let err = task.try_acquire(chrono::Utc::now()).unwrap_err();
        assert!(matches!(err, DomainError::StateTransitionNotAllowed));
        assert_eq!(task.state, TaskState::Failed);
    }
}
