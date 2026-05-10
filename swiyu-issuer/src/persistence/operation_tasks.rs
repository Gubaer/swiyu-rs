use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use sqlx::postgres::PgConnection;

use crate::domain::{IssuerId, OperationTask, TaskId, TaskType, TenantId};

use super::PersistenceError;
use super::helpers::map_database_error;

pub async fn insert(conn: &mut PgConnection, task: &OperationTask) -> Result<(), PersistenceError> {
    sqlx::query(
        r#"
        INSERT INTO operation_tasks (
            id, tenant_id, task_type, state, step,
            attempts, next_attempt_at,
            error_code, error_message,
            input, state_data,
            result_issuer_id,
            created_at, updated_at, completed_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
        "#,
    )
    .bind(&task.id)
    .bind(&task.tenant_id)
    .bind(task.task_type)
    .bind(task.state)
    .bind(task.step.as_deref())
    .bind(task.attempts as i32)
    .bind(task.next_attempt_at)
    .bind(task.error_code.as_deref())
    .bind(task.error_message.as_deref())
    .bind(&task.input)
    .bind(&task.state_data)
    .bind(task.result_issuer_id.as_ref())
    .bind(task.created_at)
    .bind(task.updated_at)
    .bind(task.completed_at)
    .execute(conn)
    .await
    .map_err(map_database_error)?;
    Ok(())
}

pub async fn find_by_id(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    task_id: &TaskId,
) -> Result<OperationTask, PersistenceError> {
    sqlx::query_as::<_, OperationTask>(
        r#"
        SELECT id, tenant_id, task_type, state, step,
               attempts, next_attempt_at,
               error_code, error_message,
               input, state_data,
               result_issuer_id,
               created_at, updated_at, completed_at
        FROM operation_tasks
        WHERE id = $1 AND tenant_id = $2
        "#,
    )
    .bind(task_id)
    .bind(tenant_id)
    .fetch_optional(conn)
    .await?
    .ok_or(PersistenceError::NotFound)
}

/// Returns the most-recently-created task matching the
/// (tenant, issuer, task_type) triple, regardless of state.
///
/// Powers the idempotency lookup behind
/// `POST /api/v1/issuers/{id}/deactivate`: a duplicate submission
/// for the same issuer should return the existing task rather than
/// inserting a second one. The query orders by `created_at DESC`
/// and takes a single row, so an issuer that has been recreated
/// (theoretically — current rules do not allow that) and
/// re-deactivated would surface its newest deactivation task.
pub async fn find_latest_by_type_and_issuer(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    issuer_id: &IssuerId,
    task_type: TaskType,
) -> Result<Option<OperationTask>, PersistenceError> {
    sqlx::query_as::<_, OperationTask>(
        r#"
        SELECT id, tenant_id, task_type, state, step,
               attempts, next_attempt_at,
               error_code, error_message,
               input, state_data,
               result_issuer_id,
               created_at, updated_at, completed_at
        FROM operation_tasks
        WHERE tenant_id = $1
          AND result_issuer_id = $2
          AND task_type = $3
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .bind(issuer_id)
    .bind(task_type)
    .fetch_optional(conn)
    .await
    .map_err(PersistenceError::from)
}

/// Returns the next runnable task while holding a row-level lock on
/// it. The caller is expected to be inside a transaction; the lock
/// is released when that transaction commits or rolls back.
///
/// "Runnable" means state is `pending` or `in_progress` (the latter
/// covers tasks resumed after a worker crash and retries whose timer
/// has elapsed) and `next_attempt_at` is null or has already passed.
/// Returns `None` when there is nothing to run.
///
/// Uses `FOR UPDATE SKIP LOCKED` so concurrent workers see the
/// already-locked row as absent and pick the next eligible row
/// instead. Pair with [`try_acquire`][OperationTask::try_acquire] (to
/// mutate the in-memory aggregate) and [`set_acquired`] (to persist)
/// before committing the transaction.
pub async fn find_next_acquirable_for_update(
    conn: &mut PgConnection,
    now: DateTime<Utc>,
) -> Result<Option<OperationTask>, PersistenceError> {
    sqlx::query_as::<_, OperationTask>(
        r#"
        SELECT id, tenant_id, task_type, state, step,
               attempts, next_attempt_at,
               error_code, error_message,
               input, state_data,
               result_issuer_id,
               created_at, updated_at, completed_at
        FROM operation_tasks
        WHERE state IN ('pending', 'in_progress')
          AND (next_attempt_at IS NULL OR next_attempt_at <= $1)
        ORDER BY next_attempt_at NULLS FIRST, created_at
        LIMIT 1
        FOR UPDATE SKIP LOCKED
        "#,
    )
    .bind(now)
    .fetch_optional(conn)
    .await
    .map_err(PersistenceError::from)
}

/// Persists the post-[`try_acquire`][OperationTask::try_acquire]
/// columns of an [`OperationTask`]: `state`, `attempts`, and
/// `updated_at`. The caller controls the transaction; this helper
/// does not commit. Run inside the same transaction that called
/// [`find_next_acquirable_for_update`] so the row remains locked until
/// the UPDATE commits.
pub async fn set_acquired(
    conn: &mut PgConnection,
    task: &OperationTask,
) -> Result<(), PersistenceError> {
    let result = sqlx::query(
        r#"
        UPDATE operation_tasks
        SET state = $1,
            attempts = $2,
            updated_at = $3
        WHERE id = $4
        "#,
    )
    .bind(task.state)
    .bind(task.attempts as i32)
    .bind(task.updated_at)
    .bind(&task.id)
    .execute(conn)
    .await
    .map_err(map_database_error)?;

    if result.rows_affected() == 0 {
        return Err(PersistenceError::NotFound);
    }
    Ok(())
}

/// Records that the current step succeeded and advances to `next_step`.
///
/// Merges `state_data_patch` into the row's `state_data` JSONB and
/// resets `attempts` and the error fields. The merge is performed in
/// Rust: a top-level `Object` merge where keys in the patch overwrite
/// existing keys; values not in the patch are preserved.
pub async fn advance_step(
    conn: &mut PgConnection,
    task_id: &TaskId,
    next_step: Option<&str>,
    state_data_patch: &Map<String, Value>,
    now: DateTime<Utc>,
) -> Result<(), PersistenceError> {
    let current: Option<Value> =
        sqlx::query_scalar("SELECT state_data FROM operation_tasks WHERE id = $1")
            .bind(task_id)
            .fetch_optional(&mut *conn)
            .await?;

    let mut merged = match current {
        Some(Value::Object(map)) => map,
        Some(_) => Map::new(),
        None => return Err(PersistenceError::NotFound),
    };
    for (key, value) in state_data_patch {
        merged.insert(key.clone(), value.clone());
    }
    let merged_value = Value::Object(merged);

    let result = sqlx::query(
        r#"
        UPDATE operation_tasks
        SET step = $1,
            attempts = 0,
            next_attempt_at = NULL,
            error_code = NULL,
            error_message = NULL,
            state_data = $2,
            updated_at = $3
        WHERE id = $4
        "#,
    )
    .bind(next_step)
    .bind(&merged_value)
    .bind(now)
    .bind(task_id)
    .execute(&mut *conn)
    .await
    .map_err(map_database_error)?;

    if result.rows_affected() == 0 {
        return Err(PersistenceError::NotFound);
    }
    Ok(())
}

/// Records a retryable failure and schedules the next attempt.
///
/// Stores `next_attempt_at` and the operator-visible error pair; does
/// not change `attempts` or `state`. The state stays `in_progress`
/// for the duration of the retry window — the next worker poll picks
/// the row up via the `next_attempt_at <= now` filter and bumps
/// `attempts` through [`try_acquire`][OperationTask::try_acquire] /
/// [`set_acquired`].
pub async fn schedule_retry(
    conn: &mut PgConnection,
    task_id: &TaskId,
    next_attempt_at: DateTime<Utc>,
    error_code: &str,
    error_message: &str,
    now: DateTime<Utc>,
) -> Result<(), PersistenceError> {
    let result = sqlx::query(
        r#"
        UPDATE operation_tasks
        SET next_attempt_at = $1,
            error_code = $2,
            error_message = $3,
            updated_at = $4
        WHERE id = $5
        "#,
    )
    .bind(next_attempt_at)
    .bind(error_code)
    .bind(error_message)
    .bind(now)
    .bind(task_id)
    .execute(conn)
    .await
    .map_err(map_database_error)?;

    if result.rows_affected() == 0 {
        return Err(PersistenceError::NotFound);
    }
    Ok(())
}

/// Persists the terminal-state columns of an [`OperationTask`] whose
/// in-memory state has just been mutated by
/// [`try_complete`][OperationTask::try_complete] /
/// [`try_fail`][OperationTask::try_fail].
///
/// The caller controls the transaction; this helper does not commit.
/// Writes `state`, `next_attempt_at`, `error_code`, `error_message`,
/// `result_issuer_id`, `updated_at`, and `completed_at` from the
/// aggregate. The aggregate is the sole source of truth for the
/// transition's validity (the `state = 'in_progress'` SQL guard is
/// gone — [`try_complete`][OperationTask::try_complete] /
/// [`try_fail`][OperationTask::try_fail] enforce it in memory before
/// this is called).
pub async fn set_terminal_state(
    conn: &mut PgConnection,
    task: &OperationTask,
) -> Result<(), PersistenceError> {
    let result = sqlx::query(
        r#"
        UPDATE operation_tasks
        SET state = $1,
            next_attempt_at = $2,
            error_code = $3,
            error_message = $4,
            result_issuer_id = $5,
            updated_at = $6,
            completed_at = $7
        WHERE id = $8
        "#,
    )
    .bind(task.state)
    .bind(task.next_attempt_at)
    .bind(task.error_code.as_deref())
    .bind(task.error_message.as_deref())
    .bind(task.result_issuer_id.as_ref())
    .bind(task.updated_at)
    .bind(task.completed_at)
    .bind(&task.id)
    .execute(conn)
    .await
    .map_err(map_database_error)?;

    if result.rows_affected() == 0 {
        return Err(PersistenceError::NotFound);
    }
    Ok(())
}
