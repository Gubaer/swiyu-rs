use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use sqlx::Row;
use sqlx::postgres::{PgConnection, PgRow};

use crate::domain::{IssuerId, OperationTask, TaskId, TaskState, TaskType, TenantId};

use super::PersistenceError;
use super::helpers::{integrity_from, map_database_error};

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
    .bind(task.id.bare())
    .bind(task.tenant_id.bare())
    .bind(task.task_type.as_str())
    .bind(task.state.as_str())
    .bind(task.step.as_deref())
    .bind(task.attempts as i32)
    .bind(task.next_attempt_at)
    .bind(task.error_code.as_deref())
    .bind(task.error_message.as_deref())
    .bind(&task.input)
    .bind(&task.state_data)
    .bind(task.result_issuer_id.as_ref().map(IssuerId::bare))
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
    let row = sqlx::query(
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
    .bind(task_id.bare())
    .bind(tenant_id.bare())
    .fetch_optional(conn)
    .await?
    .ok_or(PersistenceError::NotFound)?;

    row_to_task(&row)
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
    let row = sqlx::query(
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
    .bind(tenant_id.bare())
    .bind(issuer_id.bare())
    .bind(task_type.as_str())
    .fetch_optional(conn)
    .await?;

    row.as_ref().map(row_to_task).transpose()
}

/// Atomically picks the oldest runnable task and stamps it `in_progress`.
///
/// "Runnable" means state is `pending` or `in_progress` (the latter
/// covers tasks resumed after worker crash) and `next_attempt_at` is
/// null or has already passed. Returns `None` when there is nothing to
/// run. The query uses `FOR UPDATE SKIP LOCKED` so a future split into
/// multiple workers does not require schema or query changes.
pub async fn acquire_next(
    conn: &mut PgConnection,
    now: DateTime<Utc>,
) -> Result<Option<OperationTask>, PersistenceError> {
    let row = sqlx::query(
        r#"
        UPDATE operation_tasks
        SET state = 'in_progress',
            updated_at = $1
        WHERE id = (
            SELECT id FROM operation_tasks
            WHERE state IN ('pending', 'in_progress')
              AND (next_attempt_at IS NULL OR next_attempt_at <= $1)
            ORDER BY next_attempt_at NULLS FIRST, created_at
            LIMIT 1
            FOR UPDATE SKIP LOCKED
        )
        RETURNING id, tenant_id, task_type, state, step,
                  attempts, next_attempt_at,
                  error_code, error_message,
                  input, state_data,
                  result_issuer_id,
                  created_at, updated_at, completed_at
        "#,
    )
    .bind(now)
    .fetch_optional(conn)
    .await?;

    row.as_ref().map(row_to_task).transpose()
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
            .bind(task_id.bare())
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
    .bind(task_id.bare())
    .execute(&mut *conn)
    .await
    .map_err(map_database_error)?;

    if result.rows_affected() == 0 {
        return Err(PersistenceError::NotFound);
    }
    Ok(())
}

/// Records a retryable failure and schedules the next attempt.
pub async fn schedule_retry(
    conn: &mut PgConnection,
    task_id: &TaskId,
    attempts: u32,
    next_attempt_at: DateTime<Utc>,
    error_code: &str,
    error_message: &str,
    now: DateTime<Utc>,
) -> Result<(), PersistenceError> {
    let result = sqlx::query(
        r#"
        UPDATE operation_tasks
        SET attempts = $1,
            next_attempt_at = $2,
            error_code = $3,
            error_message = $4,
            updated_at = $5
        WHERE id = $6
        "#,
    )
    .bind(attempts as i32)
    .bind(next_attempt_at)
    .bind(error_code)
    .bind(error_message)
    .bind(now)
    .bind(task_id.bare())
    .execute(conn)
    .await
    .map_err(map_database_error)?;

    if result.rows_affected() == 0 {
        return Err(PersistenceError::NotFound);
    }
    Ok(())
}

/// Marks the task as terminally failed.
pub async fn mark_failed(
    conn: &mut PgConnection,
    task_id: &TaskId,
    error_code: &str,
    error_message: &str,
    now: DateTime<Utc>,
) -> Result<(), PersistenceError> {
    let result = sqlx::query(
        r#"
        UPDATE operation_tasks
        SET state = 'failed',
            next_attempt_at = NULL,
            error_code = $1,
            error_message = $2,
            updated_at = $3,
            completed_at = $3
        WHERE id = $4
        "#,
    )
    .bind(error_code)
    .bind(error_message)
    .bind(now)
    .bind(task_id.bare())
    .execute(conn)
    .await
    .map_err(map_database_error)?;

    if result.rows_affected() == 0 {
        return Err(PersistenceError::NotFound);
    }
    Ok(())
}

/// Marks the task as terminally successful.
pub async fn mark_completed(
    conn: &mut PgConnection,
    task_id: &TaskId,
    result_issuer_id: Option<&IssuerId>,
    now: DateTime<Utc>,
) -> Result<(), PersistenceError> {
    let result = sqlx::query(
        r#"
        UPDATE operation_tasks
        SET state = 'completed',
            next_attempt_at = NULL,
            error_code = NULL,
            error_message = NULL,
            result_issuer_id = $1,
            updated_at = $2,
            completed_at = $2
        WHERE id = $3
        "#,
    )
    .bind(result_issuer_id.map(IssuerId::bare))
    .bind(now)
    .bind(task_id.bare())
    .execute(conn)
    .await
    .map_err(map_database_error)?;

    if result.rows_affected() == 0 {
        return Err(PersistenceError::NotFound);
    }
    Ok(())
}

fn row_to_task(row: &PgRow) -> Result<OperationTask, PersistenceError> {
    let id: String = row.try_get("id")?;
    let tenant_id: String = row.try_get("tenant_id")?;
    let task_type: String = row.try_get("task_type")?;
    let state: String = row.try_get("state")?;
    let step: Option<String> = row.try_get("step")?;
    let attempts: i32 = row.try_get("attempts")?;
    let next_attempt_at: Option<DateTime<Utc>> = row.try_get("next_attempt_at")?;
    let error_code: Option<String> = row.try_get("error_code")?;
    let error_message: Option<String> = row.try_get("error_message")?;
    let input: Value = row.try_get("input")?;
    let state_data: Value = row.try_get("state_data")?;
    let result_issuer_id: Option<String> = row.try_get("result_issuer_id")?;
    let created_at: DateTime<Utc> = row.try_get("created_at")?;
    let updated_at: DateTime<Utc> = row.try_get("updated_at")?;
    let completed_at: Option<DateTime<Utc>> = row.try_get("completed_at")?;

    Ok(OperationTask {
        id: TaskId::from_bare(id).map_err(integrity_from)?,
        tenant_id: TenantId::from_bare(tenant_id).map_err(integrity_from)?,
        task_type: TaskType::try_from(task_type.as_str()).map_err(integrity_from)?,
        state: TaskState::try_from(state.as_str()).map_err(integrity_from)?,
        step,
        attempts: attempts.max(0) as u32,
        next_attempt_at,
        error_code,
        error_message,
        input,
        state_data,
        result_issuer_id: result_issuer_id
            .map(IssuerId::from_bare)
            .transpose()
            .map_err(integrity_from)?,
        created_at,
        updated_at,
        completed_at,
    })
}
