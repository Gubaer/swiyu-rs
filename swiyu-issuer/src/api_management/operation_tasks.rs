//! HTTP handlers for the operation-task polling endpoints.

use axum::Json;
use axum::extract::{Path, State};

use crate::domain::{OperationTask, TaskId};
use crate::persistence;

use super::AppState;
use super::auth::TenantContext;
use super::dto::GetOperationTaskResponse;
use super::error::ApiError;

pub async fn get(
    State(state): State<AppState>,
    Path(task_id_str): Path<String>,
    tenant_context: TenantContext,
) -> Result<Json<GetOperationTaskResponse>, ApiError> {
    tracing::debug!(
        tenant_id = %tenant_context.tenant_id,
        task_id = %task_id_str,
        "operation task fetch requested",
    );

    let task_id = TaskId::from_bare(&task_id_str).map_err(|err| ApiError::InvalidInput {
        details: format!("task_id path parameter: {err}"),
    })?;

    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;

    // Persistence layer's tenant-scoped find_by_id collapses both
    // "no such task" and "wrong tenant" to NotFound, which the
    // From<PersistenceError> impl maps to ApiError::NotFound.
    let task =
        persistence::operation_tasks::find_by_id(&mut conn, &tenant_context.tenant_id, &task_id)
            .await?;

    Ok(Json(task_to_response(task)))
}

fn task_to_response(task: OperationTask) -> GetOperationTaskResponse {
    GetOperationTaskResponse {
        id: task.id.to_string(),
        task_type: task.task_type.as_str().to_string(),
        state: task.state.as_str().to_string(),
        step: task.step,
        attempts: task.attempts,
        next_attempt_at: task.next_attempt_at,
        error_code: task.error_code,
        error_message: task.error_message,
        created_at: task.created_at,
        updated_at: task.updated_at,
        completed_at: task.completed_at,
    }
}
