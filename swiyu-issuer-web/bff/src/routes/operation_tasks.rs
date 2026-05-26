use axum::Json;
use axum::extract::{Path, State};
use serde_json::Value;

use super::AppState;
use crate::error::AppError;

pub async fn get_task(
    State(state): State<AppState>,
    Path(task_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let payload = state.mgmt_api.get_operation_task(&task_id).await?;
    Ok(Json(payload))
}
