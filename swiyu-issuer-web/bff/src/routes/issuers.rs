use axum::Json;
use axum::extract::State;
use serde_json::Value;

use super::AppState;
use crate::error::AppError;

pub async fn list_issuers(State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    let payload = state.mgmt_api.list_issuers().await?;
    Ok(Json(payload))
}
