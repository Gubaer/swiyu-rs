use axum::Json;
use axum::extract::{Path, State};
use serde_json::Value;

use super::AppState;
use crate::error::AppError;

pub async fn list_credential_types(
    State(state): State<AppState>,
    Path(issuer_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let payload = state.mgmt_api.list_credential_types(&issuer_id).await?;
    Ok(Json(payload))
}

pub async fn get_credential_type_schema(
    State(state): State<AppState>,
    Path(credential_type_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let payload = state
        .mgmt_api
        .get_credential_type_schema(&credential_type_id)
        .await?;
    Ok(Json(payload))
}
