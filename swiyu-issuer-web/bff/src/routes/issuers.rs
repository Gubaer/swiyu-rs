use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde_json::Value;

use super::AppState;
use crate::error::AppError;

pub async fn list_issuers(State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    let payload = state.mgmt_api.list_issuers().await?;
    Ok(Json(payload))
}

pub async fn create_issuer(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let payload = state.mgmt_api.create_issuer(body).await?;
    Ok((StatusCode::CREATED, Json(payload)))
}

pub async fn get_issuer(
    State(state): State<AppState>,
    Path(issuer_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let payload = state.mgmt_api.get_issuer(&issuer_id).await?;
    Ok(Json(payload))
}
