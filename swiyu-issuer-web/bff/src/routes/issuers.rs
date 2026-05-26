use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde_json::{Value, json};
use swiyu_core::did::DID;
use swiyu_core::didlog::DIDLogEntry;

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

pub async fn deactivate_issuer(
    State(state): State<AppState>,
    Path(issuer_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let payload = state.mgmt_api.deactivate_issuer(&issuer_id).await?;
    Ok(Json(payload))
}

pub async fn rotate_keys(
    State(state): State<AppState>,
    Path(issuer_id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let payload = state.mgmt_api.rotate_keys(&issuer_id, body).await?;
    Ok(Json(payload))
}

pub async fn get_did_log(
    State(state): State<AppState>,
    Path(issuer_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let issuer = state.mgmt_api.get_issuer(&issuer_id).await?;
    let did_str = issuer
        .get("did")
        .and_then(Value::as_str)
        .ok_or(AppError::MissingDid)?;
    let did: DID = did_str.parse().map_err(|_| AppError::InvalidDid)?;

    let log_text = state.identifier_registry.fetch_log(&did).await?;
    let entries = parse_did_log(&log_text)?;
    Ok(Json(json!({ "entries": entries })))
}

// Turns the raw JSONL DID log into the per-version rows the SPA renders.
// The `deactivated` flag is cumulative: once an entry sets it, the DID stays
// deactivated for every later version. Each row keeps the entry's raw JSON so
// the SPA can show it verbatim without a second fetch.
fn parse_did_log(text: &str) -> Result<Vec<Value>, AppError> {
    let mut rows = Vec::new();
    let mut deactivated = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(trimmed).map_err(|_| AppError::InvalidDidLog)?;
        let entry = DIDLogEntry::try_from(&value).map_err(|_| AppError::InvalidDidLog)?;
        if entry.parameters().deactivated() == Some(true) {
            deactivated = true;
        }
        rows.push(json!({
            "version": version_number(entry.version_id()),
            "versionId": entry.version_id(),
            "versionTime": entry.version_time(),
            "deactivated": deactivated,
            "entry": value,
        }));
    }
    Ok(rows)
}

// did:tdw/did:webvh version ids are `<number>-<hash>`; surface the number.
fn version_number(version_id: &str) -> Option<u64> {
    version_id.split('-').next().and_then(|s| s.parse().ok())
}
