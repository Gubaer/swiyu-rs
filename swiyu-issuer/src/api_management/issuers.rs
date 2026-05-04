//! HTTP handlers for the issuer-management endpoints.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use chrono::Utc;
use serde_json::json;

use crate::domain::{IssuerId, OperationTask, TaskId, TaskState, TaskType};
use crate::persistence;

use super::AppState;
use super::auth::TenantContext;
use super::dto::{CreateIssuerResponse, CreateIssuerSubmission};
use super::error::ApiError;

/// Maximum byte length applied to BA-supplied free-text fields after
/// trim. The columns are TEXT-unbounded; the cap exists for API
/// hygiene only — long values would surface in operator UIs and
/// search results unwieldily.
const MAX_FIELD_LENGTH: usize = 255;

pub async fn create(
    State(state): State<AppState>,
    tenant_context: TenantContext,
    Json(payload): Json<CreateIssuerSubmission>,
) -> Result<(StatusCode, Json<CreateIssuerResponse>), ApiError> {
    tracing::debug!(
        tenant_id = %tenant_context.tenant_id,
        "create-issuer task submission",
    );

    let description = normalise_optional_field("description", payload.description.as_deref())?;
    let supplied_display_name =
        normalise_optional_field("display_name", payload.display_name.as_deref())?;

    let issuer_id = IssuerId::generate();
    // The default display name uses the bare issuer id so each
    // auto-named issuer is identifiable in admin lists. Operators
    // can rename later via a future PATCH endpoint.
    let display_name =
        supplied_display_name.unwrap_or_else(|| format!("Issuer {}", issuer_id.bare()));
    let description = description.unwrap_or_default();
    let task_id = TaskId::generate();
    let now = Utc::now();
    let task = OperationTask {
        id: task_id.clone(),
        tenant_id: tenant_context.tenant_id.clone(),
        task_type: TaskType::CreateIssuer,
        state: TaskState::Pending,
        step: None,
        attempts: 0,
        next_attempt_at: None,
        error_code: None,
        error_message: None,
        // Re-emit the trimmed values rather than the raw payload so
        // the worker reads the same canonical form the validation
        // checks blessed.
        input: json!({
            "description": description,
            "display_name": display_name,
        }),
        state_data: json!({}),
        result_issuer_id: Some(issuer_id.clone()),
        created_at: now,
        updated_at: now,
        completed_at: None,
    };

    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;
    persistence::operation_tasks::insert(&mut conn, &task).await?;

    Ok((
        StatusCode::CREATED,
        Json(CreateIssuerResponse {
            task_id: task_id.to_string(),
            issuer_id: issuer_id.to_string(),
        }),
    ))
}

/// Trims and length-checks an optional BA-supplied field.
///
/// Returns `None` when the field is missing or trims to empty (the
/// caller substitutes a default in that case). `Some(trimmed)` is
/// returned when the field has content; oversized values surface as
/// `InvalidInput`.
fn normalise_optional_field(
    name: &'static str,
    raw: Option<&str>,
) -> Result<Option<String>, ApiError> {
    let Some(value) = raw else {
        return Ok(None);
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.len() > MAX_FIELD_LENGTH {
        return Err(ApiError::InvalidInput {
            details: format!(
                "{name} must be at most {MAX_FIELD_LENGTH} bytes (got {})",
                trimmed.len()
            ),
        });
    }
    Ok(Some(trimmed.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalise_returns_none_for_missing_field() {
        let v = normalise_optional_field("description", None).unwrap();
        assert!(v.is_none());
    }

    #[test]
    fn normalise_returns_none_for_blank_field() {
        let v = normalise_optional_field("description", Some("   \t\n")).unwrap();
        assert!(v.is_none());
    }

    #[test]
    fn normalise_trims_whitespace_when_content_present() {
        let v = normalise_optional_field("description", Some("  Padded text  \n")).unwrap();
        assert_eq!(v.as_deref(), Some("Padded text"));
    }

    #[test]
    fn normalise_rejects_oversized_after_trim() {
        let too_long = "a".repeat(MAX_FIELD_LENGTH + 1);
        let err = normalise_optional_field("display_name", Some(&too_long)).unwrap_err();
        match err {
            ApiError::InvalidInput { details } => {
                assert!(details.contains("display_name"));
                assert!(details.contains("at most"));
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn normalise_accepts_at_max_length() {
        let exact = "a".repeat(MAX_FIELD_LENGTH);
        let v = normalise_optional_field("description", Some(&exact)).unwrap();
        assert_eq!(v.unwrap().len(), MAX_FIELD_LENGTH);
    }
}
