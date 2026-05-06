//! HTTP handlers for the issuer-management endpoints.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use chrono::Utc;
use serde_json::json;

use crate::domain::{Issuer, IssuerId, IssuerState, OperationTask, TaskId, TaskState, TaskType};
use crate::persistence;
use crate::persistence::issuers::ListPageQuery;
use crate::worker::rotate_keys::RotateKeysInput;

use super::AppState;
use super::auth::TenantContext;
use super::dto::{
    CreateIssuerResponse, CreateIssuerSubmission, DeactivateIssuerResponse, GetIssuerResponse,
    ListIssuersQuery, ListIssuersResponse, RotateKeysResponse,
};
use super::error::ApiError;

/// Maximum byte length applied to BA-supplied free-text fields after
/// trim. The columns are TEXT-unbounded; the cap exists for API
/// hygiene only — long values would surface in operator UIs and
/// search results unwieldily.
const MAX_FIELD_LENGTH: usize = 255;

/// Page size applied to `GET /api/v1/issuers` when the caller omits
/// `limit`. Sized to fit a typical operator UI page without forcing a
/// follow-up request for tenants with a handful of issuers.
const DEFAULT_LIST_LIMIT: u32 = 25;

/// Lower bound on `limit`. Zero would return an empty page with a
/// `next_cursor` that never advances, so the smallest legal page is
/// one row.
const MIN_LIST_LIMIT: u32 = 1;

/// Upper bound on `limit`. Caps per-request work against the
/// database and the JSON response size; clients that need more rows
/// must paginate.
const MAX_LIST_LIMIT: u32 = 100;

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
            task_id: task_id.bare().to_string(),
            issuer_id: issuer_id.bare().to_string(),
        }),
    ))
}

pub async fn get(
    State(state): State<AppState>,
    Path(issuer_id_str): Path<String>,
    tenant_context: TenantContext,
) -> Result<Json<GetIssuerResponse>, ApiError> {
    tracing::debug!(
        tenant_id = %tenant_context.tenant_id,
        issuer_id = %issuer_id_str,
        "issuer fetch requested",
    );

    let issuer_id = IssuerId::from_bare(&issuer_id_str).map_err(|err| ApiError::InvalidInput {
        details: format!("issuer_id path parameter: {err}"),
    })?;

    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;

    let issuer = persistence::issuers::find_by_id_for_tenant(
        &mut conn,
        &tenant_context.tenant_id,
        &issuer_id,
    )
    .await?
    .ok_or(ApiError::NotFound)?;

    Ok(Json(issuer_to_response(issuer)?))
}

pub async fn deactivate(
    State(state): State<AppState>,
    Path(issuer_id_str): Path<String>,
    tenant_context: TenantContext,
) -> Result<(StatusCode, Json<DeactivateIssuerResponse>), ApiError> {
    tracing::debug!(
        tenant_id = %tenant_context.tenant_id,
        issuer_id = %issuer_id_str,
        "deactivate-issuer task submission",
    );

    let issuer_id = IssuerId::from_bare(&issuer_id_str).map_err(|err| ApiError::InvalidInput {
        details: format!("issuer_id path parameter: {err}"),
    })?;

    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;

    let issuer = persistence::issuers::find_by_id_for_tenant(
        &mut conn,
        &tenant_context.tenant_id,
        &issuer_id,
    )
    .await?
    .ok_or(ApiError::NotFound)?;

    // Hide the seeded legacy row (state == None) the same way GET
    // and DELETE do — it predates the issuer-management flow and
    // has no Authorized key the saga could sign with.
    let issuer_state = issuer.state.ok_or(ApiError::NotFound)?;

    let existing = persistence::operation_tasks::find_latest_by_type_and_issuer(
        &mut conn,
        &tenant_context.tenant_id,
        &issuer_id,
        TaskType::DeactivateIssuer,
    )
    .await?;

    match (issuer_state, existing) {
        // Already deactivated, with a task row to attribute it to.
        (IssuerState::Deactivated, Some(task)) => Ok((
            StatusCode::OK,
            Json(DeactivateIssuerResponse {
                task_id: Some(task.id.bare().to_string()),
                issuer_id: issuer_id.bare().to_string(),
            }),
        )),
        // Already deactivated, no task row (directly-mutated fixture).
        (IssuerState::Deactivated, None) => Ok((
            StatusCode::OK,
            Json(DeactivateIssuerResponse {
                task_id: None,
                issuer_id: issuer_id.bare().to_string(),
            }),
        )),
        // Active and a deactivation task is already in flight — return
        // the existing task_id so the caller can keep polling. Treat a
        // duplicate submission as a poll-handle request, not a new
        // task.
        (IssuerState::Active, Some(task))
            if matches!(task.state, TaskState::Pending | TaskState::InProgress) =>
        {
            Ok((
                StatusCode::OK,
                Json(DeactivateIssuerResponse {
                    task_id: Some(task.id.bare().to_string()),
                    issuer_id: issuer_id.bare().to_string(),
                }),
            ))
        }
        // Active and either no prior task, or only a Failed/Completed
        // one (Completed against an Active issuer is anomalous and
        // shouldn't happen under normal saga semantics, but we treat
        // it the same as "no relevant task" — the BA wants the issuer
        // deactivated, so submit a fresh attempt). Insert a new task.
        (IssuerState::Active, _) => {
            let task_id = TaskId::generate();
            let now = Utc::now();
            let task = OperationTask {
                id: task_id.clone(),
                tenant_id: tenant_context.tenant_id.clone(),
                task_type: TaskType::DeactivateIssuer,
                state: TaskState::Pending,
                step: None,
                attempts: 0,
                next_attempt_at: None,
                error_code: None,
                error_message: None,
                input: json!({}),
                state_data: json!({}),
                result_issuer_id: Some(issuer_id.clone()),
                created_at: now,
                updated_at: now,
                completed_at: None,
            };
            persistence::operation_tasks::insert(&mut conn, &task).await?;
            Ok((
                StatusCode::CREATED,
                Json(DeactivateIssuerResponse {
                    task_id: Some(task_id.bare().to_string()),
                    issuer_id: issuer_id.bare().to_string(),
                }),
            ))
        }
    }
}

pub async fn rotate_keys(
    State(state): State<AppState>,
    Path(issuer_id_str): Path<String>,
    tenant_context: TenantContext,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<RotateKeysResponse>), ApiError> {
    // Parse the body into the typed input here (rather than via the
    // Json<RotateKeysInput> extractor) so a malformed body or an
    // invalid `roles` array surfaces as 400 invalid_input rather
    // than axum's default 422 for typed-extractor failures.
    let input: RotateKeysInput =
        serde_json::from_value(body).map_err(|err| ApiError::InvalidInput {
            details: err.to_string(),
        })?;

    tracing::debug!(
        tenant_id = %tenant_context.tenant_id,
        issuer_id = %issuer_id_str,
        roles = ?input.roles,
        "rotate-keys task submission",
    );

    let issuer_id = IssuerId::from_bare(&issuer_id_str).map_err(|err| ApiError::InvalidInput {
        details: format!("issuer_id path parameter: {err}"),
    })?;

    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;

    let issuer = persistence::issuers::find_by_id_for_tenant(
        &mut conn,
        &tenant_context.tenant_id,
        &issuer_id,
    )
    .await?
    .ok_or(ApiError::NotFound)?;

    let issuer_state = issuer.state.ok_or(ApiError::NotFound)?;
    if issuer_state == IssuerState::Deactivated {
        return Err(ApiError::Conflict {
            details: "rotation is not permitted on a deactivated issuer".into(),
        });
    }

    // Saga-resume / poll-handle behaviour: if a rotate-keys task is
    // already in flight for this issuer, return its task_id with
    // 200 instead of inserting a duplicate. Terminal prior tasks
    // (Failed / Completed) fall through to a fresh insert —
    // rotation is repeatable.
    if let Some(existing) = persistence::operation_tasks::find_latest_by_type_and_issuer(
        &mut conn,
        &tenant_context.tenant_id,
        &issuer_id,
        TaskType::RotateKeys,
    )
    .await?
        && matches!(existing.state, TaskState::Pending | TaskState::InProgress)
    {
        return Ok((
            StatusCode::OK,
            Json(RotateKeysResponse {
                task_id: existing.id.bare().to_string(),
                issuer_id: issuer_id.bare().to_string(),
            }),
        ));
    }

    let task_id = TaskId::generate();
    let now = Utc::now();
    let task = OperationTask {
        id: task_id.clone(),
        tenant_id: tenant_context.tenant_id.clone(),
        task_type: TaskType::RotateKeys,
        state: TaskState::Pending,
        step: None,
        attempts: 0,
        next_attempt_at: None,
        error_code: None,
        error_message: None,
        // Re-emit the deserialised input — `"all"` has already been
        // expanded to the concrete role set, so the persisted task
        // never carries the sentinel.
        input: serde_json::to_value(&input).map_err(|err| ApiError::Internal(Box::new(err)))?,
        state_data: json!({}),
        result_issuer_id: Some(issuer_id.clone()),
        created_at: now,
        updated_at: now,
        completed_at: None,
    };
    persistence::operation_tasks::insert(&mut conn, &task).await?;

    Ok((
        StatusCode::CREATED,
        Json(RotateKeysResponse {
            task_id: task_id.bare().to_string(),
            issuer_id: issuer_id.bare().to_string(),
        }),
    ))
}

pub async fn list(
    State(state): State<AppState>,
    Query(query): Query<ListIssuersQuery>,
    tenant_context: TenantContext,
) -> Result<Json<ListIssuersResponse>, ApiError> {
    tracing::debug!(
        tenant_id = %tenant_context.tenant_id,
        limit = ?query.limit,
        cursor_present = query.cursor.is_some(),
        "issuer list requested",
    );

    let limit = resolve_list_limit(query.limit)?;
    let decoded_cursor = query
        .cursor
        .as_deref()
        .map(|raw| super::cursor::decode(raw, |bare| IssuerId::from_bare(bare).map(|_| ())))
        .transpose()?;

    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;

    let page = persistence::issuers::list(
        &mut conn,
        &tenant_context.tenant_id,
        ListPageQuery {
            cursor: decoded_cursor.map(|c| (c.timestamp, c.bare_id)),
            limit,
        },
    )
    .await?;

    let next_cursor = if page.has_more {
        page.items
            .last()
            .map(|issuer| super::cursor::encode(issuer.created_at, issuer.id.bare()))
    } else {
        None
    };

    let items = page
        .items
        .into_iter()
        .map(issuer_to_response)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Json(ListIssuersResponse { items, next_cursor }))
}

fn resolve_list_limit(requested: Option<u32>) -> Result<u32, ApiError> {
    let limit = requested.unwrap_or(DEFAULT_LIST_LIMIT);
    if !(MIN_LIST_LIMIT..=MAX_LIST_LIMIT).contains(&limit) {
        return Err(ApiError::InvalidInput {
            details: format!(
                "limit must be between {MIN_LIST_LIMIT} and {MAX_LIST_LIMIT}, got {limit}"
            ),
        });
    }
    Ok(limit)
}

/// Projects an `Issuer` to its BA-facing wire DTO.
///
/// Returns `ApiError::NotFound` for the seeded legacy row (state ==
/// None): that row pre-dates the issuer-management flow and is not
/// part of the v1 surface, so we hide it the same way we hide
/// cross-tenant rows. Any other issuer was written by
/// `worker::create_issuer::persist_issuer`, which always sets the
/// fields the response needs, so the remaining unwraps are safe by
/// construction — a `None` here would mean the DB row is corrupt
/// and an internal error response is appropriate.
fn issuer_to_response(issuer: Issuer) -> Result<GetIssuerResponse, ApiError> {
    let state = issuer.state.ok_or(ApiError::NotFound)?;
    let description = issuer.description.ok_or_else(|| internal("description"))?;
    let display_name = issuer
        .display_name
        .ok_or_else(|| internal("display_name"))?;

    Ok(GetIssuerResponse {
        id: issuer.id.bare().to_string(),
        did: issuer.did,
        state: state.as_str().to_string(),
        description,
        display_name,
    })
}

fn internal(field: &'static str) -> ApiError {
    ApiError::Internal(Box::new(std::io::Error::other(format!(
        "issuer row missing BA-facing field `{field}`"
    ))))
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

    #[test]
    fn resolve_list_limit_uses_default_when_unset() {
        assert_eq!(resolve_list_limit(None).unwrap(), DEFAULT_LIST_LIMIT);
    }

    #[test]
    fn resolve_list_limit_accepts_value_in_range() {
        assert_eq!(resolve_list_limit(Some(50)).unwrap(), 50);
        assert_eq!(
            resolve_list_limit(Some(MIN_LIST_LIMIT)).unwrap(),
            MIN_LIST_LIMIT
        );
        assert_eq!(
            resolve_list_limit(Some(MAX_LIST_LIMIT)).unwrap(),
            MAX_LIST_LIMIT
        );
    }

    #[test]
    fn resolve_list_limit_rejects_zero() {
        assert!(resolve_list_limit(Some(0)).is_err());
    }

    #[test]
    fn resolve_list_limit_rejects_above_max() {
        assert!(resolve_list_limit(Some(MAX_LIST_LIMIT + 1)).is_err());
    }
}
