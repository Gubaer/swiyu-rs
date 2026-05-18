// HTTP handlers for the credential-type CRUD endpoints.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::{Duration, Utc};
use serde_json::Value;

use crate::domain::{
    CredentialType, CredentialTypeId, IssuerCredentialTypeAssignment, RevocationMode,
};
use crate::persistence;
use crate::persistence::credential_types::{ListPageQuery, StructuredUpdate, UpdateOutcome};
use crate::persistence::issuer_credential_types::AssignOutcome;

use super::AppState;
use super::auth::TenantContext;
use super::dto::{
    AssignmentResponse, CreateCredentialTypeRequest, CreateCredentialTypeResponse,
    GetCredentialTypeResponse, ListAssignedCredentialTypesResponse, ListCredentialTypesQuery,
    ListCredentialTypesResponse, PatchCredentialTypeRequest, RetireCredentialTypeResponse,
};
use super::error::ApiError;

// Cap on BA-supplied free-text fields after trim. The columns are
// TEXT-unbounded; the cap exists for API hygiene only.
const MAX_FIELD_LENGTH: usize = 1024;

// One second is the smallest useful validity; zero almost certainly
// indicates a client bug.
const MIN_VALIDITY_SECONDS: u64 = 1;

// ~317 years. Safely fits `chrono::Duration` and is far past any
// sensible credential lifetime.
const MAX_VALIDITY_SECONDS: u64 = 10_000_000_000;

pub async fn create(
    State(state): State<AppState>,
    tenant_context: TenantContext,
    Json(payload): Json<CreateCredentialTypeRequest>,
) -> Result<(StatusCode, Json<CreateCredentialTypeResponse>), ApiError> {
    tracing::debug!(
        tenant_id = %tenant_context.tenant_id,
        vct = %payload.vct,
        "credential-type create",
    );

    let vct = super::normalise_required("vct", &payload.vct, MAX_FIELD_LENGTH)?;
    let internal_description = super::normalise_optional(
        "internal_description",
        payload.internal_description.as_deref(),
        MAX_FIELD_LENGTH,
    )?;
    let claim_schema_source_url = super::normalise_optional(
        "claim_schema_source_url",
        payload.claim_schema_source_url.as_deref(),
        MAX_FIELD_LENGTH,
    )?;
    let seconds = payload.default_validity_seconds;
    if !(MIN_VALIDITY_SECONDS..=MAX_VALIDITY_SECONDS).contains(&seconds) {
        return Err(ApiError::InvalidInput {
            details: format!(
                "default_validity_seconds must be between {MIN_VALIDITY_SECONDS} and {MAX_VALIDITY_SECONDS}, got {seconds}"
            ),
        });
    }
    let default_validity =
        Duration::try_seconds(seconds as i64).ok_or_else(|| ApiError::InvalidInput {
            details: "default_validity_seconds out of range for chrono::Duration".into(),
        })?;
    let revocation_mode =
        RevocationMode::try_from(payload.revocation_mode.as_str()).map_err(|err| {
            ApiError::InvalidInput {
                details: format!("revocation_mode: {err}"),
            }
        })?;
    let display = validate_display(payload.display.unwrap_or_else(|| serde_json::json!([])))?;
    let claims = validate_claims(payload.claims.unwrap_or_else(|| serde_json::json!({})))?;

    // Compile the claim schema before inserting so an invalid
    // document surfaces as 400 with the compiler's error.
    jsonschema::validator_for(&payload.claim_schema).map_err(|err| ApiError::InvalidInput {
        details: format!("claim_schema does not compile: {err}"),
    })?;

    let credential_type = CredentialType::new(
        tenant_context.tenant_id.clone(),
        vct,
        display,
        internal_description,
        payload.claim_schema,
        claims,
        default_validity,
        revocation_mode,
    );
    let credential_type = CredentialType {
        claim_schema_source_url,
        ..credential_type
    };

    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;
    persistence::credential_types::insert(&mut conn, &credential_type).await?;

    Ok((
        StatusCode::CREATED,
        Json(CreateCredentialTypeResponse {
            credential_type_id: credential_type.id.bare().to_string(),
        }),
    ))
}

pub async fn get(
    State(state): State<AppState>,
    Path(id_str): Path<String>,
    tenant_context: TenantContext,
) -> Result<Json<GetCredentialTypeResponse>, ApiError> {
    let id = super::parse_credential_type_id(&id_str)?;

    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;
    let row = persistence::credential_types::find_by_id_for_tenant(
        &mut conn,
        &tenant_context.tenant_id,
        &id,
    )
    .await?
    .ok_or(ApiError::NotFound)?;

    Ok(Json(row.into()))
}

pub async fn list(
    State(state): State<AppState>,
    Query(query): Query<ListCredentialTypesQuery>,
    tenant_context: TenantContext,
) -> Result<Json<ListCredentialTypesResponse>, ApiError> {
    let limit = super::resolve_list_limit(query.limit)?;
    let decoded_cursor = query
        .cursor
        .as_deref()
        .map(|raw| super::cursor::decode(raw, |bare| CredentialTypeId::from_bare(bare).map(|_| ())))
        .transpose()?;

    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;

    let page = persistence::credential_types::list(
        &mut conn,
        &tenant_context.tenant_id,
        ListPageQuery {
            cursor: decoded_cursor.map(|c| (c.timestamp, c.bare_id)),
            limit,
            include_retired: query.retired,
        },
    )
    .await?;

    let next_cursor = if page.has_more {
        page.items
            .last()
            .map(|ct| super::cursor::encode(ct.created_at, ct.id.bare()))
    } else {
        None
    };

    let items = page.items.into_iter().map(Into::into).collect();
    Ok(Json(ListCredentialTypesResponse { items, next_cursor }))
}

pub async fn patch(
    State(state): State<AppState>,
    Path(id_str): Path<String>,
    tenant_context: TenantContext,
    Json(payload): Json<PatchCredentialTypeRequest>,
) -> Result<Json<GetCredentialTypeResponse>, ApiError> {
    let id = super::parse_credential_type_id(&id_str)?;

    let vct = payload
        .vct
        .as_deref()
        .map(|raw| super::normalise_required("vct", raw, MAX_FIELD_LENGTH))
        .transpose()?;
    let internal_description = payload
        .internal_description
        .as_deref()
        .map(|raw| super::normalise_required("internal_description", raw, MAX_FIELD_LENGTH))
        .transpose()?;
    let claim_schema_source_url = payload
        .claim_schema_source_url
        .as_deref()
        .map(|raw| super::normalise_required("claim_schema_source_url", raw, MAX_FIELD_LENGTH))
        .transpose()?;
    let default_validity = match payload.default_validity_seconds {
        Some(seconds) => {
            if !(MIN_VALIDITY_SECONDS..=MAX_VALIDITY_SECONDS).contains(&seconds) {
                return Err(ApiError::InvalidInput {
                    details: format!(
                        "default_validity_seconds must be between {MIN_VALIDITY_SECONDS} and {MAX_VALIDITY_SECONDS}, got {seconds}"
                    ),
                });
            }
            Some(
                Duration::try_seconds(seconds as i64).ok_or_else(|| ApiError::InvalidInput {
                    details: "default_validity_seconds out of range for chrono::Duration".into(),
                })?,
            )
        }
        None => None,
    };
    let revocation_mode = payload
        .revocation_mode
        .as_deref()
        .map(|raw| {
            RevocationMode::try_from(raw).map_err(|err| ApiError::InvalidInput {
                details: format!("revocation_mode: {err}"),
            })
        })
        .transpose()?;

    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;

    let outcome = persistence::credential_types::update_structured(
        &mut conn,
        &tenant_context.tenant_id,
        &id,
        StructuredUpdate {
            vct: vct.as_deref(),
            internal_description: internal_description.as_deref(),
            claim_schema_source_url: claim_schema_source_url.as_deref(),
            default_validity_duration: default_validity,
            revocation_mode,
        },
    )
    .await?;

    if outcome == UpdateOutcome::NotFound {
        return Err(ApiError::NotFound);
    }

    let row = persistence::credential_types::find_by_id_for_tenant(
        &mut conn,
        &tenant_context.tenant_id,
        &id,
    )
    .await?
    .ok_or(ApiError::NotFound)?;
    Ok(Json(row.into()))
}

pub async fn retire(
    State(state): State<AppState>,
    Path(id_str): Path<String>,
    tenant_context: TenantContext,
) -> Result<Json<RetireCredentialTypeResponse>, ApiError> {
    let id = super::parse_credential_type_id(&id_str)?;
    let now = Utc::now();

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;

    let outcome =
        persistence::credential_types::retire(&mut tx, &tenant_context.tenant_id, &id, now).await?;
    if outcome == UpdateOutcome::NotFound {
        return Err(ApiError::NotFound);
    }
    tx.commit()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;

    Ok(Json(RetireCredentialTypeResponse {
        credential_type_id: id.bare().to_string(),
        retired_at: now,
    }))
}

pub async fn assign(
    State(state): State<AppState>,
    Path((issuer_id_str, credential_type_id_str)): Path<(String, String)>,
    tenant_context: TenantContext,
) -> Result<(StatusCode, Json<AssignmentResponse>), ApiError> {
    let issuer_id = super::parse_issuer_id(&issuer_id_str)?;
    let credential_type_id = super::parse_credential_type_id(&credential_type_id_str)?;

    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;

    let ownership = persistence::issuer_credential_types::tenant_owns_pair(
        &mut conn,
        &tenant_context.tenant_id,
        &issuer_id,
        &credential_type_id,
    )
    .await?;
    if !ownership.both() {
        return Err(ApiError::NotFound);
    }

    let assignment = IssuerCredentialTypeAssignment::new(
        issuer_id.clone(),
        credential_type_id.clone(),
        tenant_context.tenant_id.clone(),
    );
    let outcome = persistence::issuer_credential_types::assign(&mut conn, &assignment).await?;
    let status = match outcome {
        AssignOutcome::NowAssigned => StatusCode::CREATED,
        AssignOutcome::AlreadyAssigned => StatusCode::OK,
    };

    Ok((
        status,
        Json(AssignmentResponse {
            issuer_id: issuer_id.bare().to_string(),
            credential_type_id: credential_type_id.bare().to_string(),
        }),
    ))
}

pub async fn unassign(
    State(state): State<AppState>,
    Path((issuer_id_str, credential_type_id_str)): Path<(String, String)>,
    tenant_context: TenantContext,
) -> Result<StatusCode, ApiError> {
    let issuer_id = super::parse_issuer_id(&issuer_id_str)?;
    let credential_type_id = super::parse_credential_type_id(&credential_type_id_str)?;

    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;

    // Probing defence: pair-ownership check first so a caller cannot
    // probe for assignments against issuers or credential types they
    // don't own. The unassign itself is then idempotent — a missing
    // row still surfaces as 204.
    let ownership = persistence::issuer_credential_types::tenant_owns_pair(
        &mut conn,
        &tenant_context.tenant_id,
        &issuer_id,
        &credential_type_id,
    )
    .await?;
    if !ownership.both() {
        return Err(ApiError::NotFound);
    }

    persistence::issuer_credential_types::unassign(&mut conn, &issuer_id, &credential_type_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_assignments(
    State(state): State<AppState>,
    Path(issuer_id_str): Path<String>,
    tenant_context: TenantContext,
) -> Result<Json<ListAssignedCredentialTypesResponse>, ApiError> {
    let issuer_id = super::parse_issuer_id(&issuer_id_str)?;

    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;

    let issuer_owned =
        persistence::issuers::exists_for_tenant(&mut conn, &tenant_context.tenant_id, &issuer_id)
            .await?;
    if !issuer_owned {
        return Err(ApiError::NotFound);
    }

    let rows = persistence::credential_types::list_assigned_to_issuer(
        &mut conn,
        &tenant_context.tenant_id,
        &issuer_id,
    )
    .await?;
    let items = rows.into_iter().map(Into::into).collect();
    Ok(Json(ListAssignedCredentialTypesResponse { items }))
}

// Schema documents are served with `application/schema+json` so
// downstream tooling that branches on MIME type (linters, IDE
// integrations) treats them as JSON Schema rather than plain JSON.
const SCHEMA_CONTENT_TYPE: &str = "application/schema+json";

pub async fn get_schema(
    State(state): State<AppState>,
    Path(id_str): Path<String>,
    tenant_context: TenantContext,
) -> Result<Response, ApiError> {
    let id = super::parse_credential_type_id(&id_str)?;
    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;
    let row = persistence::credential_types::find_by_id_for_tenant(
        &mut conn,
        &tenant_context.tenant_id,
        &id,
    )
    .await?
    .ok_or(ApiError::NotFound)?;

    let body =
        serde_json::to_vec(&row.claim_schema).map_err(|err| ApiError::Internal(Box::new(err)))?;
    Ok(([(header::CONTENT_TYPE, SCHEMA_CONTENT_TYPE)], body).into_response())
}

pub async fn put_schema(
    State(state): State<AppState>,
    Path(id_str): Path<String>,
    tenant_context: TenantContext,
    Json(body): Json<Value>,
) -> Result<Json<GetCredentialTypeResponse>, ApiError> {
    let id = super::parse_credential_type_id(&id_str)?;

    // Compile the supplied schema first so an invalid document is
    // rejected before any write.
    jsonschema::validator_for(&body).map_err(|err| ApiError::InvalidInput {
        details: format!("claim_schema does not compile: {err}"),
    })?;

    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;
    let outcome = persistence::credential_types::update_blob_schema(
        &mut conn,
        &tenant_context.tenant_id,
        &id,
        &body,
    )
    .await?;
    if outcome == UpdateOutcome::NotFound {
        return Err(ApiError::NotFound);
    }

    let row = persistence::credential_types::find_by_id_for_tenant(
        &mut conn,
        &tenant_context.tenant_id,
        &id,
    )
    .await?
    .ok_or(ApiError::NotFound)?;
    Ok(Json(row.into()))
}

pub async fn get_display(
    State(state): State<AppState>,
    Path(id_str): Path<String>,
    tenant_context: TenantContext,
) -> Result<Json<Value>, ApiError> {
    let id = super::parse_credential_type_id(&id_str)?;
    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;
    let row = persistence::credential_types::find_by_id_for_tenant(
        &mut conn,
        &tenant_context.tenant_id,
        &id,
    )
    .await?
    .ok_or(ApiError::NotFound)?;
    Ok(Json(row.display))
}

pub async fn put_display(
    State(state): State<AppState>,
    Path(id_str): Path<String>,
    tenant_context: TenantContext,
    Json(body): Json<Value>,
) -> Result<Json<GetCredentialTypeResponse>, ApiError> {
    let id = super::parse_credential_type_id(&id_str)?;
    let body = validate_display(body)?;

    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;
    let outcome = persistence::credential_types::update_blob_display(
        &mut conn,
        &tenant_context.tenant_id,
        &id,
        &body,
    )
    .await?;
    if outcome == UpdateOutcome::NotFound {
        return Err(ApiError::NotFound);
    }

    let row = persistence::credential_types::find_by_id_for_tenant(
        &mut conn,
        &tenant_context.tenant_id,
        &id,
    )
    .await?
    .ok_or(ApiError::NotFound)?;
    Ok(Json(row.into()))
}

pub async fn get_claims(
    State(state): State<AppState>,
    Path(id_str): Path<String>,
    tenant_context: TenantContext,
) -> Result<Json<Value>, ApiError> {
    let id = super::parse_credential_type_id(&id_str)?;
    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;
    let row = persistence::credential_types::find_by_id_for_tenant(
        &mut conn,
        &tenant_context.tenant_id,
        &id,
    )
    .await?
    .ok_or(ApiError::NotFound)?;
    Ok(Json(row.claims))
}

pub async fn put_claims(
    State(state): State<AppState>,
    Path(id_str): Path<String>,
    tenant_context: TenantContext,
    Json(body): Json<Value>,
) -> Result<Json<GetCredentialTypeResponse>, ApiError> {
    let id = super::parse_credential_type_id(&id_str)?;
    let body = validate_claims(body)?;

    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;
    let outcome = persistence::credential_types::update_blob_claims(
        &mut conn,
        &tenant_context.tenant_id,
        &id,
        &body,
    )
    .await?;
    if outcome == UpdateOutcome::NotFound {
        return Err(ApiError::NotFound);
    }

    let row = persistence::credential_types::find_by_id_for_tenant(
        &mut conn,
        &tenant_context.tenant_id,
        &id,
    )
    .await?
    .ok_or(ApiError::NotFound)?;
    Ok(Json(row.into()))
}

impl From<CredentialType> for GetCredentialTypeResponse {
    fn from(ct: CredentialType) -> Self {
        Self {
            credential_type_id: ct.id.bare().to_string(),
            vct: ct.vct,
            internal_description: ct.internal_description,
            claim_schema_source_url: ct.claim_schema_source_url,
            claim_schema_fetched_at: ct.claim_schema_fetched_at,
            // Negative durations are impossible since the persistence
            // layer holds an unsigned-ish microsecond count and `new`
            // accepts only positive durations, so `u64` cast is safe.
            default_validity_seconds: ct
                .default_validity_duration
                .num_seconds()
                .max(0)
                .unsigned_abs(),
            revocation_mode: ct.revocation_mode.as_str().to_string(),
            created_at: ct.created_at,
            updated_at: ct.updated_at,
            retired_at: ct.retired_at,
        }
    }
}

fn validate_display(value: serde_json::Value) -> Result<serde_json::Value, ApiError> {
    if !value.is_array() {
        return Err(ApiError::InvalidInput {
            details: "display must be a JSON array".into(),
        });
    }
    Ok(value)
}

fn validate_claims(value: serde_json::Value) -> Result<serde_json::Value, ApiError> {
    if !value.is_object() {
        return Err(ApiError::InvalidInput {
            details: "claims must be a JSON object".into(),
        });
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_display_accepts_array() {
        assert!(validate_display(serde_json::json!([])).is_ok());
        assert!(validate_display(serde_json::json!([{ "name": "X" }])).is_ok());
    }

    #[test]
    fn validate_display_rejects_object() {
        assert!(matches!(
            validate_display(serde_json::json!({})),
            Err(ApiError::InvalidInput { .. })
        ));
    }

    #[test]
    fn validate_claims_accepts_object() {
        assert!(validate_claims(serde_json::json!({})).is_ok());
    }

    #[test]
    fn validate_claims_rejects_array() {
        assert!(matches!(
            validate_claims(serde_json::json!([])),
            Err(ApiError::InvalidInput { .. })
        ));
    }
}
