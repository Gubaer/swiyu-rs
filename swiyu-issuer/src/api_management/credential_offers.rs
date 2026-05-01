use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;

use super::AppState;
use super::auth::TenantContext;
use super::dto::{CreateCredentialOfferRequest, CreateCredentialOfferResponse};
use super::error::ApiError;

pub async fn create(
    State(state): State<AppState>,
    Path(issuer_id): Path<String>,
    tenant_context: TenantContext,
    Json(payload): Json<CreateCredentialOfferRequest>,
) -> Result<(StatusCode, Json<CreateCredentialOfferResponse>), ApiError> {
    tracing::debug!(
        tenant_id = %tenant_context.tenant_id,
        issuer_id = %issuer_id,
        vct = %payload.vct,
        expires_in_seconds = ?payload.expires_in_seconds,
        "credential offer creation requested",
    );

    validate_claims(&state, &payload)?;

    // The remaining steps depend on domain::ids and persistence::credential_offers
    // landing first (see specs/impl_api_management.md "Suggested slice ordering").
    // Returning 501 keeps the endpoint reachable for smoke tests of the schema
    // validation path while the dependencies arrive.
    Err(ApiError::NotImplemented {
        what: "credential offer creation requires domain::ids and persistence::credential_offers",
    })
}

fn validate_claims(
    state: &AppState,
    payload: &CreateCredentialOfferRequest,
) -> Result<(), ApiError> {
    let validator = state
        .schemas
        .get(&payload.vct)
        .ok_or_else(|| ApiError::UnknownVct {
            vct: payload.vct.clone(),
        })?;

    let errors: Vec<String> = validator
        .iter_errors(&payload.claims)
        .map(|err| err.to_string())
        .collect();

    if errors.is_empty() {
        Ok(())
    } else {
        Err(ApiError::ClaimsValidationFailed { errors })
    }
}
