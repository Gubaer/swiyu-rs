// Public, unauthenticated JSON Schema dereference endpoint.
//
// The schema URL is embedded in every issued credential's
// `credentialSchema` field and may be hit by any verifier in the
// world long after the credential was minted. The endpoint therefore
// has no tenant in its path, no authentication, and no probing-
// defence carve-out beyond filtering retired rows. The body is the
// canonical JSON Schema 2020-12 document for the credential type.

use axum::extract::{Path, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};

use crate::persistence;

use super::AppState;
use super::error::OidcError;

const SCHEMA_CONTENT_TYPE: &str = "application/schema+json";

pub async fn get_public_schema(
    State(state): State<AppState>,
    Path(id_str): Path<String>,
) -> Result<Response, OidcError> {
    let id = super::parse_credential_type_id(&id_str)?;

    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| OidcError::Internal(Box::new(err)))?;

    let row = persistence::credential_types::find_by_id(&mut conn, &id)
        .await?
        .ok_or(OidcError::NotFound)?;
    if row.retired_at.is_some() {
        return Err(OidcError::NotFound);
    }

    let body =
        serde_json::to_vec(&row.claim_schema).map_err(|err| OidcError::Internal(Box::new(err)))?;
    Ok(([(header::CONTENT_TYPE, SCHEMA_CONTENT_TYPE)], body).into_response())
}
