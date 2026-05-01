use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use chrono::Utc;
use sqlx::Postgres;
use sqlx::pool::PoolConnection;
use sqlx::postgres::PgConnection;

use crate::domain::{ApiTokenSecret, IssuerId, TenantId};
use crate::persistence;

use super::AppState;
use super::error::ApiError;

const BEARER_PREFIX: &str = "Bearer ";

pub struct TenantContext {
    pub tenant_id: TenantId,
}

impl FromRequestParts<AppState> for TenantContext {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Every step that can fail collapses to ApiError::Unauthorised
        // with a generic body, so the client cannot distinguish "no
        // header" from "wrong scheme" from "expired token" from
        // "revoked token". The tracing::debug! lines preserve the
        // diagnostic detail server-side.
        let secret = extract_bearer(parts)?;
        let hash = secret.hash();

        let mut conn = state.pool.acquire().await.map_err(|err| {
            tracing::debug!(error = %err, "auth: failed to acquire DB connection");
            ApiError::Unauthorised
        })?;

        let token = persistence::api_tokens::find_valid_by_hash(&mut conn, &hash, Utc::now())
            .await
            .map_err(|err| {
                tracing::debug!(error = %err, "auth: token lookup failed");
                ApiError::Unauthorised
            })?
            .ok_or_else(|| {
                tracing::debug!("auth: no valid token matches the presented hash");
                ApiError::Unauthorised
            })?;

        // last_used_at is best-effort: a failure here means the audit
        // signal is missing, not that the request should be denied.
        if let Err(err) = persistence::api_tokens::mark_used(&mut conn, &token.id, Utc::now()).await
        {
            tracing::warn!(error = %err, token_id = %token.id, "auth: failed to bump last_used_at");
        }

        Ok(TenantContext {
            tenant_id: token.tenant_id,
        })
    }
}

fn extract_bearer(parts: &Parts) -> Result<ApiTokenSecret, ApiError> {
    let header = parts.headers.get(AUTHORIZATION).ok_or_else(|| {
        tracing::debug!("auth: missing Authorization header");
        ApiError::Unauthorised
    })?;
    let value = header.to_str().map_err(|_| {
        tracing::debug!("auth: Authorization header is not valid UTF-8");
        ApiError::Unauthorised
    })?;
    let token_str = value.strip_prefix(BEARER_PREFIX).ok_or_else(|| {
        tracing::debug!("auth: Authorization header is not a Bearer credential");
        ApiError::Unauthorised
    })?;
    ApiTokenSecret::from_wire(token_str).map_err(|err| {
        tracing::debug!(error = %err, "auth: malformed bearer token");
        ApiError::Unauthorised
    })
}

/// Verifies that `issuer_id` exists and belongs to `tenant_id`.
///
/// This is the request-boundary ownership check the multi-tenancy
/// spec calls for. Every handler that accepts an [`IssuerId`] from
/// the URL path runs it before touching persistence functions
/// scoped to the issuer.
///
/// # Errors
///
/// Returns [`ApiError::NotFound`] if the issuer does not exist, or
/// exists under a different tenant. The same status is used for
/// "wrong tenant" and for "no such issuer" so an attacker cannot
/// probe for the existence of issuers outside their tenant.
pub async fn require_issuer_owned_by_tenant(
    conn: &mut PgConnection,
    tenant_id: &TenantId,
    issuer_id: &IssuerId,
) -> Result<(), ApiError> {
    let exists = persistence::issuers::exists_for_tenant(conn, tenant_id, issuer_id).await?;
    if exists {
        Ok(())
    } else {
        Err(ApiError::NotFound)
    }
}

/// Acquires a pool connection and verifies issuer ownership before
/// returning it. Every issuer-scoped management handler runs through
/// this so the ownership check cannot be skipped by accident: a
/// handler that needs a connection at all gets the check for free.
pub async fn acquire_for_issuer(
    state: &AppState,
    tenant_id: &TenantId,
    issuer_id: &IssuerId,
) -> Result<PoolConnection<Postgres>, ApiError> {
    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| ApiError::Internal(Box::new(err)))?;
    require_issuer_owned_by_tenant(&mut conn, tenant_id, issuer_id).await?;
    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderValue, Request};

    fn parts_with_header(value: Option<&str>) -> Parts {
        let mut req = Request::builder().body(()).unwrap();
        if let Some(v) = value {
            req.headers_mut()
                .insert(AUTHORIZATION, HeaderValue::from_str(v).unwrap());
        }
        let (parts, _body) = req.into_parts();
        parts
    }

    #[test]
    fn extract_bearer_accepts_well_formed_token() {
        let parts = parts_with_header(Some("Bearer tok_DevDevDevDevDev"));
        let secret = extract_bearer(&parts).unwrap();
        assert_eq!(secret.bare(), "DevDevDevDevDev");
    }

    #[test]
    fn extract_bearer_rejects_missing_header() {
        let parts = parts_with_header(None);
        assert!(extract_bearer(&parts).is_err());
    }

    #[test]
    fn extract_bearer_rejects_basic_scheme() {
        let parts = parts_with_header(Some("Basic dXNlcjpwYXNz"));
        assert!(extract_bearer(&parts).is_err());
    }

    #[test]
    fn extract_bearer_rejects_missing_tok_prefix() {
        let parts = parts_with_header(Some("Bearer DevDevDevDevDev"));
        assert!(extract_bearer(&parts).is_err());
    }

    #[test]
    fn extract_bearer_rejects_non_base58_body() {
        let parts = parts_with_header(Some("Bearer tok_Dev0Dev"));
        assert!(extract_bearer(&parts).is_err());
    }

    #[test]
    fn extract_bearer_rejects_empty_body() {
        let parts = parts_with_header(Some("Bearer tok_"));
        assert!(extract_bearer(&parts).is_err());
    }
}
