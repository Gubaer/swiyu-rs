use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use sqlx::postgres::PgConnection;

use crate::domain::{IssuerId, TenantId};
use crate::persistence;

use super::AppState;
use super::error::ApiError;

pub struct TenantContext {
    pub tenant_id: TenantId,
}

impl FromRequestParts<AppState> for TenantContext {
    type Rejection = ApiError;

    async fn from_request_parts(
        _parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // v0.1.0 stub: returns the seeded tenant id from config. Real
        // API-token authentication replaces this body in a later slice;
        // handler signatures do not change.
        Ok(TenantContext {
            tenant_id: state.config.default_tenant_id.clone(),
        })
    }
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
