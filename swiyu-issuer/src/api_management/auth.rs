use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use super::AppState;
use super::error::ApiError;

pub struct TenantContext {
    pub tenant_id: String,
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
