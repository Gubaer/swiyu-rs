use std::sync::Arc;

use sqlx::PgPool;

pub struct Config {
    /// Public base URL the wallet sees. The metadata document
    /// substitutes this into `credential_issuer`,
    /// `credential_endpoint`, and the like. Both binaries
    /// (`issuer-mgmt` and `issuer-oidc`) must agree on it; a
    /// reverse proxy in front of the two is the canonical layout
    /// (see `impl_api_oidc.md` Deployment topology).
    pub issuer_base_url: String,
}

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Arc<Config>,
}

impl AppState {
    pub fn new(pool: PgPool, config: Config) -> Self {
        Self {
            pool,
            config: Arc::new(config),
        }
    }
}
