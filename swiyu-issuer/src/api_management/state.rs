use std::sync::Arc;

use sqlx::PgPool;

use crate::state::ValidatorCache;

pub struct Config {
    /// Public base URL of the wallet-facing OIDC endpoints, used to
    /// build the `credential_offer_uri` in each offer deeplink. The
    /// binary resolves it from `ISSUER_OIDC_HTTP_URL` (falling back to
    /// `ISSUER_BASE_URL`) so the deeplink points the wallet at the OIDC
    /// server, which need not share this binary's port. See
    /// [`resolve_oidc_public_url`][crate::config::resolve_oidc_public_url].
    pub issuer_base_url: String,
}

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Arc<Config>,
    pub validators: Arc<ValidatorCache>,
}

impl AppState {
    pub fn new(pool: PgPool, config: Config) -> Self {
        Self {
            pool,
            config: Arc::new(config),
            validators: Arc::new(ValidatorCache::new()),
        }
    }
}
