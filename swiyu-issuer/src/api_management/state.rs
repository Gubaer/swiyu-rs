use std::sync::Arc;

use sqlx::PgPool;

use crate::state::ValidatorCache;

pub struct Config {
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
