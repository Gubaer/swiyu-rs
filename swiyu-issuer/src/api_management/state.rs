use std::collections::HashMap;
use std::sync::Arc;

use jsonschema::Validator;
use sqlx::PgPool;

use crate::domain::TenantId;

use super::schemas::{self, SchemaLoadError};

pub struct Config {
    pub default_tenant_id: TenantId,
    pub issuer_base_url: String,
}

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub schemas: Arc<HashMap<String, Arc<Validator>>>,
    pub config: Arc<Config>,
}

impl AppState {
    pub fn new(pool: PgPool, config: Config) -> Result<Self, SchemaLoadError> {
        let schemas = schemas::load()?;
        Ok(Self {
            pool,
            schemas: Arc::new(schemas),
            config: Arc::new(config),
        })
    }
}
