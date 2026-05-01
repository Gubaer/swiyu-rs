use std::collections::HashMap;
use std::sync::Arc;

use jsonschema::Validator;
use thiserror::Error;

const BUNDLED_SCHEMAS: &[(&str, &str)] = &[(
    "urn:communal:local-residence-id",
    include_str!("../../schemas/urn_communal_local-residence-id.json"),
)];

#[derive(Debug, Error)]
pub enum SchemaLoadError {
    #[error("failed to parse bundled schema for {vct}: {source}")]
    Parse {
        vct: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to compile bundled schema for {vct}: {message}")]
    Compile { vct: String, message: String },
}

pub fn load() -> Result<HashMap<String, Arc<Validator>>, SchemaLoadError> {
    BUNDLED_SCHEMAS
        .iter()
        .map(|(vct, json)| {
            let document: serde_json::Value =
                serde_json::from_str(json).map_err(|source| SchemaLoadError::Parse {
                    vct: (*vct).to_string(),
                    source,
                })?;
            let validator =
                jsonschema::validator_for(&document).map_err(|err| SchemaLoadError::Compile {
                    vct: (*vct).to_string(),
                    message: err.to_string(),
                })?;
            Ok(((*vct).to_string(), Arc::new(validator)))
        })
        .collect()
}
