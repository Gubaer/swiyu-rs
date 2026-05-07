use std::collections::HashMap;
use std::sync::Arc;

use jsonschema::Validator;
use thiserror::Error;

use crate::domain::vct::CATALOGUE;

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

/// Compile and return validators for all schemas bundled in the VCT catalogue.
///
/// Temporary: the catalogue currently holds exactly one hard-coded schema.
/// Replace this with dynamic schema loading once the catalogue is configurable.
pub fn load() -> Result<HashMap<String, Arc<Validator>>, SchemaLoadError> {
    CATALOGUE
        .iter()
        .map(|entry| {
            let document: serde_json::Value =
                serde_json::from_str(entry.schema).map_err(|source| SchemaLoadError::Parse {
                    vct: entry.vct.to_string(),
                    source,
                })?;
            let validator =
                jsonschema::validator_for(&document).map_err(|err| SchemaLoadError::Compile {
                    vct: entry.vct.to_string(),
                    message: err.to_string(),
                })?;
            Ok((entry.vct.to_string(), Arc::new(validator)))
        })
        .collect()
}
