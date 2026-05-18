// Process-wide, lazily-populated cache of compiled JSON Schema
// validators keyed by `CredentialTypeId`. Each entry carries the
// `updated_at` timestamp of the row it was compiled from, so callers
// detect schema edits via per-request freshness checks without any
// pub/sub or cross-process invalidation. The fast path is a read-lock
// HashMap lookup + Arc clone; the slow path takes the write lock,
// double-checks (a racing caller may have inserted), compiles, and
// inserts. Schema updates bump `updated_at` on the row; the next
// request notices the mismatch and re-compiles once.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use jsonschema::Validator;
use serde_json::Value;
use thiserror::Error;
use tokio::sync::RwLock;

use crate::domain::CredentialTypeId;

#[derive(Debug, Error)]
pub enum ValidatorCompileError {
    #[error("failed to compile JSON Schema: {message}")]
    Compile { message: String },
}

/// One compiled validator and the source row's `updated_at` it was
/// compiled from.
pub struct ValidatorCacheEntry {
    pub validator: Arc<Validator>,
    /// Copied from `credential_types.updated_at` at compile time;
    /// compared against the row's current `updated_at` on every
    /// request to detect schema edits.
    pub schema_updated_at: DateTime<Utc>,
}

/// Process-wide cache of compiled JSON Schema validators keyed by
/// [`CredentialTypeId`].
///
/// Empty at startup, populated lazily on first call to
/// [`get_or_compile`][Self::get_or_compile]. Concurrent first-use on
/// the same id collapses to a single compile via the double-checked
/// write-lock acquisition; subsequent requests with the same
/// `updated_at` take the read-lock fast path.
#[derive(Default)]
pub struct ValidatorCache {
    inner: RwLock<HashMap<CredentialTypeId, ValidatorCacheEntry>>,
}

impl ValidatorCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn get_or_compile(
        &self,
        id: &CredentialTypeId,
        claim_schema: &Value,
        updated_at: DateTime<Utc>,
    ) -> Result<Arc<Validator>, ValidatorCompileError> {
        {
            let guard = self.inner.read().await;
            if let Some(entry) = guard.get(id)
                && entry.schema_updated_at == updated_at
            {
                return Ok(Arc::clone(&entry.validator));
            }
        }

        let mut guard = self.inner.write().await;
        // Re-check under the write lock: a racing caller may have
        // inserted (or refreshed) the entry between our read-lock
        // drop and here.
        if let Some(entry) = guard.get(id)
            && entry.schema_updated_at == updated_at
        {
            return Ok(Arc::clone(&entry.validator));
        }

        let validator = jsonschema::validator_for(claim_schema).map_err(|err| {
            ValidatorCompileError::Compile {
                message: err.to_string(),
            }
        })?;
        let validator = Arc::new(validator);
        guard.insert(
            id.clone(),
            ValidatorCacheEntry {
                validator: Arc::clone(&validator),
                schema_updated_at: updated_at,
            },
        );
        Ok(validator)
    }

    #[cfg(test)]
    pub(crate) async fn entry_count(&self) -> usize {
        self.inner.read().await.len()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::Duration;
    use serde_json::json;

    use super::*;

    fn fresh_schema() -> Value {
        json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "first_name": { "type": "string" },
                "last_name":  { "type": "string" }
            },
            "required": ["first_name", "last_name"]
        })
    }

    fn fresh_id() -> CredentialTypeId {
        CredentialTypeId::generate()
    }

    #[tokio::test]
    async fn first_call_compiles_and_caches() {
        let cache = ValidatorCache::new();
        let id = fresh_id();
        let schema = fresh_schema();
        let now = Utc::now();

        assert_eq!(cache.entry_count().await, 0);
        let validator = cache.get_or_compile(&id, &schema, now).await.unwrap();
        assert_eq!(cache.entry_count().await, 1);

        // Returned validator accepts a valid payload and rejects an invalid one.
        assert!(
            validator
                .validate(&json!({ "first_name": "A", "last_name": "B" }))
                .is_ok()
        );
        assert!(validator.validate(&json!({ "first_name": "A" })).is_err());
    }

    #[tokio::test]
    async fn second_call_with_same_updated_at_hits_the_cache() {
        let cache = ValidatorCache::new();
        let id = fresh_id();
        let schema = fresh_schema();
        let now = Utc::now();

        let first = cache.get_or_compile(&id, &schema, now).await.unwrap();
        let second = cache.get_or_compile(&id, &schema, now).await.unwrap();

        // Same Arc — the second call returned the cached validator.
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(cache.entry_count().await, 1);
    }

    #[tokio::test]
    async fn updated_at_change_triggers_recompile() {
        let cache = ValidatorCache::new();
        let id = fresh_id();
        let first_schema = fresh_schema();
        let first_ts = Utc::now();

        let first = cache
            .get_or_compile(&id, &first_schema, first_ts)
            .await
            .unwrap();

        // A schema edit bumps `updated_at` on the row.
        let second_schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": { "age": { "type": "integer" } },
            "required": ["age"]
        });
        let second_ts = first_ts + Duration::seconds(1);

        let second = cache
            .get_or_compile(&id, &second_schema, second_ts)
            .await
            .unwrap();

        // A fresh allocation, not the cached one.
        assert!(!Arc::ptr_eq(&first, &second));
        // The cache still holds exactly one entry for this id — the
        // refreshed one replaced the stale one.
        assert_eq!(cache.entry_count().await, 1);

        // The new validator reflects the new schema.
        assert!(second.validate(&json!({ "age": 30 })).is_ok());
        assert!(second.validate(&json!({ "age": "thirty" })).is_err());
    }

    #[tokio::test]
    async fn broken_schema_surfaces_as_typed_compile_error() {
        let cache = ValidatorCache::new();
        let id = fresh_id();
        // `type` must be a string or array of strings; an integer is
        // a structural error that the compiler rejects.
        let broken = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": 42
        });
        let now = Utc::now();

        let result = cache.get_or_compile(&id, &broken, now).await;
        assert!(matches!(result, Err(ValidatorCompileError::Compile { .. })));
        // Nothing was cached.
        assert_eq!(cache.entry_count().await, 0);
    }

    #[tokio::test]
    async fn concurrent_first_use_compiles_once_and_returns_same_arc() {
        // Sixteen callers race on the same id with identical
        // `updated_at`. The double-check in `get_or_compile` must
        // ensure at most one entry lands in the cache, and every
        // caller observes the same Arc<Validator>.
        let cache = Arc::new(ValidatorCache::new());
        let id = fresh_id();
        let schema = fresh_schema();
        let now = Utc::now();

        let mut handles = Vec::new();
        for _ in 0..16 {
            let cache = Arc::clone(&cache);
            let id = id.clone();
            let schema = schema.clone();
            handles.push(tokio::spawn(async move {
                cache.get_or_compile(&id, &schema, now).await.unwrap()
            }));
        }

        let mut validators = Vec::with_capacity(16);
        for h in handles {
            validators.push(h.await.unwrap());
        }

        let first = &validators[0];
        for v in &validators[1..] {
            assert!(Arc::ptr_eq(first, v));
        }
        assert_eq!(cache.entry_count().await, 1);
    }
}
