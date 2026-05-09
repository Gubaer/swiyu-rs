//! `ProviderRegistry` — process-wide map of `tenant_id → provider`.
//!
//! Holds one `AnyTokenProvider` per tenant, constructed lazily on
//! first request and cached for the lifetime of the registry.
//! Concurrent first-use of the same tenant collapses to a single
//! construction via a double-checked write-lock acquisition.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::Duration;
use reqwest::Client;
use tokio::sync::RwLock;

use crate::domain::TenantId;

use super::{AnyTokenProvider, OAuth2TokenProvider};

/// Process-wide cache of `TokenProvider` instances keyed by tenant.
///
/// Built once at startup from the shared infrastructure handles
/// (`pool`, `http`, `token_url`, `safety_margin`) and threaded into
/// the `Worker` and `StatusListPublisher` as `Arc<ProviderRegistry>`.
/// Each tenant's provider is constructed on first use and reused
/// thereafter so the in-memory access-token cache, the single-flight
/// gate, and the `FOR UPDATE` row-lock window all live on a single
/// long-lived instance per tenant.
pub struct ProviderRegistry {
    /// Pool handed to every `OAuth2TokenProvider` this registry
    /// builds; each provider opens its own transaction inside the
    /// `refresh_token` grant and relies on Postgres row locking
    /// rather than an in-process mutex for cross-replica safety.
    pool: sqlx::PgPool,
    /// Shared HTTP client. Cloning a `reqwest::Client` shares the
    /// underlying connection pool, so per-provider clones do not
    /// fragment TLS sessions to the token endpoint.
    http: Client,
    /// Token endpoint URL. Same value for every tenant — the OAuth2
    /// authorization server is shared; only credentials differ.
    token_url: String,
    /// Refresh pre-emptively when a cached access token has less than
    /// this much time remaining. Propagated unchanged into every
    /// provider so the entire process refreshes on the same schedule.
    safety_margin: Duration,
    /// Lazily-populated `tenant_id → provider` map. `RwLock` because
    /// the steady-state read path (warm cache hit) must not contend
    /// against itself; only first-use of a new tenant takes the
    /// write lock.
    providers: RwLock<HashMap<TenantId, Arc<AnyTokenProvider>>>,
}

impl ProviderRegistry {
    pub fn new(
        pool: sqlx::PgPool,
        http: Client,
        token_url: String,
        safety_margin: Duration,
    ) -> Self {
        Self {
            pool,
            http,
            token_url,
            safety_margin,
            providers: RwLock::new(HashMap::new()),
        }
    }

    /// Returns the cached provider for `tenant_id`, constructing one
    /// on first call. Subsequent calls with the same id return clones
    /// of the same `Arc`, so per-tenant state (in-memory access-token
    /// cache, single-flight gate) is shared across all callers.
    pub async fn provider_for(&self, tenant_id: &TenantId) -> Arc<AnyTokenProvider> {
        {
            let guard = self.providers.read().await;
            if let Some(provider) = guard.get(tenant_id) {
                return Arc::clone(provider);
            }
        }

        let mut guard = self.providers.write().await;
        // Re-check under the write lock: a racing caller may have
        // inserted the entry between our read-lock drop and here.
        if let Some(provider) = guard.get(tenant_id) {
            return Arc::clone(provider);
        }

        let provider = OAuth2TokenProvider::new(
            tenant_id.clone(),
            self.pool.clone(),
            self.http.clone(),
            self.token_url.clone(),
            self.safety_margin,
        );
        let any = Arc::new(AnyTokenProvider::OAuth2(provider));
        guard.insert(tenant_id.clone(), Arc::clone(&any));
        any
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use sqlx::PgPool;

    fn http_client() -> Client {
        Client::builder().build().unwrap()
    }

    fn registry(pool: PgPool) -> ProviderRegistry {
        ProviderRegistry::new(
            pool,
            http_client(),
            "http://example.invalid/token".to_string(),
            Duration::seconds(30),
        )
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn distinct_tenants_get_distinct_providers(pool: PgPool) {
        let registry = registry(pool);
        let id_a = TenantId::generate();
        let id_b = TenantId::generate();

        let provider_a = registry.provider_for(&id_a).await;
        let provider_b = registry.provider_for(&id_b).await;

        assert!(!Arc::ptr_eq(&provider_a, &provider_b));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn same_tenant_returns_same_arc(pool: PgPool) {
        let registry = registry(pool);
        let tenant_id = TenantId::generate();

        let first = registry.provider_for(&tenant_id).await;
        let second = registry.provider_for(&tenant_id).await;

        assert!(Arc::ptr_eq(&first, &second));
    }
}
