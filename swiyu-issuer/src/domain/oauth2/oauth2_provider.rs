//! `OAuth2TokenProvider` — the production [`TokenProvider`].
//!
//! Maintains an in-memory access-token cache, performs
//! `refresh_token` grants against the SWIYU OAuth2 token endpoint
//! when the cache is cold or near expiry, and persists the rotated
//! refresh token back to the tenant row inside the same transaction
//! that locks the row for update.

use std::future::Future;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use reqwest::{Client, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};

use swiyu_registries::common::AccessToken;

use crate::domain::TenantId;
use crate::domain::secret_encryption_engine::AnySecretEncryptionEngine;
use crate::persistence::{
    PersistenceError,
    tenants::{TenantOauthCreds, read_oauth_credentials_for_update, write_oauth_refresh_token},
};

use super::{TokenProvider, TokenProviderError};

/// Snapshot of one successful `refresh_token` grant, held in memory
/// by an [`OAuth2TokenProvider`].
///
/// The rotated refresh token is *not* cached — every grant re-reads
/// it from the tenant row inside the same `FOR UPDATE` transaction
/// that performs the new grant, so the DB is the single source of
/// truth and there is nothing for an in-memory copy to add.
struct CachedToken {
    /// The access token returned by the most recent successful grant.
    access: AccessToken,
    /// Absolute clock at which `access` elapses. The provider's
    /// safety margin is applied at read time, not baked in here.
    expires_at: DateTime<Utc>,
    /// Raw access-token string, retained in test builds only so unit
    /// tests can assert on rotation. [`AccessToken`]'s payload is
    /// otherwise opaque to crates outside `swiyu-registries`.
    #[cfg(test)]
    access_raw: String,
}

/// `TokenProvider` backed by an OAuth2 `refresh_token` grant flow.
/// One instance per tenant.
pub struct OAuth2TokenProvider {
    tenant_id: TenantId,
    /// Per-replica DB pool. The provider opens its own transaction
    /// inside `get()`; the `FOR UPDATE` row lock blocks other
    /// replicas from racing the same refresh.
    pool: sqlx::PgPool,
    http: Client,
    token_url: String,
    /// Engine used to decrypt the persisted client secret + refresh
    /// token at read time and to re-encrypt the rotated refresh token
    /// at write time. Shared with every other provider in the
    /// process via [`ProviderRegistry`][super::ProviderRegistry].
    engine: Arc<AnySecretEncryptionEngine>,
    /// The most recent successful grant, in memory.
    cached: RwLock<Option<CachedToken>>,
    /// Per-instance single-flight gate so concurrent `get()` calls
    /// collapse onto one network round-trip.
    refresh_lock: Mutex<()>,
    /// Refresh pre-emptively when the cached access token has less
    /// than this much time remaining.
    safety_margin: Duration,
}

impl OAuth2TokenProvider {
    pub fn new(
        tenant_id: TenantId,
        pool: sqlx::PgPool,
        http: Client,
        token_url: String,
        engine: Arc<AnySecretEncryptionEngine>,
        safety_margin: Duration,
    ) -> Self {
        Self {
            tenant_id,
            pool,
            http,
            token_url,
            engine,
            cached: RwLock::new(None),
            refresh_lock: Mutex::new(()),
            safety_margin,
        }
    }

    fn is_fresh(&self, expires_at: DateTime<Utc>) -> bool {
        expires_at - Utc::now() > self.safety_margin
    }

    async fn cached_access(&self) -> Option<AccessToken> {
        let guard = self.cached.read().await;
        match guard.as_ref() {
            Some(c) if self.is_fresh(c.expires_at) => Some(c.access.clone()),
            _ => None,
        }
    }

    async fn refresh_and_cache(&self) -> Result<AccessToken, TokenProviderError> {
        let _guard = self.refresh_lock.lock().await;

        // Re-check under the single-flight lock: another task may
        // have just populated the cache while we were queued.
        if let Some(token) = self.cached_access().await {
            return Ok(token);
        }

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| TokenProviderError::Persistence(PersistenceError::Db(e)))?;

        let creds =
            read_oauth_credentials_for_update(&mut tx, &self.tenant_id, &self.engine).await?;
        let creds = creds.ok_or_else(|| {
            TokenProviderError::MissingCredentials(format!("tenant {} not found", self.tenant_id))
        })?;
        let validated = ValidatedCreds::from_row(creds, &self.tenant_id)?;

        let response = self
            .do_refresh_grant(
                &validated.client_id,
                &validated.client_secret,
                &validated.refresh_token,
            )
            .await?;

        let new_refresh = SecretString::from(response.refresh_token);
        write_oauth_refresh_token(&mut tx, &self.tenant_id, &new_refresh, &self.engine).await?;
        tx.commit()
            .await
            .map_err(|e| TokenProviderError::Persistence(PersistenceError::Db(e)))?;

        let expires_at = Utc::now() + Duration::seconds(response.expires_in);
        let access = AccessToken::new(response.access_token.clone());
        let returned = access.clone();
        let new_cached = CachedToken {
            access,
            expires_at,
            #[cfg(test)]
            access_raw: response.access_token,
        };
        {
            let mut guard = self.cached.write().await;
            *guard = Some(new_cached);
        }
        Ok(returned)
    }

    async fn do_refresh_grant(
        &self,
        client_id: &str,
        client_secret: &SecretString,
        refresh_token: &SecretString,
    ) -> Result<TokenResponse, TokenProviderError> {
        let params = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.expose_secret()),
            ("client_id", client_id),
            ("client_secret", client_secret.expose_secret()),
        ];
        let response = self
            .http
            .post(&self.token_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| TokenProviderError::Transport(e.to_string()))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| TokenProviderError::Transport(e.to_string()))?;

        if status.is_success() {
            return parse_token_response(&body);
        }
        if status.is_client_error() {
            return Err(TokenProviderError::RefreshRejected(format_oauth_error(
                status, &body,
            )));
        }
        Err(TokenProviderError::Transport(format!(
            "token endpoint returned HTTP {}: {}",
            status.as_u16(),
            body
        )))
    }

    #[cfg(test)]
    pub(crate) async fn cached_access_raw(&self) -> Option<String> {
        self.cached
            .read()
            .await
            .as_ref()
            .map(|c| c.access_raw.clone())
    }
}

impl TokenProvider for OAuth2TokenProvider {
    // The trait's RPIT signature carries an explicit `+ Send` bound;
    // `async fn` in an impl drops the bound, so the explicit form is
    // load-bearing here.
    #[allow(clippy::manual_async_fn)]
    fn get(&self) -> impl Future<Output = Result<AccessToken, TokenProviderError>> + Send {
        async move {
            if let Some(token) = self.cached_access().await {
                return Ok(token);
            }
            self.refresh_and_cache().await
        }
    }

    #[allow(clippy::manual_async_fn)]
    fn invalidate(&self) -> impl Future<Output = Result<AccessToken, TokenProviderError>> + Send {
        async move {
            {
                let mut guard = self.cached.write().await;
                *guard = None;
            }
            self.refresh_and_cache().await
        }
    }
}

/// Tenant credentials with all three required columns confirmed
/// non-NULL. Built from a [`TenantOauthCreds`] row read inside the
/// transaction.
struct ValidatedCreds {
    client_id: String,
    client_secret: SecretString,
    refresh_token: SecretString,
}

impl ValidatedCreds {
    fn from_row(row: TenantOauthCreds, tenant_id: &TenantId) -> Result<Self, TokenProviderError> {
        let client_id = row.client_id.ok_or_else(|| {
            TokenProviderError::MissingCredentials(format!(
                "tenant {tenant_id}: oauth_client_id is NULL"
            ))
        })?;
        let client_secret = row.client_secret.ok_or_else(|| {
            TokenProviderError::MissingCredentials(format!(
                "tenant {tenant_id}: oauth_client_secret is NULL"
            ))
        })?;
        let refresh_token = row.refresh_token.ok_or_else(|| {
            TokenProviderError::MissingCredentials(format!(
                "tenant {tenant_id}: oauth_refresh_token is NULL"
            ))
        })?;
        Ok(Self {
            client_id,
            client_secret,
            refresh_token,
        })
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    expires_in: i64,
}

#[derive(Deserialize)]
struct OauthErrorBody {
    error: Option<String>,
    error_description: Option<String>,
}

fn parse_token_response(body: &str) -> Result<TokenResponse, TokenProviderError> {
    serde_json::from_str::<TokenResponse>(body)
        .map_err(|e| TokenProviderError::Decode(format!("token endpoint body: {e}")))
}

fn format_oauth_error(status: StatusCode, body: &str) -> String {
    if let Ok(parsed) = serde_json::from_str::<OauthErrorBody>(body) {
        let kind = parsed.error.as_deref().unwrap_or("(no error code)");
        let detail = parsed.error_description.as_deref().unwrap_or("");
        if detail.is_empty() {
            format!("HTTP {}: {}", status.as_u16(), kind)
        } else {
            format!("HTTP {}: {}: {}", status.as_u16(), kind, detail)
        }
    } else {
        format!("HTTP {}: {}", status.as_u16(), body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration as StdDuration;

    use serde_json::json;
    use sqlx::PgPool;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::domain::secret_encryption_engine::{
        DevSecretEncryptionEngine, SecretEncryptionEngine,
    };
    use crate::persistence::tenant_secret_keys::{
        oauth2_client_secret_key_name, oauth2_refresh_token_key_name,
    };

    fn http_client() -> Client {
        Client::builder()
            .timeout(StdDuration::from_secs(5))
            .build()
            .unwrap()
    }

    fn safety_margin() -> Duration {
        // 30 seconds — short enough that tests using "expires_in: 60"
        // are clearly outside the margin.
        Duration::seconds(30)
    }

    fn test_engine() -> Arc<AnySecretEncryptionEngine> {
        Arc::new(AnySecretEncryptionEngine::Dev(
            DevSecretEncryptionEngine::new([0x42u8; 32]),
        ))
    }

    async fn encrypt_for(
        engine: &AnySecretEncryptionEngine,
        key_name: &str,
        plaintext: &str,
    ) -> Vec<u8> {
        engine
            .encrypt(key_name, plaintext.as_bytes())
            .await
            .unwrap()
            .into_bytes()
    }

    async fn seed_tenant_with_creds(
        pool: &PgPool,
        tenant_id: &TenantId,
        engine: &AnySecretEncryptionEngine,
        client_id: Option<&str>,
        client_secret: Option<&str>,
        refresh_token: Option<&str>,
    ) {
        let client_secret_blob = match client_secret {
            None => None,
            Some(s) => {
                Some(encrypt_for(engine, &oauth2_client_secret_key_name(tenant_id), s).await)
            }
        };
        let refresh_token_blob = match refresh_token {
            None => None,
            Some(s) => {
                Some(encrypt_for(engine, &oauth2_refresh_token_key_name(tenant_id), s).await)
            }
        };
        sqlx::query(
            r#"
            INSERT INTO tenants
                (id, partner_id, oauth_client_id, oauth_client_secret, oauth_refresh_token)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(tenant_id.bare())
        .bind("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef")
        .bind(client_id)
        .bind(client_secret_blob)
        .bind(refresh_token_blob)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn read_refresh_column(
        pool: &PgPool,
        tenant_id: &TenantId,
        engine: &AnySecretEncryptionEngine,
    ) -> Option<String> {
        let row: (Option<Vec<u8>>,) =
            sqlx::query_as("SELECT oauth_refresh_token FROM tenants WHERE id = $1")
                .bind(tenant_id.bare())
                .fetch_one(pool)
                .await
                .unwrap();
        let bytes = row.0?;
        let plaintext = engine
            .decrypt(&oauth2_refresh_token_key_name(tenant_id), &bytes.into())
            .await
            .unwrap();
        Some(String::from_utf8(plaintext).unwrap())
    }

    fn ok_token_response(access: &str, refresh: &str, expires_in: i64) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(json!({
            "access_token": access,
            "refresh_token": refresh,
            "expires_in": expires_in,
            "token_type": "Bearer",
        }))
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn cold_start_grants_caches_and_rotates(pool: PgPool) {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_string_contains("grant_type=refresh_token"))
            .and(body_string_contains("refresh_token=initial-refresh"))
            .and(body_string_contains("client_id=client-A"))
            .and(body_string_contains("client_secret=secret-A"))
            .respond_with(ok_token_response("access-A", "rotated-refresh", 3600))
            .expect(1)
            .mount(&server)
            .await;

        let engine = test_engine();
        let tenant_id = TenantId::generate();
        seed_tenant_with_creds(
            &pool,
            &tenant_id,
            &engine,
            Some("client-A"),
            Some("secret-A"),
            Some("initial-refresh"),
        )
        .await;

        let provider = OAuth2TokenProvider::new(
            tenant_id.clone(),
            pool.clone(),
            http_client(),
            server.uri(),
            Arc::clone(&engine),
            safety_margin(),
        );

        let token = provider.get().await.expect("get returns Ok");
        assert_eq!(format!("{token:?}"), "AccessToken(***)");
        assert_eq!(
            provider.cached_access_raw().await.as_deref(),
            Some("access-A")
        );
        assert_eq!(
            read_refresh_column(&pool, &tenant_id, &engine)
                .await
                .as_deref(),
            Some("rotated-refresh"),
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn warm_path_returns_cached_without_calling_token_endpoint(pool: PgPool) {
        let server = MockServer::start().await;
        // First call grants once.
        Mock::given(method("POST"))
            .respond_with(ok_token_response("access-1", "rotated-1", 3600))
            .expect(1)
            .mount(&server)
            .await;

        let engine = test_engine();
        let tenant_id = TenantId::generate();
        seed_tenant_with_creds(
            &pool,
            &tenant_id,
            &engine,
            Some("client"),
            Some("secret"),
            Some("refresh"),
        )
        .await;

        let provider = OAuth2TokenProvider::new(
            tenant_id,
            pool,
            http_client(),
            server.uri(),
            Arc::clone(&engine),
            safety_margin(),
        );

        let _first = provider.get().await.expect("first get");
        let _second = provider.get().await.expect("second get");
        // wiremock's `.expect(1)` enforces exactly one POST.
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn pre_emptive_refresh_when_inside_safety_margin(pool: PgPool) {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            // expires_in: 10s, safety_margin: 30s -> always inside the margin.
            .respond_with(ok_token_response("access-near-expiry", "rotated-1", 10))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ok_token_response("access-fresh", "rotated-2", 3600))
            .expect(1)
            .mount(&server)
            .await;

        let engine = test_engine();
        let tenant_id = TenantId::generate();
        seed_tenant_with_creds(
            &pool,
            &tenant_id,
            &engine,
            Some("client"),
            Some("secret"),
            Some("refresh"),
        )
        .await;

        let provider = OAuth2TokenProvider::new(
            tenant_id.clone(),
            pool.clone(),
            http_client(),
            server.uri(),
            Arc::clone(&engine),
            safety_margin(),
        );

        let _first = provider.get().await.expect("first get");
        // Cache is now populated but already inside the safety margin;
        // the second get must trigger a fresh grant.
        let _second = provider.get().await.expect("second get");
        assert_eq!(
            provider.cached_access_raw().await.as_deref(),
            Some("access-fresh"),
        );
        assert_eq!(
            read_refresh_column(&pool, &tenant_id, &engine)
                .await
                .as_deref(),
            Some("rotated-2"),
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn invalidate_forces_grant_even_when_fresh(pool: PgPool) {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ok_token_response("access-1", "rotated-1", 3600))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ok_token_response("access-2", "rotated-2", 3600))
            .expect(1)
            .mount(&server)
            .await;

        let engine = test_engine();
        let tenant_id = TenantId::generate();
        seed_tenant_with_creds(
            &pool,
            &tenant_id,
            &engine,
            Some("client"),
            Some("secret"),
            Some("refresh"),
        )
        .await;

        let provider = OAuth2TokenProvider::new(
            tenant_id,
            pool,
            http_client(),
            server.uri(),
            Arc::clone(&engine),
            safety_margin(),
        );

        let _first = provider.get().await.expect("first get");
        assert_eq!(
            provider.cached_access_raw().await.as_deref(),
            Some("access-1")
        );
        let _second = provider.invalidate().await.expect("invalidate");
        assert_eq!(
            provider.cached_access_raw().await.as_deref(),
            Some("access-2")
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn refresh_token_rejected_returns_terminal_error_and_rolls_back(pool: PgPool) {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": "invalid_grant",
                "error_description": "Token is not active",
            })))
            .expect(1)
            .mount(&server)
            .await;

        let engine = test_engine();
        let tenant_id = TenantId::generate();
        seed_tenant_with_creds(
            &pool,
            &tenant_id,
            &engine,
            Some("client"),
            Some("secret"),
            Some("dead-refresh"),
        )
        .await;

        let provider = OAuth2TokenProvider::new(
            tenant_id.clone(),
            pool.clone(),
            http_client(),
            server.uri(),
            Arc::clone(&engine),
            safety_margin(),
        );

        let err = provider.get().await.expect_err("get must fail");
        match err {
            TokenProviderError::RefreshRejected(msg) => {
                assert!(msg.contains("invalid_grant"), "msg was: {msg}");
            }
            other => panic!("expected RefreshRejected, got {other:?}"),
        }
        // Transaction rolled back: the dead refresh token is unchanged.
        assert_eq!(
            read_refresh_column(&pool, &tenant_id, &engine)
                .await
                .as_deref(),
            Some("dead-refresh"),
        );
        assert!(provider.cached_access_raw().await.is_none());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn transport_error_is_retryable(pool: PgPool) {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&server)
            .await;

        let engine = test_engine();
        let tenant_id = TenantId::generate();
        seed_tenant_with_creds(
            &pool,
            &tenant_id,
            &engine,
            Some("client"),
            Some("secret"),
            Some("refresh"),
        )
        .await;

        let provider = OAuth2TokenProvider::new(
            tenant_id,
            pool,
            http_client(),
            server.uri(),
            Arc::clone(&engine),
            safety_margin(),
        );

        let err = provider.get().await.expect_err("get must fail");
        assert!(matches!(err, TokenProviderError::Transport(_)));
        assert!(err.is_retryable());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn missing_client_id_returns_missing_credentials(pool: PgPool) {
        let server = MockServer::start().await;
        // No mock — provider must not call the endpoint.

        let engine = test_engine();
        let tenant_id = TenantId::generate();
        seed_tenant_with_creds(
            &pool,
            &tenant_id,
            &engine,
            None,
            Some("secret"),
            Some("refresh"),
        )
        .await;

        let provider = OAuth2TokenProvider::new(
            tenant_id,
            pool,
            http_client(),
            server.uri(),
            Arc::clone(&engine),
            safety_margin(),
        );

        let err = provider.get().await.expect_err("get must fail");
        match err {
            TokenProviderError::MissingCredentials(msg) => {
                assert!(msg.contains("oauth_client_id"), "msg was: {msg}");
            }
            other => panic!("expected MissingCredentials, got {other:?}"),
        }
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn single_flight_collapses_concurrent_gets_to_one_grant(pool: PgPool) {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            // A small server-side delay encourages tasks to queue on
            // the refresh_lock rather than serialise via the runtime
            // before any of them reach the lock.
            .respond_with(
                ok_token_response("access-shared", "rotated", 3600)
                    .set_delay(StdDuration::from_millis(50)),
            )
            .expect(1)
            .mount(&server)
            .await;

        let engine = test_engine();
        let tenant_id = TenantId::generate();
        seed_tenant_with_creds(
            &pool,
            &tenant_id,
            &engine,
            Some("client"),
            Some("secret"),
            Some("refresh"),
        )
        .await;

        let provider = Arc::new(OAuth2TokenProvider::new(
            tenant_id,
            pool,
            http_client(),
            server.uri(),
            Arc::clone(&engine),
            safety_margin(),
        ));

        let mut handles = Vec::new();
        for _ in 0..5 {
            let p = Arc::clone(&provider);
            handles.push(tokio::spawn(async move { p.get().await }));
        }
        for h in handles {
            h.await.unwrap().expect("get returns Ok");
        }
        // wiremock's `.expect(1)` enforces exactly one POST.
        assert_eq!(
            provider.cached_access_raw().await.as_deref(),
            Some("access-shared"),
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn decode_error_when_response_is_not_token_shaped(pool: PgPool) {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .expect(1)
            .mount(&server)
            .await;

        let engine = test_engine();
        let tenant_id = TenantId::generate();
        seed_tenant_with_creds(
            &pool,
            &tenant_id,
            &engine,
            Some("client"),
            Some("secret"),
            Some("refresh"),
        )
        .await;

        let provider = OAuth2TokenProvider::new(
            tenant_id,
            pool,
            http_client(),
            server.uri(),
            Arc::clone(&engine),
            safety_margin(),
        );

        let err = provider.get().await.expect_err("get must fail");
        assert!(matches!(err, TokenProviderError::Decode(_)));
        assert!(!err.is_retryable());
    }
}
