//! Shared scaffolding for tests that construct a `Worker` or
//! `StatusListPublisher`. Both now require an `Arc<ProviderRegistry>`
//! whose first `provider_for(tenant)` call drives a real
//! `OAuth2TokenProvider`, so every such test needs a `wiremock` token
//! endpoint serving an OK token response and a tenant row with
//! `oauth_*` columns populated.

#![allow(dead_code)] // not every test module uses every helper

// The OAuth2 secret columns (oauth_client_secret, oauth_refresh_token)
// are BYTEA and persist self-describing ciphertext blobs. Seed values
// must be encrypted with the same engine the ProviderRegistry will
// later use to decrypt them, so test_engine, insert_tenant_with_oauth_secrets,
// and build_provider_registry must all see the same Arc.

use std::sync::Arc;

use chrono::Duration;
use reqwest::Client;
use serde_json::json;
use sqlx::PgPool;
use swiyu_issuer::domain::{
    AnySecretEncryptionEngine, DevSecretEncryptionEngine, ProviderRegistry, SecretEncryptionEngine,
    TenantId,
};
use swiyu_issuer::persistence::tenant_secret_keys::{
    oauth2_client_secret_key_name, oauth2_refresh_token_key_name,
};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

pub async fn mock_token_endpoint() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "test-access",
            "refresh_token": "rotated-refresh",
            "expires_in": 3600,
            "token_type": "Bearer",
        })))
        .mount(&server)
        .await;
    server
}

pub fn test_engine() -> Arc<AnySecretEncryptionEngine> {
    Arc::new(AnySecretEncryptionEngine::Dev(
        DevSecretEncryptionEngine::new([0x42u8; 32]),
    ))
}

pub fn build_provider_registry(
    pool: PgPool,
    token_url: String,
    engine: Arc<AnySecretEncryptionEngine>,
) -> Arc<ProviderRegistry> {
    Arc::new(ProviderRegistry::new(
        pool,
        Client::new(),
        token_url,
        engine,
        Duration::seconds(30),
    ))
}

// Caller must keep the returned MockServer alive for the duration of any worker
// run; dropping it closes the bound port and breaks subsequent provider.get() calls.
pub async fn build_provider_setup(
    pool: &PgPool,
    engine: Arc<AnySecretEncryptionEngine>,
) -> (MockServer, Arc<ProviderRegistry>) {
    let server = mock_token_endpoint().await;
    let providers = build_provider_registry(pool.clone(), server.uri(), engine);
    (server, providers)
}

pub async fn insert_tenant_with_oauth_secrets(
    pool: &PgPool,
    tenant_id: &TenantId,
    partner_id: uuid::Uuid,
    engine: &AnySecretEncryptionEngine,
    client_id: &str,
    client_secret: &str,
    refresh_token: &str,
) {
    let client_secret_blob = engine
        .encrypt(
            &oauth2_client_secret_key_name(tenant_id),
            client_secret.as_bytes(),
        )
        .await
        .unwrap()
        .into_bytes();
    let refresh_token_blob = engine
        .encrypt(
            &oauth2_refresh_token_key_name(tenant_id),
            refresh_token.as_bytes(),
        )
        .await
        .unwrap()
        .into_bytes();
    sqlx::query(
        "INSERT INTO tenants (id, partner_id, oauth_client_id, oauth_client_secret, oauth_refresh_token)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(tenant_id.bare())
    .bind(partner_id)
    .bind(client_id)
    .bind(client_secret_blob)
    .bind(refresh_token_blob)
    .execute(pool)
    .await
    .unwrap();
}

pub async fn insert_test_tenant_with_oauth(
    pool: &PgPool,
    tenant_id: &TenantId,
    engine: &AnySecretEncryptionEngine,
) {
    insert_tenant_with_oauth_secrets(
        pool,
        tenant_id,
        super::fixtures::SAMPLE_PARTNER_ID
            .parse()
            .expect("SAMPLE_PARTNER_ID parses"),
        engine,
        "test-client",
        "test-secret",
        "test-refresh",
    )
    .await;
}

pub async fn read_refresh_token(
    pool: &PgPool,
    tenant_id: &TenantId,
    engine: &AnySecretEncryptionEngine,
) -> Option<String> {
    let blob: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT oauth_refresh_token FROM tenants WHERE id = $1")
            .bind(tenant_id.bare())
            .fetch_one(pool)
            .await
            .unwrap();
    let bytes = blob?;
    let plaintext = engine
        .decrypt(&oauth2_refresh_token_key_name(tenant_id), &bytes.into())
        .await
        .unwrap();
    Some(String::from_utf8(plaintext).unwrap())
}
