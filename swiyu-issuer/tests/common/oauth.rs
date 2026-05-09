//! Shared scaffolding for tests that construct a `Worker` or
//! `StatusListPublisher`. Both now require an `Arc<ProviderRegistry>`
//! whose first `provider_for(tenant)` call drives a real
//! `OAuth2TokenProvider`, so every such test needs a `wiremock` token
//! endpoint serving an OK token response and a tenant row with
//! `oauth_*` columns populated.

#![allow(dead_code)] // not every test module uses every helper

use std::sync::Arc;

use chrono::Duration;
use reqwest::Client;
use serde_json::json;
use sqlx::PgPool;
use swiyu_issuer::domain::{ProviderRegistry, TenantId};
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

pub fn build_provider_registry(pool: PgPool, token_url: String) -> Arc<ProviderRegistry> {
    Arc::new(ProviderRegistry::new(
        pool,
        Client::new(),
        token_url,
        Duration::seconds(30),
    ))
}

pub async fn seed_tenant_oauth_columns(pool: &PgPool, tenant_id: &TenantId) {
    sqlx::query(
        "UPDATE tenants
         SET oauth_client_id = $1,
             oauth_client_secret = $2,
             oauth_refresh_token = $3
         WHERE id = $4",
    )
    .bind("test-client")
    .bind("test-secret")
    .bind("test-refresh")
    .bind(tenant_id.bare())
    .execute(pool)
    .await
    .unwrap();
}
