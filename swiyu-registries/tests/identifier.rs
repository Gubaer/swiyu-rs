//! End-to-end happy-path tests for `IdentifierRegistryClient`,
//! driving the crate's public API against a mock server. Per-error
//! variants and edge cases are covered by the in-module unit tests;
//! these tests exist to catch breakage in the public re-exports and
//! the surface a downstream consumer would actually use.

use swiyu_registries::common::AccessToken;
use swiyu_registries::identifier::IdentifierRegistryClient;
use wiremock::matchers::{body_string, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PARTNER: &str = "4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef";
const IDENTIFIER: &str = "fce949f2-32c4-4915-8b60-0ee2f705231d";
const TOKEN: &str = "test-token";

async fn fixture() -> (MockServer, IdentifierRegistryClient) {
    let server = MockServer::start().await;
    let client = IdentifierRegistryClient::with_http(server.uri(), reqwest::Client::new());
    (server, client)
}

fn token() -> AccessToken {
    AccessToken::new(TOKEN.to_string())
}

#[tokio::test]
async fn allocate_did_returns_allocation() {
    let (server, client) = fixture().await;
    let registry_url =
        format!("https://identifier-reg.swiyu.admin.ch/api/v1/did/{IDENTIFIER}/did.jsonl");

    Mock::given(method("POST"))
        .and(path(format!(
            "/api/v1/identifier/business-entities/{PARTNER}/identifier-entries"
        )))
        .and(header("Authorization", format!("Bearer {TOKEN}").as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "identifierRegistryUrl": registry_url,
        })))
        .mount(&server)
        .await;

    let allocation = client.allocate_did(&token(), PARTNER).await.unwrap();
    assert_eq!(allocation.url, registry_url);
    assert_eq!(allocation.identifier, IDENTIFIER);
}

#[tokio::test]
async fn publish_log_entry_succeeds() {
    let (server, client) = fixture().await;
    let entry =
        r#"["1-abc","2026-05-04T00:00:00Z",{"method":"did:tdw:0.3"},{"value":"did:tdw:abc"}]"#;

    Mock::given(method("PUT"))
        .and(path(format!(
            "/api/v1/identifier/business-entities/{PARTNER}/identifier-entries/{IDENTIFIER}"
        )))
        .and(header("Authorization", format!("Bearer {TOKEN}").as_str()))
        .and(header("Content-Type", "application/jsonl+json"))
        .and(body_string(entry))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    client
        .publish_log_entry(&token(), PARTNER, IDENTIFIER, entry)
        .await
        .unwrap();
}
