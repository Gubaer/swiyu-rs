//! End-to-end happy-path tests for `StatusRegistryClient`, driving
//! the crate's public API against a mock server. Per-error variants
//! and edge cases are covered by the in-module unit tests; these
//! tests exist to catch breakage in the public re-exports and the
//! surface a downstream consumer would actually use.

#![cfg(feature = "status")]

use swiyu_registries::common::AccessToken;
use swiyu_registries::status::{ListParams, StatusRegistryClient};
use wiremock::matchers::{body_string, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PARTNER: &str = "8432e1f3-8119-4fb9-a879-190ab2cb9deb";
const ENTRY_ID: &str = "18fa7c77-9dd1-4e20-a147-fb1bec146085";
const TOKEN: &str = "test-token";
const REGISTRY_URL: &str =
    "https://status-registry.admin.ch/api/v1/statuslist/18fa7c77-9dd1-4e20-a147-fb1bec146085.jwt";

async fn fixture() -> (MockServer, StatusRegistryClient) {
    let server = MockServer::start().await;
    let client = StatusRegistryClient::with_http(server.uri(), reqwest::Client::new());
    (server, client)
}

fn token() -> AccessToken {
    AccessToken::new(TOKEN.to_string())
}

#[tokio::test]
async fn create_status_list_entry_returns_entry() {
    let (server, client) = fixture().await;

    Mock::given(method("POST"))
        .and(path(format!(
            "/api/v1/status/business-entities/{PARTNER}/status-list-entries/"
        )))
        .and(header("Authorization", format!("Bearer {TOKEN}").as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": ENTRY_ID,
            "statusRegistryUrl": REGISTRY_URL,
        })))
        .mount(&server)
        .await;

    let entry = client
        .create_status_list_entry(&token(), PARTNER)
        .await
        .unwrap();
    assert_eq!(entry.id, ENTRY_ID);
    assert_eq!(entry.registry_url, REGISTRY_URL);
}

#[tokio::test]
async fn update_status_list_entry_succeeds() {
    let (server, client) = fixture().await;
    let jwt = "eyJhbGciOiJFUzI1NiJ9.eyJzdGF0dXNfbGlzdCI6e319.signature";

    Mock::given(method("PUT"))
        .and(path(format!(
            "/api/v1/status/business-entities/{PARTNER}/status-list-entries/{ENTRY_ID}"
        )))
        .and(header("Authorization", format!("Bearer {TOKEN}").as_str()))
        .and(header("Content-Type", "application/statuslist+jwt"))
        .and(body_string(jwt))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    client
        .update_status_list_entry(&token(), PARTNER, ENTRY_ID, jwt)
        .await
        .unwrap();
}

#[tokio::test]
async fn list_status_list_entries_returns_page() {
    let (server, client) = fixture().await;

    Mock::given(method("GET"))
        .and(path(format!(
            "/api/v1/status/business-entities/{PARTNER}/status-list-entries/"
        )))
        .and(header("Authorization", format!("Bearer {TOKEN}").as_str()))
        .and(query_param("page", "0"))
        .and(query_param("size", "20"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "totalElements": 1,
            "totalPages": 1,
            "size": 20,
            "number": 0,
            "content": [
                {
                    "id": ENTRY_ID,
                    "createdAt": "2024-10-29T09:35:16.809924Z",
                    "updatedAt": "2024-10-29T09:35:16.809924Z",
                }
            ],
        })))
        .mount(&server)
        .await;

    let page = client
        .list_status_list_entries(&token(), PARTNER, ListParams::default())
        .await
        .unwrap();
    assert_eq!(page.entries.len(), 1);
    assert_eq!(page.entries[0].id, ENTRY_ID);
    assert_eq!(page.total_elements, 1);
    assert_eq!(page.total_pages, 1);
    assert_eq!(page.page, 0);
    assert_eq!(page.size, 20);
}
