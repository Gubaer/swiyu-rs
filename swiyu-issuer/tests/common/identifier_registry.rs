#![allow(dead_code)] // not every test module pulls in this helper

use serde_json::{Value, json};
use swiyu_core::didlog::DIDLogEntry;
use swiyu_registries::identifier::IdentifierRegistryClient;
use wiremock::MockServer;

use super::fixtures::{SAMPLE_PARTNER_ID, SAMPLE_REGISTRY_UUID};

pub const SAMPLE_SCID: &str = "Qm-fixture-scid";

pub fn build_client(server: &MockServer) -> IdentifierRegistryClient {
    IdentifierRegistryClient::with_http(server.uri(), reqwest::Client::new())
}

pub fn allocate_path() -> String {
    format!("/api/v1/identifier/business-entities/{SAMPLE_PARTNER_ID}/identifier-entries")
}

pub fn publish_path() -> String {
    format!(
        "/api/v1/identifier/business-entities/{SAMPLE_PARTNER_ID}/identifier-entries/{SAMPLE_REGISTRY_UUID}"
    )
}

pub fn registry_url_in_response() -> String {
    format!("https://reg.test/api/v1/did/{SAMPLE_REGISTRY_UUID}/did.jsonl")
}

pub fn fixture_did() -> String {
    format!("did:tdw:{SAMPLE_SCID}:reg.test:{SAMPLE_REGISTRY_UUID}")
}

// Saga steps only read version_id, parameters.deactivated / .update_keys, and
// the embedded DID document, so signature bytes and other fields are left out.
pub fn fixture_genesis_entry(update_keys: &[&str]) -> DIDLogEntry {
    let value: Value = json!([
        "1-Qmfixture-genesis-version-id",
        "2026-04-01T00:00:00Z",
        {
            "method": "did:tdw:0.3",
            "scid": SAMPLE_SCID,
            "updateKeys": update_keys,
            "portable": false,
        },
        {
            "value": {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": fixture_did(),
            }
        },
        [],
    ]);
    DIDLogEntry::try_from(&value).expect("fixture genesis parses")
}
