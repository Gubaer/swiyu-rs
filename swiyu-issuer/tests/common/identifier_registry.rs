#![allow(dead_code)] // not every test module pulls in this helper

use super::fixtures::{SAMPLE_PARTNER_ID, SAMPLE_REGISTRY_UUID};

pub const SAMPLE_SCID: &str = "Qm-fixture-scid";

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
