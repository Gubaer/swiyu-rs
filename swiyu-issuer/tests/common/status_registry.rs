#![allow(dead_code)] // not every test module pulls in this helper

use swiyu_issuer::test_support::worker::{CreateStatusListEntryCall, MockStatusRegistry};
use swiyu_registries::status::StatusListEntry;

use super::fixtures::{SAMPLE_STATUS_ENTRY_ID, SAMPLE_STATUS_REGISTRY_URL};

pub fn with_one_ok() -> MockStatusRegistry {
    let r = MockStatusRegistry::new();
    r.enqueue_create(CreateStatusListEntryCall::Ok(StatusListEntry {
        id: SAMPLE_STATUS_ENTRY_ID.into(),
        registry_url: SAMPLE_STATUS_REGISTRY_URL.into(),
    }));
    r
}
