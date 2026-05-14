use swiyu_registries::status::StatusListEntry;

use crate::test_support::fixtures::{SAMPLE_STATUS_ENTRY_ID, SAMPLE_STATUS_REGISTRY_URL};
use crate::test_support::worker::{CreateStatusListEntryCall, MockStatusRegistry};

pub fn with_one_ok() -> MockStatusRegistry {
    let r = MockStatusRegistry::new();
    r.enqueue_create(CreateStatusListEntryCall::Ok(StatusListEntry {
        id: SAMPLE_STATUS_ENTRY_ID.into(),
        registry_url: SAMPLE_STATUS_REGISTRY_URL.into(),
    }));
    r
}
