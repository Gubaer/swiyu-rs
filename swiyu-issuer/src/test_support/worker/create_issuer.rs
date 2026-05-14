//! Test fixtures specific to the create-issuer saga step tests.

use crate::test_support::fixture_kid;
use crate::worker::create_issuer::{CreateIssuerStateData, KeyTriple};

/// Saga state populated as if all preceding steps already ran:
/// the registry returned an allocation, three keys have been
/// generated, and only `didlog_published` is still in flux.
pub fn fixture_state(didlog_published: bool) -> CreateIssuerStateData {
    CreateIssuerStateData {
        assigned_did_url: Some("https://reg.example.com/api/v1/did/abc/did.jsonl".into()),
        assigned_identifier: Some("abc".into()),
        key_ids: Some(KeyTriple {
            authorized: fixture_kid(0x11),
            authentication: fixture_kid(0x22),
            assertion: fixture_kid(0x33),
        }),
        didlog_published,
        status_list_registry_entry_id: None,
        status_list_registry_url: None,
    }
}
