//! Test fixtures specific to the create-issuer saga step tests.

use crate::test_support::domain::signing_engine::{
    GetPublicKeyCall, MockSigningEngine, SignCall, fixture_ed25519_pk, fixture_p256_pk,
    fixture_signature,
};
use crate::test_support::fixture_kid;
use crate::worker::create_issuer::{CreateIssuerStateData, KeyTriple};

/// Pre-loads one create-issuer didlog step's engine calls: three
/// `get_public_key` calls (Ed25519 authorized, P-256 authentication,
/// P-256 assertion) followed by one Ed25519 signature.
pub fn enqueue_happy_step(engine: &MockSigningEngine) {
    engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_ed25519_pk()));
    engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_p256_pk()));
    engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_p256_pk()));
    engine.enqueue_sign(SignCall::Ok(fixture_signature()));
}

/// Fresh engine pre-loaded with exactly one happy-path
/// create-issuer didlog step.
pub fn engine_for_happy_path() -> MockSigningEngine {
    let engine = MockSigningEngine::new();
    enqueue_happy_step(&engine);
    engine
}

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
