//! Test fixtures specific to the deactivate-issuer saga step tests.

use crate::test_support::domain::signing_engine::{
    GetPublicKeyCall, MockSigningEngine, SignCall, fixture_ed25519_pk, fixture_signature,
};

/// Engine queue for a happy-path deactivate-issuer didlog step: one
/// Authorized public-key read followed by one Ed25519 signature.
pub fn engine_for_happy_path() -> MockSigningEngine {
    let engine = MockSigningEngine::new();
    engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_ed25519_pk()));
    engine.enqueue_sign(SignCall::Ok(fixture_signature()));
    engine
}
