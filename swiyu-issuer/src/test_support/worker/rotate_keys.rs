//! Test fixtures specific to the rotate-keys saga step tests.

use crate::domain::{KeyAlgorithm, RawPublicKey};
use crate::test_support::domain::signing_engine::{
    GetPublicKeyCall, MockSigningEngine, SignCall, fixture_p256_pk, fixture_signature,
};

pub fn fixture_ed25519_pk(seed: u8) -> RawPublicKey {
    RawPublicKey {
        algorithm: KeyAlgorithm::Ed25519,
        bytes: vec![seed; 32],
    }
}

/// Engine queue for a happy-path single-role rotation of authorized:
/// the four `get_public_key` calls (new authorized, new authentication,
/// new assertion, outgoing authorized for the proof's verification_method)
/// plus the one `sign` call.
pub fn engine_for_happy_path() -> MockSigningEngine {
    let engine = MockSigningEngine::new();
    // new authorized
    engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_ed25519_pk(0xAA)));
    // new authentication
    engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_p256_pk()));
    // new assertion
    engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_p256_pk()));
    // outgoing authorized (for verification_method id)
    engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_ed25519_pk(0x11)));
    // sign
    engine.enqueue_sign(SignCall::Ok(fixture_signature()));
    engine
}
