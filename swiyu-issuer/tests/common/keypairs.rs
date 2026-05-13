#![allow(dead_code)] // not every test module pulls in this helper

use uuid::Uuid;

use swiyu_issuer::domain::{KeyAlgorithm, KeyPairId, RawPublicKey, Signature};

/// Produces a deterministic `KeyPairId` from a single seed byte by
/// filling all 16 UUID bytes with the seed and forcing the UUIDv4
/// version/variant bits. Useful when tests need to assert on a
/// specific id without coordinating with a real engine.
pub fn fixture_kid(byte: u8) -> KeyPairId {
    let mut bytes = [byte; 16];
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    KeyPairId::from(Uuid::from_bytes(bytes))
}

pub fn fixture_ed25519_pk() -> RawPublicKey {
    RawPublicKey {
        algorithm: KeyAlgorithm::Ed25519,
        bytes: vec![0xab; 32],
    }
}

pub fn fixture_p256_pk() -> RawPublicKey {
    let mut bytes = vec![0x04];
    bytes.extend_from_slice(&[0xcd; 32]);
    bytes.extend_from_slice(&[0xef; 32]);
    RawPublicKey {
        algorithm: KeyAlgorithm::EcdsaP256,
        bytes,
    }
}

pub fn fixture_signature() -> Signature {
    Signature {
        algorithm: KeyAlgorithm::Ed25519,
        bytes: vec![0x42; 64],
    }
}
