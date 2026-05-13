#![allow(dead_code)] // not every test module pulls in this helper

use uuid::Uuid;

use swiyu_issuer::domain::KeyPairId;

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
