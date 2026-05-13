#![allow(dead_code)] // not every test module pulls in this helper

use uuid::Uuid;

use swiyu_issuer::domain::KeyPairId;

pub fn fixture_kid(byte: u8) -> KeyPairId {
    let mut bytes = [byte; 16];
    // Force the UUIDv4 version/variant bits so the value parses as a valid UUID.
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    KeyPairId::from(Uuid::from_bytes(bytes))
}
