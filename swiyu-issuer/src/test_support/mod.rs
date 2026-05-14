// crate-wide test support

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::domain::{Issuer, IssuerId, IssuerState, KeyPairId, TenantId};

pub mod api;
pub mod domain;
pub mod env;
pub mod fixtures;
pub mod http;
pub mod oauth;
pub mod persistence;
pub mod registry;
pub mod time;
pub mod worker;

pub fn fixture_kid(byte: u8) -> KeyPairId {
    let mut bytes = [byte; 16];
    // Force the UUIDv4 version/variant bits so the value parses as a valid UUID.
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    KeyPairId::from(Uuid::from_bytes(bytes))
}

// 1_768_982_400 = 2026-01-21T12:00:00Z.
pub fn fixture_now() -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(1_768_982_400, 0).unwrap()
}

pub const FIXTURE_DID_REGISTRY_UUID: &str = "fce949f2-32c4-4915-8b60-0ee2f705231d";

pub fn fixture_did() -> &'static str {
    "did:tdw:scid-placeholder:reg.example.com:fce949f2-32c4-4915-8b60-0ee2f705231d"
}

pub fn fixture_issuer() -> Issuer {
    Issuer {
        id: IssuerId::generate(),
        tenant_id: TenantId::generate(),
        did: fixture_did().into(),
        state: Some(IssuerState::Active),
        description: Some("fixture".into()),
        authorized_key_id: Some(fixture_kid(0x11)),
        authentication_key_id: Some(fixture_kid(0x22)),
        assertion_key_id: Some(fixture_kid(0x33)),
        display_name: Some("Fixture".into()),
        logo_uri: None,
        locale: None,
        created_at: Utc::now(),
    }
}

pub fn fixture_issuer_minimal() -> Issuer {
    Issuer {
        id: IssuerId::generate(),
        tenant_id: TenantId::generate(),
        did: "did:tdw:9hXq2vRtL8pK7f:example.com".into(),
        state: None,
        description: None,
        authorized_key_id: None,
        authentication_key_id: None,
        assertion_key_id: None,
        display_name: None,
        logo_uri: None,
        locale: None,
        created_at: Utc::now(),
    }
}
