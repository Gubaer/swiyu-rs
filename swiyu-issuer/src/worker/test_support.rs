//! Shared worker test support: in-memory doubles for [`RegistryFacade`]
//! and [`StatusRegistryFacade`], plus pure value fixtures
//! (`fixture_kid`, `fixture_now`, `fixture_did`, `fixture_p256`) and a
//! deterministic [`ConstantRng`] used across the per-step worker
//! tests so they stay fast and independent of Postgres or wiremock.
//! Each mock records calls in order and replays a pre-configured
//! queue of outcomes; tests fail loudly on under- or over-call.
//!
//! The matching `MockSigningEngine` lives in
//! [`crate::domain::signing_engine::test_support`] so the
//! domain → worker dependency direction stays clean.

use std::future::Future;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use rand_core::RngCore;
use serde_json::Value;
use swiyu_core::did::DID;
use swiyu_core::diddoc::public_keys::P256PublicKey;
use swiyu_core::didlog::DIDLogEntry;
use swiyu_registries::common::{AccessToken, RegistryError};
use swiyu_registries::identifier::Allocation;
use swiyu_registries::status::StatusListEntry;
use uuid::Uuid;

use super::registry_facades::{FetchedLog, RegistryFacade, StatusRegistryFacade};
use crate::domain::{
    GeneratedKeyPair, KeyAlgorithm, KeyPairId, RawPublicKey, StaticTokenProvider, Tenant, TenantId,
};

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

pub fn fixture_keypair(byte: u8, algorithm: KeyAlgorithm, pk_len: usize) -> GeneratedKeyPair {
    GeneratedKeyPair {
        id: fixture_kid(byte),
        public_key: RawPublicKey {
            algorithm,
            bytes: vec![byte; pk_len],
        },
    }
}

pub fn fixture_allocation() -> Allocation {
    Allocation {
        url: "https://reg.example/api/v1/did/abc/did.jsonl".into(),
        identifier: "abc".into(),
    }
}

pub fn fixture_token_provider() -> StaticTokenProvider {
    StaticTokenProvider::new(AccessToken::new("test-token".to_string()))
}

pub fn fixture_tenant(partner_id: &str) -> Tenant {
    Tenant {
        id: TenantId::generate(),
        partner_id: partner_id
            .parse()
            .expect("test partner_id must be a valid UUID"),
        display_name: None,
        description: None,
        oauth_client_id: None,
        oauth_client_secret: None,
        oauth_refresh_token: None,
    }
}

pub fn fixture_p256() -> P256PublicKey {
    P256PublicKey {
        x: [1u8; 32],
        y: [2u8; 32],
    }
}

pub struct ConstantRng(pub u64);

impl RngCore for ConstantRng {
    fn next_u32(&mut self) -> u32 {
        self.0 as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let bytes = self.0.to_le_bytes();
            let take = chunk.len().min(bytes.len());
            chunk[..take].copy_from_slice(&bytes[..take]);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllocateCall {
    Ok(Allocation),
    HttpStatus { status: u16, body: String },
    Decode(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishCall {
    Ok,
    HttpStatus { status: u16, body: String },
}

/// One queued `fetch_log` outcome. `Ok` carries pre-parsed entries —
/// the trait already does the JSONL parse, so unit tests build entry
/// fixtures (e.g. via `DIDLogEntry::new_genesis`) rather than feeding
/// in raw text.
///
/// `Transport`-style errors are not exposed because
/// [`RegistryError::Transport`] wraps a real `reqwest::Error` that
/// cannot be constructed by hand. Tests that need retryable failure
/// use `HttpStatus { status: 5xx, .. }` instead, which
/// [`RegistryError::is_retryable`] reports the same way.
pub enum FetchLogCall {
    Ok(Vec<DIDLogEntry>),
    HttpStatus { status: u16, body: String },
    Decode(String),
}

#[derive(Default)]
pub struct MockRegistry {
    allocate_queue: Mutex<Vec<AllocateCall>>,
    publish_queue: Mutex<Vec<PublishCall>>,
    fetch_log_queue: Mutex<Vec<FetchLogCall>>,
    pub allocate_invocations: Mutex<Vec<String>>,
    pub publish_invocations: Mutex<Vec<(String, String, String)>>,
    pub fetch_log_invocations: Mutex<Vec<DID>>,
}

impl MockRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enqueue_allocate(&self, call: AllocateCall) {
        self.allocate_queue.lock().unwrap().push(call);
    }

    pub fn enqueue_publish(&self, call: PublishCall) {
        self.publish_queue.lock().unwrap().push(call);
    }

    pub fn enqueue_fetch_log(&self, call: FetchLogCall) {
        self.fetch_log_queue.lock().unwrap().push(call);
    }
}

impl RegistryFacade for MockRegistry {
    fn allocate_did(
        &self,
        _token: &AccessToken,
        partner_id: &str,
    ) -> impl Future<Output = Result<Allocation, RegistryError>> + Send {
        self.allocate_invocations
            .lock()
            .unwrap()
            .push(partner_id.to_string());
        let next = self.allocate_queue.lock().unwrap().remove(0);
        async move {
            match next {
                AllocateCall::Ok(allocation) => Ok(allocation),
                AllocateCall::HttpStatus { status, body } => {
                    Err(RegistryError::HttpStatus { status, body })
                }
                AllocateCall::Decode(message) => Err(RegistryError::Decode(message)),
            }
        }
    }

    fn publish_log_entry(
        &self,
        _token: &AccessToken,
        partner_id: &str,
        identifier: &str,
        entry: &str,
    ) -> impl Future<Output = Result<(), RegistryError>> + Send {
        self.publish_invocations.lock().unwrap().push((
            partner_id.to_string(),
            identifier.to_string(),
            entry.to_string(),
        ));
        let next = self.publish_queue.lock().unwrap().remove(0);
        async move {
            match next {
                PublishCall::Ok => Ok(()),
                PublishCall::HttpStatus { status, body } => {
                    Err(RegistryError::HttpStatus { status, body })
                }
            }
        }
    }

    fn fetch_log(
        &self,
        did: &DID,
    ) -> impl Future<Output = Result<FetchedLog, RegistryError>> + Send {
        self.fetch_log_invocations.lock().unwrap().push(did.clone());
        let next = self.fetch_log_queue.lock().unwrap().remove(0);
        async move {
            match next {
                FetchLogCall::Ok(entries) => {
                    // Synthesise the raw JSONL view from the parsed
                    // entries. Byte fidelity does not matter here
                    // because the mock's publish_log_entry accepts
                    // anything; tests that need to verify the published
                    // body inspect publish_invocations directly.
                    let raw = entries
                        .iter()
                        .cloned()
                        .map(|e| {
                            serde_json::to_string(&Value::from(e))
                                .expect("DIDLogEntry serialises to JSON")
                        })
                        .collect::<Vec<_>>()
                        .join("\n");
                    Ok(FetchedLog { raw, entries })
                }
                FetchLogCall::HttpStatus { status, body } => {
                    Err(RegistryError::HttpStatus { status, body })
                }
                FetchLogCall::Decode(message) => Err(RegistryError::Decode(message)),
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateStatusListEntryCall {
    Ok(StatusListEntry),
    HttpStatus { status: u16, body: String },
    Decode(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateStatusListEntryCall {
    Ok,
    HttpStatus { status: u16, body: String },
}

#[derive(Default)]
pub struct MockStatusRegistry {
    create_queue: Mutex<Vec<CreateStatusListEntryCall>>,
    update_queue: Mutex<Vec<UpdateStatusListEntryCall>>,
    pub create_invocations: Mutex<Vec<String>>,
    pub update_invocations: Mutex<Vec<(String, String, String)>>,
}

impl MockStatusRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enqueue_create(&self, call: CreateStatusListEntryCall) {
        self.create_queue.lock().unwrap().push(call);
    }

    pub fn enqueue_update(&self, call: UpdateStatusListEntryCall) {
        self.update_queue.lock().unwrap().push(call);
    }
}

impl StatusRegistryFacade for MockStatusRegistry {
    fn create_status_list_entry(
        &self,
        _token: &AccessToken,
        partner_id: &str,
    ) -> impl Future<Output = Result<StatusListEntry, RegistryError>> + Send {
        self.create_invocations
            .lock()
            .unwrap()
            .push(partner_id.to_string());
        let next = self.create_queue.lock().unwrap().remove(0);
        async move {
            match next {
                CreateStatusListEntryCall::Ok(entry) => Ok(entry),
                CreateStatusListEntryCall::HttpStatus { status, body } => {
                    Err(RegistryError::HttpStatus { status, body })
                }
                CreateStatusListEntryCall::Decode(message) => Err(RegistryError::Decode(message)),
            }
        }
    }

    fn update_status_list_entry(
        &self,
        _token: &AccessToken,
        partner_id: &str,
        entry_id: &str,
        status_list_jwt: &str,
    ) -> impl Future<Output = Result<(), RegistryError>> + Send {
        self.update_invocations.lock().unwrap().push((
            partner_id.to_string(),
            entry_id.to_string(),
            status_list_jwt.to_string(),
        ));
        let next = self.update_queue.lock().unwrap().remove(0);
        async move {
            match next {
                UpdateStatusListEntryCall::Ok => Ok(()),
                UpdateStatusListEntryCall::HttpStatus { status, body } => {
                    Err(RegistryError::HttpStatus { status, body })
                }
            }
        }
    }
}
