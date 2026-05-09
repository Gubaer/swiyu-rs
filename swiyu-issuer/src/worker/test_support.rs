//! In-memory test doubles for [`RegistryFacade`] and
//! [`StatusRegistryFacade`].
//!
//! Used by the per-step worker tests so they stay fast and
//! independent of Postgres or wiremock. Each mock records calls in
//! order and replays a pre-configured queue of outcomes; tests fail
//! loudly on under- or over-call.
//!
//! The matching `MockSigningEngine` lives in
//! [`crate::domain::signing_engine::test_support`] so the
//! domain → worker dependency direction stays clean.

use std::future::Future;
use std::sync::Mutex;

use serde_json::Value;
use swiyu_core::did::DID;
use swiyu_core::didlog::DIDLogEntry;
use swiyu_registries::common::{AccessToken, RegistryError};
use swiyu_registries::identifier::Allocation;
use swiyu_registries::status::StatusListEntry;

use super::registry_facades::{FetchedLog, RegistryFacade, StatusRegistryFacade};

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
