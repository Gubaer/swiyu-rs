//! In-memory test doubles for `RegistryFacade` and `SigningEngine`.
//!
//! Used by the per-step executor unit tests so they stay fast and
//! independent of Postgres or wiremock. Each mock records calls in
//! order and replays a pre-configured queue of outcomes; tests fail
//! loudly on under- or over-call.
//!
//! New variants are added alongside the executors that need them.

use std::future::Future;
use std::sync::Mutex;

use swiyu_core::didlog::DIDLogEntry;
use swiyu_registries::common::RegistryError;
use swiyu_registries::identifier::Allocation;

use crate::domain::{
    GeneratedKeyPair, KeyPairId, KeyRole, RawPublicKey, Signature, SigningEngine,
    SigningEngineError,
};

use super::registry::RegistryFacade;

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
    pub fetch_log_invocations: Mutex<Vec<String>>,
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
        identifier: &str,
    ) -> impl Future<Output = Result<Vec<DIDLogEntry>, RegistryError>> + Send {
        self.fetch_log_invocations
            .lock()
            .unwrap()
            .push(identifier.to_string());
        let next = self.fetch_log_queue.lock().unwrap().remove(0);
        async move {
            match next {
                FetchLogCall::Ok(entries) => Ok(entries),
                FetchLogCall::HttpStatus { status, body } => {
                    Err(RegistryError::HttpStatus { status, body })
                }
                FetchLogCall::Decode(message) => Err(RegistryError::Decode(message)),
            }
        }
    }
}

pub enum GenerateKeypairCall {
    Ok(GeneratedKeyPair),
    Backend(String),
    Unsupported,
}

pub enum GetPublicKeyCall {
    Ok(RawPublicKey),
    NotFound(KeyPairId),
    Backend(String),
}

pub enum SignCall {
    Ok(Signature),
    NotFound(KeyPairId),
    Backend(String),
}

#[derive(Default)]
pub struct MockSigningEngine {
    generate_queue: Mutex<Vec<GenerateKeypairCall>>,
    public_key_queue: Mutex<Vec<GetPublicKeyCall>>,
    sign_queue: Mutex<Vec<SignCall>>,
    pub generate_invocations: Mutex<Vec<KeyRole>>,
    pub public_key_invocations: Mutex<Vec<KeyPairId>>,
    pub sign_invocations: Mutex<Vec<(KeyPairId, Vec<u8>)>>,
}

impl MockSigningEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enqueue_generate(&self, call: GenerateKeypairCall) {
        self.generate_queue.lock().unwrap().push(call);
    }

    pub fn enqueue_public_key(&self, call: GetPublicKeyCall) {
        self.public_key_queue.lock().unwrap().push(call);
    }

    pub fn enqueue_sign(&self, call: SignCall) {
        self.sign_queue.lock().unwrap().push(call);
    }
}

impl SigningEngine for MockSigningEngine {
    fn generate_keypair(
        &self,
        role: KeyRole,
    ) -> impl Future<Output = Result<GeneratedKeyPair, SigningEngineError>> + Send {
        self.generate_invocations.lock().unwrap().push(role);
        let next = self.generate_queue.lock().unwrap().remove(0);
        async move {
            match next {
                GenerateKeypairCall::Ok(kp) => Ok(kp),
                GenerateKeypairCall::Backend(message) => {
                    Err(SigningEngineError::Backend(message.into()))
                }
                GenerateKeypairCall::Unsupported => Err(SigningEngineError::UnsupportedAlgorithm),
            }
        }
    }

    fn get_public_key(
        &self,
        id: &KeyPairId,
    ) -> impl Future<Output = Result<RawPublicKey, SigningEngineError>> + Send {
        self.public_key_invocations.lock().unwrap().push(*id);
        let next = self.public_key_queue.lock().unwrap().remove(0);
        async move {
            match next {
                GetPublicKeyCall::Ok(pk) => Ok(pk),
                GetPublicKeyCall::NotFound(id) => Err(SigningEngineError::KeyNotFound(id)),
                GetPublicKeyCall::Backend(message) => {
                    Err(SigningEngineError::Backend(message.into()))
                }
            }
        }
    }

    fn sign(
        &self,
        id: &KeyPairId,
        input: &[u8],
    ) -> impl Future<Output = Result<Signature, SigningEngineError>> + Send {
        self.sign_invocations
            .lock()
            .unwrap()
            .push((*id, input.to_vec()));
        let next = self.sign_queue.lock().unwrap().remove(0);
        async move {
            match next {
                SignCall::Ok(sig) => Ok(sig),
                SignCall::NotFound(id) => Err(SigningEngineError::KeyNotFound(id)),
                SignCall::Backend(message) => Err(SigningEngineError::Backend(message.into())),
            }
        }
    }

    async fn delete_keypair(&self, _id: &KeyPairId) -> Result<(), SigningEngineError> {
        Ok(())
    }
}
