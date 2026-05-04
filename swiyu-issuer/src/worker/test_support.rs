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

use swiyu_registries::common::RegistryError;
use swiyu_registries::identifier::Allocation;

use super::registry::RegistryFacade;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllocateCall {
    Ok(Allocation),
    HttpStatus { status: u16, body: String },
    Decode(String),
}

#[derive(Default)]
pub struct MockRegistry {
    allocate_queue: Mutex<Vec<AllocateCall>>,
    pub allocate_invocations: Mutex<Vec<String>>,
}

impl MockRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enqueue_allocate(&self, call: AllocateCall) {
        self.allocate_queue.lock().unwrap().push(call);
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

    async fn publish_log_entry(
        &self,
        _partner_id: &str,
        _identifier: &str,
        _entry: &str,
    ) -> Result<(), RegistryError> {
        unreachable!("publish path not exercised in this test scope")
    }
}
