//! Async-trait abstraction over the SWIYU Identifier Registry HTTP
//! client.
//!
//! Step executors take an `&impl RegistryFacade` so unit tests can
//! inject an in-memory mock without pulling wiremock into the
//! unit-test scope, while production code passes the real
//! [`IdentifierRegistry`] wrapping `swiyu_registries`'s async client.
//! Native async-in-trait (Rust 2024) with explicit `+ Send` bounds
//! keeps futures unboxed; the trait is consumed via generics rather
//! than `&dyn` because `impl Future` is not object-safe.

use std::future::Future;

use swiyu_core::didlog::{DIDLog, DIDLogEntry};
use swiyu_registries::common::RegistryError;
use swiyu_registries::identifier::{Allocation, IdentifierRegistryClient};

/// The registry operations the worker drives across `CreateIssuer`
/// and `DeactivateIssuer` tasks: allocate the DID space, fetch the
/// current DIDLog tail, and publish a signed DIDLog entry.
///
/// Errors flow through as [`RegistryError`]; callers route between
/// `StepOutcome::Retry` and `StepOutcome::Terminal` via
/// [`RegistryError::is_retryable`]. `fetch_log` parses the JSONL
/// body into typed entries on the way out — a malformed body becomes
/// [`RegistryError::Decode`] (non-retryable), so step executors do
/// not see raw text.
pub trait RegistryFacade: Send + Sync {
    fn allocate_did(
        &self,
        partner_id: &str,
    ) -> impl Future<Output = Result<Allocation, RegistryError>> + Send;

    fn publish_log_entry(
        &self,
        partner_id: &str,
        identifier: &str,
        entry: &str,
    ) -> impl Future<Output = Result<(), RegistryError>> + Send;

    fn fetch_log(
        &self,
        identifier: &str,
    ) -> impl Future<Output = Result<Vec<DIDLogEntry>, RegistryError>> + Send;
}

impl RegistryFacade for IdentifierRegistryClient {
    fn allocate_did(
        &self,
        partner_id: &str,
    ) -> impl Future<Output = Result<Allocation, RegistryError>> + Send {
        IdentifierRegistryClient::allocate_did(self, partner_id)
    }

    fn publish_log_entry(
        &self,
        partner_id: &str,
        identifier: &str,
        entry: &str,
    ) -> impl Future<Output = Result<(), RegistryError>> + Send {
        IdentifierRegistryClient::publish_log_entry(self, partner_id, identifier, entry)
    }

    async fn fetch_log(&self, identifier: &str) -> Result<Vec<DIDLogEntry>, RegistryError> {
        let body = IdentifierRegistryClient::fetch_log(self, identifier).await?;
        DIDLog::try_from_jsonl(&body)
            .map(DIDLog::into_entries)
            .map_err(|e| RegistryError::Decode(format!("DIDLog parse: {e}")))
    }
}
