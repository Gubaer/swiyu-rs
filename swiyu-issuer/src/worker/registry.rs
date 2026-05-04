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

use swiyu_registries::common::RegistryError;
use swiyu_registries::identifier::{Allocation, IdentifierRegistryClient};

/// The two registry operations the worker drives during a
/// `CreateIssuer` task: allocate the DID space and publish the
/// signed initial DIDLog entry. `fetch_log` exists on the underlying
/// client but is not part of any worker step in v1.
///
/// Errors flow through as [`RegistryError`]; callers route between
/// `StepOutcome::Retry` and `StepOutcome::Terminal` via
/// [`RegistryError::is_retryable`].
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
}
