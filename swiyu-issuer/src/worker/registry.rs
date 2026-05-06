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
use std::sync::Arc;

use swiyu_core::did::DID;
use swiyu_core::didlog::{DIDLog, DIDLogEntry};
use swiyu_registries::common::RegistryError;
use swiyu_registries::identifier::{Allocation, IdentifierRegistryClient};
use swiyu_registries::status::{StatusListEntry, StatusRegistryClient};

/// A successful `fetch_log` result.
///
/// Pairs the raw JSONL body the registry returned with the parsed
/// entries. Both views matter because the SWIYU registry's PUT
/// endpoint is "replace the whole log", not "append": each
/// publish_log step needs the parsed entries to build the next entry
/// on top, and the raw bytes to put back the prior entries verbatim.
/// Re-serialising the parsed entries would risk byte-level drift
/// (key ordering, whitespace) and corrupt the entryHash chain.
pub struct FetchedLog {
    pub raw: String,
    pub entries: Vec<DIDLogEntry>,
}

/// Concatenates the existing JSONL log with a single new entry line,
/// producing the body to PUT back to the SWIYU registry. Mirrors
/// swiyu-didtool's `build_updated_log` so both producers send the
/// same shape: previous lines verbatim, one `\n`, the new line, and
/// no trailing newline.
pub fn build_updated_log(prev_raw: &str, new_line: &str) -> String {
    let mut out = prev_raw.trim_end_matches('\n').to_string();
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(new_line);
    out
}

/// The registry operations the worker drives across `CreateIssuer`
/// and `DeactivateIssuer` tasks: allocate the DID space, fetch the
/// current DIDLog tail, and publish a signed DIDLog entry.
///
/// `fetch_log` is keyed by DID rather than by partner-id +
/// identifier because the public resolver lives at the URL the DID
/// itself encodes (see [`DID::log_url`]) — on SWIYU integration that
/// is a different host from the partner-write API. Allocate and
/// publish stay keyed by partner-id + identifier because both target
/// the partner-write API.
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
        did: &DID,
    ) -> impl Future<Output = Result<FetchedLog, RegistryError>> + Send;
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

    async fn fetch_log(&self, did: &DID) -> Result<FetchedLog, RegistryError> {
        let raw = IdentifierRegistryClient::fetch_log(self, did).await?;
        let entries = DIDLog::try_from_jsonl(&raw)
            .map(DIDLog::into_entries)
            .map_err(|e| RegistryError::Decode(format!("DIDLog parse: {e}")))?;
        Ok(FetchedLog { raw, entries })
    }
}

/// Lets tests share a `RegistryFacade` impl between the worker
/// (which takes ownership) and the test body (which inspects mock
/// invocations after the run). All methods auto-deref through the
/// `Arc` to the inner value.
impl<T: RegistryFacade + ?Sized> RegistryFacade for Arc<T> {
    fn allocate_did(
        &self,
        partner_id: &str,
    ) -> impl Future<Output = Result<Allocation, RegistryError>> + Send {
        T::allocate_did(self, partner_id)
    }

    fn publish_log_entry(
        &self,
        partner_id: &str,
        identifier: &str,
        entry: &str,
    ) -> impl Future<Output = Result<(), RegistryError>> + Send {
        T::publish_log_entry(self, partner_id, identifier, entry)
    }

    fn fetch_log(
        &self,
        did: &DID,
    ) -> impl Future<Output = Result<FetchedLog, RegistryError>> + Send {
        T::fetch_log(self, did)
    }
}

/// SWIYU Status Registry operations the worker drives across
/// `CreateIssuer` (allocate the issuer's first registry-side entry) and
/// the phase-2 publish loop (PUT signed status-list JWTs). Mirrors
/// [`RegistryFacade`] so step executors can be unit-tested against an
/// in-memory mock without pulling wiremock into scope.
pub trait StatusRegistryFacade: Send + Sync {
    fn create_status_list_entry(
        &self,
        partner_id: &str,
    ) -> impl Future<Output = Result<StatusListEntry, RegistryError>> + Send;
}

impl StatusRegistryFacade for StatusRegistryClient {
    fn create_status_list_entry(
        &self,
        partner_id: &str,
    ) -> impl Future<Output = Result<StatusListEntry, RegistryError>> + Send {
        StatusRegistryClient::create_status_list_entry(self, partner_id)
    }
}

impl<T: StatusRegistryFacade + ?Sized> StatusRegistryFacade for Arc<T> {
    fn create_status_list_entry(
        &self,
        partner_id: &str,
    ) -> impl Future<Output = Result<StatusListEntry, RegistryError>> + Send {
        T::create_status_list_entry(self, partner_id)
    }
}
