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

use swiyu_core::did::DID;
use swiyu_core::didlog::{DIDLog, DIDLogEntry};
use swiyu_registries::common::RegistryError;
use swiyu_registries::identifier::{Allocation, IdentifierRegistryClient};

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
