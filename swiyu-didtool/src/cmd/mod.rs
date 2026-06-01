pub mod did;
pub mod didlog;
pub mod file;
pub mod http;
pub mod key;
pub mod pop;
pub mod trust;

use std::str::FromStr;

use chrono::{DateTime, SecondsFormat};
use tracing::debug;

use swiyu_core::did::{DID, DIDError};

use crate::keystore::{KeyStore, KeyStoreEntry, KeyStoreError};

/// Drives a single async call to completion from didtool's otherwise
/// synchronous command code, used to invoke the async `swiyu-registries`
/// clients. Spins up a transient current-thread tokio runtime per call.
///
/// Building a current-thread runtime only fails on OS resource exhaustion,
/// which is an environment failure this command cannot act on; there is no
/// useful recovery, so we treat it as unreachable.
pub(crate) fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("building a current-thread tokio runtime")
        .block_on(future)
}

/// Formats a Unix timestamp as a UTC ISO-8601 string with `Z` suffix
/// (e.g. `2026-04-29T18:23:00Z`). Falls back to the raw integer rendered as
/// a string if the timestamp is out of range.
pub(crate) fn iso8601(unix_secs: u64) -> String {
    DateTime::from_timestamp(unix_secs as i64, 0)
        .map(|dt| dt.to_rfc3339_opts(SecondsFormat::Secs, true))
        .unwrap_or_else(|| unix_secs.to_string())
}

/// Errors raised when the SWIYU identifier-registry credentials are required but
/// were not supplied. The `&'static str` is appended to the message verbatim — use
/// `""` when `--no-publish` is not a meaningful escape (as in `did create`, where the
/// POST to allocate the DID URL is mandatory regardless of `--no-publish`), or
/// `" (or use --no-publish)"` when it is (as in `did rotate` / `did deactivate`).
#[derive(Debug, thiserror::Error)]
pub enum RegistryArgsError {
    #[error("provide --partner-id or set SWIYU_PARTNER_ID{0}")]
    PartnerIdMissing(&'static str),
    #[error("provide --registry-url or set SWIYU_IDENTIFIER_REGISTRY_URL{0}")]
    RegistryUrlMissing(&'static str),
}

/// Validates that both `partner_id` and `registry_url` are present, returning
/// the values as a tuple or a [`RegistryArgsError`] indicating which is missing.
pub(crate) fn require_registry_credentials(
    partner_id: Option<String>,
    registry_url: Option<String>,
    no_publish_hint: &'static str,
) -> Result<(String, String), RegistryArgsError> {
    let partner_id = partner_id.ok_or(RegistryArgsError::PartnerIdMissing(no_publish_hint))?;
    let registry_url =
        registry_url.ok_or(RegistryArgsError::RegistryUrlMissing(no_publish_hint))?;
    Ok((partner_id, registry_url))
}

/// Errors common to the `<hash|did>` resolution helpers below. Each command's error
/// type wraps this via `#[from] ResolveError` (transparent), so `?` propagates cleanly
/// from `resolve_did` / `resolve_entry` into any command function.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("no entry found for '{0}'")]
    NotFound(String),
    #[error(transparent)]
    Did(#[from] DIDError),
    #[error(transparent)]
    KeyStore(#[from] KeyStoreError),
}

/// Resolves a `<hash|did>` target to a [`DID`].
///
/// A 12-character ASCII-hex string is treated as a BLAKE3 hash and looked up in the
/// key store; the entry's stored DID string is then parsed into a [`DID`]. Anything
/// else is parsed directly via the `FromStr` impl on [`DID`] without consulting the
/// key store — this means foreign DIDs (e.g. an issuer DID looked up at the trust
/// registry) are accepted even when they aren't present locally.
pub(crate) fn resolve_did(store: &KeyStore, target: &str) -> Result<DID, ResolveError> {
    if is_hash(target) {
        debug!("resolving '{target}' as BLAKE3 hash via key store");
        let entry = store
            .lookup_by_hash(target)?
            .ok_or_else(|| ResolveError::NotFound(target.to_string()))?;
        Ok(DID::from_str(entry.did())?)
    } else {
        debug!("resolving '{target}' as DID string");
        Ok(DID::from_str(target)?)
    }
}

/// Resolves a `<hash|did>` target to a [`KeyStoreEntry`].
///
/// Both forms require the entry to exist locally — used by commands that need access
/// to the DID's keys (e.g. `key show`, `pop create`).
pub(crate) fn resolve_entry(store: &KeyStore, target: &str) -> Result<KeyStoreEntry, ResolveError> {
    if is_hash(target) {
        debug!("resolving '{target}' as BLAKE3 hash via key store");
        store
            .lookup_by_hash(target)?
            .ok_or_else(|| ResolveError::NotFound(target.to_string()))
    } else {
        debug!("resolving '{target}' as DID string");
        let did = DID::from_str(target)?;
        store
            .lookup(&did)?
            .ok_or_else(|| ResolveError::NotFound(target.to_string()))
    }
}

fn is_hash(s: &str) -> bool {
    s.len() == 12 && s.chars().all(|c| c.is_ascii_hexdigit())
}
