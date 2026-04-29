pub mod business_entity;
pub mod create;
pub mod create_pop;
pub mod deactivate;
pub mod diddoc;
pub mod http;
pub mod log;
pub mod update;
pub mod verify_pop;

use chrono::{DateTime, SecondsFormat};
use tracing::debug;

use swiyu_core::did::{DID, DIDError};

use crate::keystore::{KeyStore, KeyStoreEntry, KeyStoreError};

/// Formats a Unix timestamp as a UTC ISO-8601 string with `Z` suffix
/// (e.g. `2026-04-29T18:23:00Z`). Falls back to the raw integer rendered as
/// a string if the timestamp is out of range.
pub(crate) fn iso8601(unix_secs: u64) -> String {
    DateTime::from_timestamp(unix_secs as i64, 0)
        .map(|dt| dt.to_rfc3339_opts(SecondsFormat::Secs, true))
        .unwrap_or_else(|| unix_secs.to_string())
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
/// else is parsed directly with [`DID::parse`] without consulting the key store —
/// this means foreign DIDs (e.g. an issuer DID looked up at the trust registry) are
/// accepted even when they aren't present locally.
pub(crate) fn resolve_did(store: &KeyStore, target: &str) -> Result<DID, ResolveError> {
    if is_hash(target) {
        debug!("resolving '{target}' as BLAKE3 hash via key store");
        let entry = store
            .lookup_by_hash(target)?
            .ok_or_else(|| ResolveError::NotFound(target.to_string()))?;
        Ok(DID::parse(entry.did())?)
    } else {
        debug!("resolving '{target}' as DID string");
        Ok(DID::parse(target)?)
    }
}

/// Resolves a `<hash|did>` target to a [`KeyStoreEntry`].
///
/// Both forms require the entry to exist locally — used by commands that need access
/// to the DID's keys (e.g. `keystore show`, `create-pop`).
pub(crate) fn resolve_entry(store: &KeyStore, target: &str) -> Result<KeyStoreEntry, ResolveError> {
    if is_hash(target) {
        debug!("resolving '{target}' as BLAKE3 hash via key store");
        store
            .lookup_by_hash(target)?
            .ok_or_else(|| ResolveError::NotFound(target.to_string()))
    } else {
        debug!("resolving '{target}' as DID string");
        let did = DID::parse(target)?;
        store
            .lookup(&did)?
            .ok_or_else(|| ResolveError::NotFound(target.to_string()))
    }
}

fn is_hash(s: &str) -> bool {
    s.len() == 12 && s.chars().all(|c| c.is_ascii_hexdigit())
}
