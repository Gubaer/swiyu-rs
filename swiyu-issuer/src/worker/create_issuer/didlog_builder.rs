//! Constructs the finalised genesis DIDLog entry for a `CreateIssuer`
//! task.
//!
//! Used by both `execute_build_initial_didlog` (validation) and
//! `execute_publish_didlog` (regenerate-and-PUT). Deterministic given
//! the same `state_data`, key material, and `now`, so calling it
//! twice on the same task produces byte-identical output — the
//! property that lets `publish_didlog` re-derive the entry on resume
//! instead of carrying it through `state_data`.

use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::Value;
use thiserror::Error;

use swiyu_core::did::DID;
use swiyu_core::diddoc::public_keys::ed25519_verifying_key_to_multikey;
use swiyu_core::didlog::entry_edits::{set_version_id, strip_proof_slot};
use swiyu_core::didlog::scid::{derive_entry_hash, derive_scid};
use swiyu_core::didlog::{DIDLogEntry, LogEntryFormat};

use crate::domain::{SigningEngine, SigningEngineError};
use crate::worker::didlog_common::{
    InvalidPublicKey, ed25519_bytes, sec1_to_p256, sign_and_append_proof,
};

use super::CreateIssuerStateData;

#[derive(Debug, Error)]
pub enum BuildError {
    #[error("state_data missing required field: {0}")]
    MissingState(&'static str),

    #[error("invalid allocation URL: {0}")]
    InvalidUrl(String),

    #[error("invalid public key for {role}: {message}")]
    InvalidPublicKey { role: &'static str, message: String },

    #[error(transparent)]
    Engine(#[from] SigningEngineError),
}

impl From<InvalidPublicKey> for BuildError {
    fn from(e: InvalidPublicKey) -> Self {
        BuildError::InvalidPublicKey {
            role: e.role,
            message: e.message,
        }
    }
}

impl BuildError {
    /// Maps a build-failure variant to the stable `error_code` the
    /// step executor records on the operation task. Every variant
    /// has a fixed code except `Engine(_)`, which carries the
    /// calling step's name (e.g. `"build_initial_didlog_failed"`,
    /// `"publish_didlog_failed"`) — that string is supplied by the
    /// caller as `engine_failure_code`.
    pub fn error_code(&self, engine_failure_code: &'static str) -> &'static str {
        match self {
            BuildError::MissingState(_) => "missing_state",
            BuildError::InvalidUrl(_) => "invalid_allocation_url",
            BuildError::InvalidPublicKey { .. } => "invalid_public_key",
            BuildError::Engine(_) => engine_failure_code,
        }
    }
}

/// Returns the finalised genesis DIDLog entry as a JSON value, ready
/// for JCS serialisation onto the registry as a single `did.jsonl`
/// line.
///
/// Engine traffic: three `get_public_key` calls (one per role) and
/// one `sign` call (the eddsa-jcs-2022 64-byte signing input on the
/// `Authorized` key). `now` becomes the entry's `versionTime` and
/// the proof's `created`; the dispatch loop passes `task.created_at`
/// so re-running on resume produces a byte-identical entry.
pub async fn build_log_entry<S: SigningEngine>(
    state: &CreateIssuerStateData,
    engine: &S,
    now: DateTime<Utc>,
) -> Result<Value, BuildError> {
    let url = state
        .assigned_did_url
        .as_deref()
        .ok_or(BuildError::MissingState("assigned_did_url"))?;
    let key_ids = state
        .key_ids
        .as_ref()
        .ok_or(BuildError::MissingState("key_ids"))?;

    let (domain, path) = parse_url(url)?;

    let authorized_pk = engine.get_public_key(&key_ids.authorized).await?;
    let authorized_bytes = ed25519_bytes("authorized", &authorized_pk)?;
    let authorized_multikey = ed25519_verifying_key_to_multikey(&authorized_bytes);

    let authentication_pk = engine.get_public_key(&key_ids.authentication).await?;
    let authentication_key = sec1_to_p256("authentication", &authentication_pk)?;

    let assertion_pk = engine.get_public_key(&key_ids.assertion).await?;
    let assertion_key = sec1_to_p256("assertion", &assertion_pk)?;

    // Build a canonical did:tdw via the typed constructor; with
    // scid=None the Display impl writes the literal `{SCID}`
    // placeholder, which we substitute after derive_scid below.
    // Going through the type guarantees the wire format matches what
    // `DID::from_str` expects (canonical: SCID first), which is what
    // every downstream parser in swiyu-core / swiyu-didtool relies on.
    let did_placeholder = DID::try_new_tdw(None, domain.clone(), path.clone())
        .map_err(|e| BuildError::InvalidUrl(format!("DID construction failed: {e}")))?
        .to_string();

    let now_iso = now.to_rfc3339_opts(SecondsFormat::Secs, true);

    let entry_template = DIDLogEntry::new_genesis(
        &LogEntryFormat::TDW03,
        &authorized_multikey,
        &did_placeholder,
        &authentication_key,
        &assertion_key,
        &now_iso,
    );

    // SCID is derived over the four-element preliminary form.
    let mut prelim = Value::from(entry_template);
    strip_proof_slot(&mut prelim, &LogEntryFormat::TDW03);
    let scid = derive_scid(&prelim);

    // Substitute {SCID} into versionId and the DID.
    let prelim_str = serde_json::to_string(&prelim).expect("preliminary entry serialises");
    let with_scid_str = prelim_str.replace("{SCID}", &scid);
    let mut entry_value: Value =
        serde_json::from_str(&with_scid_str).expect("substitution preserves JSON validity");

    let entry_hash = derive_entry_hash(&entry_value);
    let version_id = format!("1-{entry_hash}");
    set_version_id(&mut entry_value, &version_id, &LogEntryFormat::TDW03);

    sign_and_append_proof(
        &mut entry_value,
        &key_ids.authorized,
        &authorized_multikey,
        version_id,
        now_iso,
        engine,
    )
    .await?;

    Ok(entry_value)
}

fn parse_url(url: &str) -> Result<(String, Option<String>), BuildError> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| BuildError::InvalidUrl(format!("URL must use https://: {url}")))?;

    let (host, path_str) = match rest.find('/') {
        Some(pos) => (&rest[..pos], &rest[pos + 1..]),
        None => (rest, ""),
    };

    if host.is_empty() {
        return Err(BuildError::InvalidUrl(format!("URL missing host: {url}")));
    }

    // Percent-encode the port separator so it survives the DID colon-separator syntax.
    let did_host = match host.find(':') {
        Some(pos) => format!("{}%3A{}", &host[..pos], &host[pos + 1..]),
        None => host.to_string(),
    };

    let mut segments: Vec<&str> = path_str.split('/').filter(|s| !s.is_empty()).collect();
    if segments.last() == Some(&"did.jsonl") {
        segments.pop();
    }

    let did_path = if segments.is_empty() || segments == [".well-known"] {
        None
    } else {
        Some(segments.join(":"))
    };

    Ok((did_host, did_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_url_extracts_host_and_path() {
        let url = "https://reg.example.com/api/v1/did/abc/did.jsonl";
        let (host, path) = parse_url(url).unwrap();
        assert_eq!(host, "reg.example.com");
        assert_eq!(path.as_deref(), Some("api:v1:did:abc"));
    }

    #[test]
    fn parse_url_strips_did_jsonl_filename() {
        let url = "https://reg.example.com/x/y/did.jsonl";
        let (_, path) = parse_url(url).unwrap();
        assert_eq!(path.as_deref(), Some("x:y"));
    }

    #[test]
    fn parse_url_returns_none_path_for_well_known_root() {
        let url = "https://reg.example.com/.well-known/did.jsonl";
        let (_, path) = parse_url(url).unwrap();
        assert!(path.is_none());
    }

    #[test]
    fn parse_url_percent_encodes_port_in_host() {
        let url = "https://reg.example.com:8443/x/did.jsonl";
        let (host, _) = parse_url(url).unwrap();
        assert_eq!(host, "reg.example.com%3A8443");
    }

    #[test]
    fn parse_url_rejects_non_https() {
        let url = "http://reg.example.com/x/did.jsonl";
        let err = parse_url(url).unwrap_err();
        assert!(matches!(err, BuildError::InvalidUrl(_)));
    }
}
