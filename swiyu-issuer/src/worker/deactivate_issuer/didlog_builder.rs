//! Constructs the finalised deactivation DIDLog entry for a
//! `DeactivateIssuer` task.
//!
//! Used by `execute_build_deactivation_didlog` (validation) and
//! `execute_publish_didlog` (regenerate-and-PUT). Mirrors
//! `create_issuer::didlog_builder::build_log_entry` in shape and
//! determinism guarantees: given the same `issuer`, the same fetched
//! tail of log entries, the same key material, and the same `now`,
//! the produced entry is byte-identical, so the publish step can
//! re-derive on resume instead of carrying the entry through
//! `state_data`.

use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::Value;
use thiserror::Error;

use swiyu_core::diddoc::DIDDoc;
use swiyu_core::diddoc::public_keys::ed25519_verifying_key_to_multikey;
use swiyu_core::didlog::entry_edits::{set_version_id, strip_proof_slot};
use swiyu_core::didlog::scid::derive_entry_hash;
use swiyu_core::didlog::{DIDDocState, DIDLogEntry, LogEntryFormat};

use crate::domain::{Issuer, IssuerState, SigningEngine, SigningEngineError};
use crate::worker::didlog_common::{
    ChainedBuildError, InvalidPublicKey, ed25519_bytes, sign_and_append_proof,
};

#[derive(Debug, Error)]
pub(crate) enum BuildError {
    #[error(transparent)]
    Chained(#[from] ChainedBuildError),

    #[error(
        "registry's tail entry is already deactivated — saga should not have reached build_deactivation_didlog"
    )]
    AlreadyDeactivated,
}

impl From<InvalidPublicKey> for BuildError {
    fn from(e: InvalidPublicKey) -> Self {
        BuildError::Chained(e.into())
    }
}

impl From<SigningEngineError> for BuildError {
    fn from(e: SigningEngineError) -> Self {
        BuildError::Chained(e.into())
    }
}

impl BuildError {
    /// Maps a build-failure variant to the stable `error_code` the
    /// step executor records on the operation task. The
    /// `engine_failure_code` argument carries the calling step's
    /// name (e.g. `"build_deactivation_didlog_failed"`,
    /// `"publish_didlog_failed"`).
    pub fn error_code(&self, engine_failure_code: &'static str) -> &'static str {
        match self {
            BuildError::Chained(e) => e.error_code(engine_failure_code),
            BuildError::AlreadyDeactivated => "already_deactivated",
        }
    }
}

/// Returns the finalised deactivation DIDLog entry as a JSON value,
/// ready for JCS serialisation onto the registry as a single
/// `did.jsonl` line.
///
/// Engine traffic: one `get_public_key` call (the Authorized key)
/// and one `sign` call (the eddsa-jcs-2022 64-byte signing input on
/// that same key). `now` becomes the entry's `versionTime` and the
/// proof's `created`; the dispatch loop pins this to `task.created_at`
/// so re-running on resume produces a byte-identical entry.
pub(crate) async fn build_deactivation_entry<S: SigningEngine>(
    issuer: &Issuer,
    log: &[DIDLogEntry],
    engine: &S,
    now: DateTime<Utc>,
) -> Result<Value, BuildError> {
    if issuer.state != Some(IssuerState::Active) {
        return Err(
            ChainedBuildError::IssuerNotActive(format!("{:?}", issuer.state.as_ref())).into(),
        );
    }
    let authorized_key_id = issuer
        .authorized_key_id
        .ok_or(ChainedBuildError::MissingIssuerField("authorized_key_id"))?;

    let last = log.last().ok_or(ChainedBuildError::EmptyLog)?;
    if last.parameters().deactivated() == Some(true) {
        return Err(BuildError::AlreadyDeactivated);
    }
    let prev_doc_value = match last.did_doc_state() {
        DIDDocState::Value(v) => v,
        DIDDocState::Patch(_) => return Err(ChainedBuildError::PreviousStateIsPatch.into()),
    };
    let prev_doc = DIDDoc::try_from(prev_doc_value)
        .map_err(|e| ChainedBuildError::InvalidPredecessorDoc(e.to_string()))?;
    let prev_version_id = last.version_id().to_string();

    let now_iso = now.to_rfc3339_opts(SecondsFormat::Secs, true);

    let entry_template = DIDLogEntry::new_deactivation(
        &LogEntryFormat::TDW03,
        &prev_version_id,
        &prev_doc,
        &now_iso,
    );

    // `to_json` emits the 5-element TDW form including an empty
    // proof slot at index 4. The entryHash must be computed over
    // the 4-element preliminary form (no proof slot), per the
    // did:tdw 0.3 spec — same discipline as create_issuer's
    // didlog_builder. Strip first, then append the real proof at the
    // end.
    let mut entry_value = Value::from(entry_template);
    strip_proof_slot(&mut entry_value, &LogEntryFormat::TDW03);

    let next_seq = log.len() as u32 + 1;
    let entry_hash = derive_entry_hash(&entry_value);
    let new_version_id = format!("{next_seq}-{entry_hash}");
    set_version_id(&mut entry_value, &new_version_id, &LogEntryFormat::TDW03);

    let authorized_pk = engine.get_public_key(&authorized_key_id).await?;
    let authorized_bytes = ed25519_bytes("authorized", &authorized_pk)?;
    let authorized_multikey = ed25519_verifying_key_to_multikey(&authorized_bytes);

    sign_and_append_proof(
        &mut entry_value,
        &authorized_key_id,
        &authorized_multikey,
        new_version_id,
        now_iso,
        engine,
    )
    .await?;

    Ok(entry_value)
}
