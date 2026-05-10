//! Constructs the finalised rotation DIDLog entry for a
//! `RotateKeys` task.
//!
//! Used by `execute_build_rotation_didlog` (validation) and
//! `execute_publish_didlog` (regenerate-and-PUT). The proof-signing
//! flow and the key-format validators are shared with the other
//! saga builders via `crate::worker::didlog_common`; this file
//! handles the rotation-specific scaffolding (verifying the issuer
//! is Active, fetching the prev tail, the resume-short-circuit when
//! the registry already advertises the new Authorized key, building
//! the typed [`DIDLogEntry::new_rotation`] template).
//!
//! Determinism: given the same `issuer`, the same `new_triple`, the
//! same fetched tail of log entries, the same key material, and the
//! same `now`, the produced entry is byte-identical, so the publish
//! step can re-derive on resume instead of carrying the entry
//! through `state_data`.
//!
//! **Outgoing-Authorized signing rule.** The rotation entry is
//! signed with the issuer's *current* (outgoing) Authorized private
//! key — even when Authorized is itself one of the rotated roles.
//! The new Authorized only starts signing on the *next* entry. The
//! signing key id comes from `issuer.authorized_key_id` (current);
//! the new ids come from `new_triple`; never confuse the two.

use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::Value;
use thiserror::Error;

use swiyu_core::diddoc::DIDDoc;
use swiyu_core::diddoc::public_keys::ed25519_verifying_key_to_multikey;
use swiyu_core::didlog::entry_edits::{set_version_id, strip_proof_slot};
use swiyu_core::didlog::scid::derive_entry_hash;
use swiyu_core::didlog::{DIDDocState, DIDLogEntry, LogEntryFormat};

use crate::domain::{Issuer, IssuerState, SigningEngine, SigningEngineError};
use crate::worker::create_issuer::KeyTriple;
use crate::worker::didlog_common::{
    ChainedBuildError, InvalidPublicKey, ed25519_bytes, sec1_to_p256, sign_and_append_proof,
};

#[derive(Debug, Error)]
pub(crate) enum BuildError {
    #[error(transparent)]
    Chained(#[from] ChainedBuildError),

    #[error(
        "registry's tail entry already advertises the new Authorized key — saga should not have reached build_rotation_didlog a second time"
    )]
    AlreadyRotated,
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
    /// name (e.g. `"build_rotation_didlog_failed"`,
    /// `"publish_didlog_failed"`).
    pub fn error_code(&self, engine_failure_code: &'static str) -> &'static str {
        match self {
            BuildError::Chained(e) => e.error_code(engine_failure_code),
            BuildError::AlreadyRotated => "already_rotated",
        }
    }
}

/// Returns the finalised rotation DIDLog entry as a JSON value,
/// ready for JCS serialisation onto the registry as a single
/// `did.jsonl` line.
///
/// Engine traffic: four `get_public_key` calls (the new
/// Authorized, Authentication, Assertion keys plus the *outgoing*
/// Authorized key for the proof's verification_method id) and one
/// `sign` call (the eddsa-jcs-2022 64-byte signing input on the
/// outgoing Authorized key). `now` becomes the entry's
/// `versionTime` and the proof's `created`; the dispatch loop pins
/// this to `task.created_at` so re-running on resume produces a
/// byte-identical entry.
pub(crate) async fn build_rotation_entry<S: SigningEngine>(
    issuer: &Issuer,
    new_triple: &KeyTriple,
    log: &[DIDLogEntry],
    engine: &S,
    now: DateTime<Utc>,
) -> Result<Value, BuildError> {
    if issuer.state != Some(IssuerState::Active) {
        return Err(
            ChainedBuildError::IssuerNotActive(format!("{:?}", issuer.state.as_ref())).into(),
        );
    }
    let outgoing_authorized_id = issuer
        .authorized_key_id
        .ok_or(ChainedBuildError::MissingIssuerField("authorized_key_id"))?;

    let last = log.last().ok_or(ChainedBuildError::EmptyLog)?;
    let prev_doc_value = match last.did_doc_state() {
        DIDDocState::Value(v) => v,
        DIDDocState::Patch(_) => return Err(ChainedBuildError::PreviousStateIsPatch.into()),
    };
    // We don't reuse the previous document's verification methods
    // (the rotation entry's doc carries the new Authentication and
    // Assertion VMs), but we still validate the predecessor parses
    // — a malformed predecessor would imply a broken registry tail
    // and no rotation could chain onto it correctly.
    let _prev_doc = DIDDoc::try_from(prev_doc_value)
        .map_err(|e| ChainedBuildError::InvalidPredecessorDoc(e.to_string()))?;
    let prev_version_id = last.version_id().to_string();

    // Fetch the three new public keys.
    let new_authorized_pk = engine.get_public_key(&new_triple.authorized).await?;
    let new_authorized_bytes = ed25519_bytes("authorized", &new_authorized_pk)?;
    let new_authorized_multikey = ed25519_verifying_key_to_multikey(&new_authorized_bytes);

    let new_authentication_pk = engine.get_public_key(&new_triple.authentication).await?;
    let new_authentication_p256 = sec1_to_p256("authentication", &new_authentication_pk)?;

    let new_assertion_pk = engine.get_public_key(&new_triple.assertion).await?;
    let new_assertion_p256 = sec1_to_p256("assertion", &new_assertion_pk)?;

    // Saga-resume short-circuit: if the registry tail already
    // advertises the new Authorized key in `updateKeys`, the
    // rotation was already published. Caller (publish_didlog) maps
    // this to `Done` with `didlog_published: true`.
    let already_rotated = last
        .parameters()
        .update_keys()
        .and_then(|keys| keys.first())
        .is_some_and(|k| k == &new_authorized_multikey);
    if already_rotated {
        return Err(BuildError::AlreadyRotated);
    }

    let now_iso = now.to_rfc3339_opts(SecondsFormat::Secs, true);

    let entry_template = DIDLogEntry::new_rotation(
        &LogEntryFormat::TDW03,
        &prev_version_id,
        &issuer.did,
        &new_authorized_multikey,
        &new_authentication_p256,
        &new_assertion_p256,
        &now_iso,
    );

    // `Value::from(entry_template)` emits the 5-element TDW form
    // with an empty proof slot at index 4. The entryHash must be
    // computed over the 4-element preliminary form (no proof slot).
    let mut entry_value = Value::from(entry_template);
    strip_proof_slot(&mut entry_value, &LogEntryFormat::TDW03);

    let next_seq = log.len() as u32 + 1;
    let entry_hash = derive_entry_hash(&entry_value);
    let new_version_id = format!("{next_seq}-{entry_hash}");
    set_version_id(&mut entry_value, &new_version_id, &LogEntryFormat::TDW03);

    // Sign with the OUTGOING Authorized key. Even when Authorized
    // is itself among the rotated roles, the old key signs this
    // entry — see module-level doc and aspect-issuer.md §"Rotate
    // keys" step 4.
    let outgoing_pk = engine.get_public_key(&outgoing_authorized_id).await?;
    let outgoing_bytes = ed25519_bytes("outgoing-authorized", &outgoing_pk)?;
    let outgoing_multikey = ed25519_verifying_key_to_multikey(&outgoing_bytes);

    sign_and_append_proof(
        &mut entry_value,
        &outgoing_authorized_id,
        &outgoing_multikey,
        new_version_id,
        now_iso,
        engine,
    )
    .await?;

    Ok(entry_value)
}
