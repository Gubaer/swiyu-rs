//! Constructs the finalised deactivation DIDLog entry for a
//! `DeactivateIssuer` task.
//!
//! Used by `execute_build_deactivation_log` (validation) and
//! `execute_publish_log` (regenerate-and-PUT). Mirrors
//! `create_issuer::log_builder::build_log_entry` in shape and
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
use swiyu_core::didlog::entry_edits::{append_proof, set_version_id, strip_proof_slot};
use swiyu_core::didlog::scid::derive_entry_hash;
use swiyu_core::didlog::{DIDDocState, DIDLogEntry, LogEntryFormat};
use swiyu_core::proof::{Cryptosuite, DataIntegrityProof, ProofConfig, ProofPurpose};

use crate::domain::{Issuer, IssuerState, KeyAlgorithm, SigningEngine, SigningEngineError};

/// `did:tdw:0.3` is the only DID method swiyu-issuer can validate
/// end-to-end against the SWIYU registry. Mirrors the same `FORMAT`
/// constant in `create_issuer::log_builder`.
const FORMAT: LogEntryFormat = LogEntryFormat::TDW03;

#[derive(Debug, Error)]
pub enum BuildError {
    #[error("issuer is not in state Active: {0}")]
    IssuerNotActive(String),

    #[error("issuer is missing required field: {0}")]
    MissingIssuerField(&'static str),

    #[error("registry returned an empty DID log — nothing to chain a deactivation entry onto")]
    EmptyLog,

    #[error(
        "registry's tail entry is already deactivated — saga should not have reached build_deactivation_log"
    )]
    AlreadyDeactivated,

    #[error("registry's tail entry uses a Patch state — deactivation requires a full DID document")]
    PreviousStateIsPatch,

    #[error("registry's tail DID document is malformed: {0}")]
    InvalidPredecessorDoc(String),

    #[error("invalid public key for {role}: {message}")]
    InvalidPublicKey { role: &'static str, message: String },

    #[error(transparent)]
    Engine(#[from] SigningEngineError),
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
pub async fn build_deactivation_entry<S: SigningEngine>(
    issuer: &Issuer,
    log: &[DIDLogEntry],
    engine: &S,
    now: DateTime<Utc>,
) -> Result<Value, BuildError> {
    if issuer.state != Some(IssuerState::Active) {
        return Err(BuildError::IssuerNotActive(format!(
            "{:?}",
            issuer.state.as_ref()
        )));
    }
    let authorized_key_id = issuer
        .authorized_key_id
        .ok_or(BuildError::MissingIssuerField("authorized_key_id"))?;

    let last = log.last().ok_or(BuildError::EmptyLog)?;
    if last.parameters().deactivated() == Some(true) {
        return Err(BuildError::AlreadyDeactivated);
    }
    let prev_doc_value = match last.did_doc_state() {
        DIDDocState::Value(v) => v,
        DIDDocState::Patch(_) => return Err(BuildError::PreviousStateIsPatch),
    };
    let prev_doc = DIDDoc::try_from(prev_doc_value)
        .map_err(|e| BuildError::InvalidPredecessorDoc(e.to_string()))?;
    let prev_version_id = last.version_id().to_string();

    let now_iso = now.to_rfc3339_opts(SecondsFormat::Secs, true);

    let entry_template =
        DIDLogEntry::new_deactivation(&FORMAT, &prev_version_id, &prev_doc, &now_iso);

    // `to_json` emits the 5-element TDW form including an empty
    // proof slot at index 4. The entryHash must be computed over
    // the 4-element preliminary form (no proof slot), per the
    // did:tdw 0.3 spec — same discipline as create_issuer's
    // log_builder. Strip first, then append the real proof at the
    // end.
    let mut entry_value = Value::from(entry_template);
    strip_proof_slot(&mut entry_value, &FORMAT);

    let next_seq = log.len() as u32 + 1;
    let entry_hash = derive_entry_hash(&entry_value);
    let new_version_id = format!("{next_seq}-{entry_hash}");
    set_version_id(&mut entry_value, &new_version_id, &FORMAT);

    let authorized_pk = engine.get_public_key(&authorized_key_id).await?;
    if authorized_pk.algorithm != KeyAlgorithm::Ed25519 || authorized_pk.bytes.len() != 32 {
        return Err(BuildError::InvalidPublicKey {
            role: "authorized",
            message: format!(
                "expected 32-byte Ed25519, got {} bytes ({:?})",
                authorized_pk.bytes.len(),
                authorized_pk.algorithm
            ),
        });
    }
    let authorized_bytes: [u8; 32] = authorized_pk
        .bytes
        .as_slice()
        .try_into()
        .expect("length checked above; conversion is infallible");
    let authorized_multikey = ed25519_verifying_key_to_multikey(&authorized_bytes);

    // The DID Toolbox (Java) signs only the document content (entry[3]["value"]
    // for did:tdw 0.3), not the entire entry. Mirroring that — same as
    // create_issuer's log_builder — keeps signature bytes interoperable.
    let document_for_hash = entry_value[3]["value"].clone();

    let vm_id = format!("did:key:{authorized_multikey}#{authorized_multikey}");
    let proof_config = ProofConfig {
        cryptosuite: Cryptosuite::EddsaJcs2022,
        verification_method: vm_id,
        proof_purpose: ProofPurpose::Authentication,
        challenge: new_version_id,
        created: now_iso,
    };

    let hash_data = proof_config.signing_input(&document_for_hash);
    let signature = engine.sign(&authorized_key_id, &hash_data).await?;
    let proof = DataIntegrityProof::from_signature(proof_config, &signature.bytes);
    append_proof(&mut entry_value, Value::from(proof), &FORMAT);

    Ok(entry_value)
}
