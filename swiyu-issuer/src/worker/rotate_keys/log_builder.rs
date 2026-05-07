//! Constructs the finalised rotation DIDLog entry for a
//! `RotateKeys` task.
//!
//! Used by `execute_build_rotation_log` (validation) and
//! `execute_publish_log` (regenerate-and-PUT). Mirrors
//! `deactivate_issuer::log_builder::build_deactivation_entry` in
//! shape and determinism guarantees: given the same `issuer`, the
//! same `new_triple`, the same fetched tail of log entries, the
//! same key material, and the same `now`, the produced entry is
//! byte-identical, so the publish step can re-derive on resume
//! instead of carrying the entry through `state_data`.
//!
//! **Outgoing-Authorized signing rule.** Per `aspect-issuer.md`
//! §"Rotate keys" step 4, the rotation entry is signed with the
//! issuer's *current* (outgoing) Authorized private key — even
//! when Authorized is itself rotated. The new Authorized only
//! starts signing on the *next* entry. The signing key id comes
//! from `issuer.authorized_key_id` (current); the new ids come
//! from `new_triple`; never confuse the two.

use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::Value;
use thiserror::Error;

use swiyu_core::diddoc::DIDDoc;
use swiyu_core::diddoc::public_keys::{P256PublicKey, ed25519_verifying_key_to_multikey};
use swiyu_core::didlog::entry_edits::{append_proof, set_version_id, strip_proof_slot};
use swiyu_core::didlog::scid::derive_entry_hash;
use swiyu_core::didlog::{DIDDocState, DIDLogEntry, LogEntryFormat};
use swiyu_core::proof::{Cryptosuite, DataIntegrityProof, ProofConfig, ProofPurpose};

use crate::domain::{Issuer, IssuerState, KeyAlgorithm, SigningEngine, SigningEngineError};
use crate::worker::create_issuer::KeyTriple;

#[derive(Debug, Error)]
pub enum BuildError {
    #[error("issuer is not in state Active: {0}")]
    IssuerNotActive(String),

    #[error("issuer is missing required field: {0}")]
    MissingIssuerField(&'static str),

    #[error("registry returned an empty DID log — nothing to chain a rotation entry onto")]
    EmptyLog,

    #[error(
        "registry's tail entry already advertises the new Authorized key — saga should not have reached build_rotation_log a second time"
    )]
    AlreadyRotated,

    #[error("registry's tail entry uses a Patch state — rotation requires a full DID document")]
    PreviousStateIsPatch,

    #[error("registry's tail DID document is malformed: {0}")]
    InvalidPredecessorDoc(String),

    #[error("invalid public key for {role}: {message}")]
    InvalidPublicKey { role: &'static str, message: String },

    #[error(transparent)]
    Engine(#[from] SigningEngineError),
}

impl BuildError {
    /// Maps a build-failure variant to the stable `error_code` the
    /// step executor records on the operation task. Every variant
    /// has a fixed code except `Engine(_)`, which carries the
    /// calling step's name (e.g. `"build_rotation_log_failed"`,
    /// `"publish_log_failed"`) — that string is supplied by the
    /// caller as `engine_failure_code`.
    pub fn error_code(&self, engine_failure_code: &'static str) -> &'static str {
        match self {
            BuildError::IssuerNotActive(_) => "issuer_not_active",
            BuildError::MissingIssuerField(_) => "missing_issuer_field",
            BuildError::EmptyLog => "registry_empty_log",
            BuildError::AlreadyRotated => "already_rotated",
            BuildError::PreviousStateIsPatch => "predecessor_state_is_patch",
            BuildError::InvalidPredecessorDoc(_) => "invalid_predecessor_doc",
            BuildError::InvalidPublicKey { .. } => "invalid_public_key",
            BuildError::Engine(_) => engine_failure_code,
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
pub async fn build_rotation_entry<S: SigningEngine>(
    issuer: &Issuer,
    new_triple: &KeyTriple,
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
    let outgoing_authorized_id = issuer
        .authorized_key_id
        .ok_or(BuildError::MissingIssuerField("authorized_key_id"))?;

    let last = log.last().ok_or(BuildError::EmptyLog)?;
    let prev_doc_value = match last.did_doc_state() {
        DIDDocState::Value(v) => v,
        DIDDocState::Patch(_) => return Err(BuildError::PreviousStateIsPatch),
    };
    // We don't reuse the previous document's verification methods
    // (the rotation entry's doc carries the new Authentication and
    // Assertion VMs), but we still validate the predecessor parses
    // — a malformed predecessor would imply a broken registry tail
    // and no rotation could chain onto it correctly.
    let _prev_doc = DIDDoc::try_from(prev_doc_value)
        .map_err(|e| BuildError::InvalidPredecessorDoc(e.to_string()))?;
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
    // rotation was already published. Caller (publish_log) maps
    // this to `Done` with `log_published: true`.
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

    let document_for_hash = entry_value[3]["value"].clone();
    let vm_id = format!("did:key:{outgoing_multikey}#{outgoing_multikey}");
    let proof_config = ProofConfig {
        cryptosuite: Cryptosuite::EddsaJcs2022,
        verification_method: vm_id,
        proof_purpose: ProofPurpose::Authentication,
        challenge: new_version_id,
        created: now_iso,
    };

    let hash_data = proof_config.signing_input(&document_for_hash);
    let signature = engine.sign(&outgoing_authorized_id, &hash_data).await?;
    let proof = DataIntegrityProof::from_signature(proof_config, &signature.bytes);
    append_proof(&mut entry_value, Value::from(proof), &LogEntryFormat::TDW03);

    Ok(entry_value)
}

fn ed25519_bytes(
    role: &'static str,
    pk: &crate::domain::RawPublicKey,
) -> Result<[u8; 32], BuildError> {
    if pk.algorithm != KeyAlgorithm::Ed25519 || pk.bytes.len() != 32 {
        return Err(BuildError::InvalidPublicKey {
            role,
            message: format!(
                "expected 32-byte Ed25519, got {} bytes ({:?})",
                pk.bytes.len(),
                pk.algorithm
            ),
        });
    }
    Ok(pk
        .bytes
        .as_slice()
        .try_into()
        .expect("length checked above; conversion is infallible"))
}

fn sec1_to_p256(
    role: &'static str,
    pk: &crate::domain::RawPublicKey,
) -> Result<P256PublicKey, BuildError> {
    if pk.algorithm != KeyAlgorithm::EcdsaP256 {
        return Err(BuildError::InvalidPublicKey {
            role,
            message: format!("expected ECDSA P-256, got {:?}", pk.algorithm),
        });
    }
    if pk.bytes.len() != 65 || pk.bytes[0] != 0x04 {
        return Err(BuildError::InvalidPublicKey {
            role,
            message: format!(
                "expected 65-byte SEC1 uncompressed (0x04 prefix), got {} bytes",
                pk.bytes.len()
            ),
        });
    }
    let x: [u8; 32] = pk.bytes[1..33].try_into().expect("length 32");
    let y: [u8; 32] = pk.bytes[33..65].try_into().expect("length 32");
    Ok(P256PublicKey { x, y })
}
