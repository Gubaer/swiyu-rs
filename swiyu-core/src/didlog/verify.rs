//! Verifies a DID log against the chain integrity rules of did:tdw 0.3.
//!
//! For every fetched DID log this module:
//! - re-derives the SCID from the genesis entry's preliminary form and matches
//!   it against the SCID encoded in the DID,
//! - re-derives the entryHash for every entry and matches it against the
//!   versionId,
//! - verifies each entry's `eddsa-jcs-2022` proof signature using the
//!   authorized keys in `parameters.updateKeys` (carried forward from the
//!   previous entry unless rotated).
//!
//! did:webvh 1.0 logs are not currently supported and short-circuit with
//! [`DIDLogVerifyError::UnsupportedFormat`] — callers may treat that as a
//! soft skip if they wish.

use std::fmt;
use std::str::FromStr;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;

use crate::did::DID;
use crate::diddoc::public_keys::PublicKeyMultibase;
use crate::didlog::scid::{derive_entry_hash, derive_scid};
use crate::didlog::{DIDDocState, DIDLog, DIDLogEntry, LogEntryFormat, eddsa_jcs_2022_hash};

#[derive(Debug)]
pub enum DIDLogVerifyError {
    Empty,
    DidWithoutScid {
        did: String,
    },
    UnsupportedFormat(usize),
    PatchState(usize),
    ScidMismatch {
        derived: String,
        claimed: String,
    },
    DidIdentifierMismatch {
        entry: usize,
        expected: String,
        actual: String,
    },
    VersionIdSequenceMismatch {
        entry: usize,
        expected_seq: u32,
        actual: String,
    },
    EntryHashMismatch {
        entry: usize,
        claimed: String,
        derived: String,
    },
    MissingGenesisUpdateKeys,
    MissingProof(usize),
    MalformedProof {
        entry: usize,
        message: String,
    },
    ProofKeyNotAuthorized {
        entry: usize,
        verification_method: String,
        multikey: String,
    },
    SignatureInvalid(usize),
    MalformedEntry {
        entry: usize,
        message: String,
    },
}

impl fmt::Display for DIDLogVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use DIDLogVerifyError::*;
        match self {
            Empty => write!(f, "DID log is empty"),
            DidWithoutScid { did } => write!(
                f,
                "DID '{did}' has no SCID — cannot verify a did:tdw log against it"
            ),
            UnsupportedFormat(i) => {
                write!(f, "entry {i}: only did:tdw 0.3 verification is implemented")
            }
            PatchState(i) => write!(
                f,
                "entry {i}: state is a Patch — only Value states are supported for verification"
            ),
            ScidMismatch { derived, claimed } => write!(
                f,
                "genesis SCID mismatch: derived '{derived}', DID claims '{claimed}'"
            ),
            DidIdentifierMismatch {
                entry,
                expected,
                actual,
            } => write!(
                f,
                "entry {entry}: state.value.id is '{actual}', expected '{expected}'"
            ),
            VersionIdSequenceMismatch {
                entry,
                expected_seq,
                actual,
            } => write!(
                f,
                "entry {entry}: versionId '{actual}' does not have the expected '{expected_seq}-' sequence prefix"
            ),
            EntryHashMismatch {
                entry,
                claimed,
                derived,
            } => write!(
                f,
                "entry {entry}: entryHash mismatch — versionId claims '{claimed}', recomputed '{derived}'"
            ),
            MissingGenesisUpdateKeys => {
                write!(f, "genesis entry must announce parameters.updateKeys")
            }
            MissingProof(i) => write!(f, "entry {i}: no data integrity proof"),
            MalformedProof { entry, message } => {
                write!(f, "entry {entry}: malformed proof: {message}")
            }
            ProofKeyNotAuthorized {
                entry,
                verification_method,
                multikey,
            } => write!(
                f,
                "entry {entry}: proof verificationMethod '{verification_method}' references key '{multikey}', which is not in the authorized updateKeys"
            ),
            SignatureInvalid(i) => write!(f, "entry {i}: proof signature is invalid"),
            MalformedEntry { entry, message } => {
                write!(f, "entry {entry}: malformed: {message}")
            }
        }
    }
}

impl std::error::Error for DIDLogVerifyError {}

/// Verifies a did:tdw 0.3 log against the chain integrity rules of the spec.
///
/// Walks the log start-to-end, re-deriving the genesis SCID from the
/// preliminary form, the `entryHash` for every entry, and verifying every
/// entry's `eddsa-jcs-2022` proof signature against the authorized keys in
/// `parameters.updateKeys` (carried forward across entries unless rotated).
/// Stops at the first failure.
///
/// # Errors
///
/// Returns a [`DIDLogVerifyError`] on the first rejection. Notable cases:
/// [`ScidMismatch`] for a wrong-DID or tampered genesis, [`EntryHashMismatch`]
/// for a tampered entry body, [`SignatureInvalid`] for a forged proof, and
/// [`ProofKeyNotAuthorized`] if a proof was signed by a key not in the
/// carry-forward `parameters.updateKeys`.
///
/// [`ScidMismatch`]: DIDLogVerifyError::ScidMismatch
/// [`EntryHashMismatch`]: DIDLogVerifyError::EntryHashMismatch
/// [`SignatureInvalid`]: DIDLogVerifyError::SignatureInvalid
/// [`ProofKeyNotAuthorized`]: DIDLogVerifyError::ProofKeyNotAuthorized
pub fn verify_log(log: &DIDLog, did: &DID) -> Result<(), DIDLogVerifyError> {
    use DIDLogVerifyError::*;

    let entries = log.entries();
    if entries.is_empty() {
        return Err(Empty);
    }

    let claimed_scid = did.scid().ok_or_else(|| DidWithoutScid {
        did: did.to_string(),
    })?;
    let did_str = did.to_string();

    for (i, entry) in entries.iter().enumerate() {
        if !matches!(entry.format(), LogEntryFormat::TDW03) {
            return Err(UnsupportedFormat(i));
        }
    }

    let mut effective_update_keys: Vec<String> = Vec::new();
    let mut prev_version_id: Option<String> = None;

    for (i, entry) in entries.iter().enumerate() {
        let n = (i as u32) + 1;

        // Determine which keys are authorized to sign THIS entry's proof.
        // Genesis: keys announced in entry 0. Subsequent: previous entry's
        // effective updateKeys (carried forward unless rotated).
        let auth_keys: &[String] = if i == 0 {
            entry
                .parameters()
                .update_keys()
                .ok_or(MissingGenesisUpdateKeys)?
        } else {
            &effective_update_keys
        };

        verify_entry(
            i,
            n,
            entry,
            claimed_scid,
            &did_str,
            prev_version_id.as_deref(),
            auth_keys,
        )?;

        if let Some(uks) = entry.parameters().update_keys() {
            effective_update_keys = uks.to_vec();
        }
        prev_version_id = Some(entry.version_id().to_string());
    }

    Ok(())
}

fn verify_entry(
    i: usize,
    n: u32,
    entry: &DIDLogEntry,
    claimed_scid: &str,
    expected_did: &str,
    prev_version_id: Option<&str>,
    auth_keys: &[String],
) -> Result<(), DIDLogVerifyError> {
    use DIDLogVerifyError::*;

    let doc_value = match entry.did_doc_state() {
        DIDDocState::Value(v) => v,
        DIDDocState::Patch(_) => return Err(PatchState(i)),
    };
    let actual_did = doc_value
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| MalformedEntry {
            entry: i,
            message: "state.value.id is missing or not a string".into(),
        })?;
    if actual_did != expected_did {
        return Err(DidIdentifierMismatch {
            entry: i,
            expected: expected_did.to_string(),
            actual: actual_did.to_string(),
        });
    }

    let vid = entry.version_id();
    let prefix = format!("{n}-");
    let actual_hash = vid
        .strip_prefix(&prefix)
        .ok_or_else(|| VersionIdSequenceMismatch {
            entry: i,
            expected_seq: n,
            actual: vid.to_string(),
        })?;

    let entry_json = Value::from(entry.clone());
    let arr = entry_json.as_array().ok_or_else(|| MalformedEntry {
        entry: i,
        message: "entry is not a JSON array".into(),
    })?;
    if arr.len() < 4 {
        return Err(MalformedEntry {
            entry: i,
            message: format!("expected at least 4 elements, got {}", arr.len()),
        });
    }

    // 4-element entry-for-hashing form: [versionId, versionTime, parameters, state]
    // with the proof slot dropped. versionId field is replaced with either the
    // bare SCID (genesis) or the previous entry's versionId.
    let mut hashing_entry = arr[..4].to_vec();
    hashing_entry[0] = Value::String(match prev_version_id {
        Some(p) => p.to_string(),
        None => claimed_scid.to_string(),
    });
    let hashing_entry_value = Value::Array(hashing_entry);

    let derived_hash = derive_entry_hash(&hashing_entry_value);
    if derived_hash != actual_hash {
        return Err(EntryHashMismatch {
            entry: i,
            claimed: actual_hash.to_string(),
            derived: derived_hash,
        });
    }

    // Genesis only: re-derive SCID from the preliminary form.
    if i == 0 {
        let s = serde_json::to_string(&hashing_entry_value).map_err(|e| MalformedEntry {
            entry: i,
            message: format!("serialize for SCID re-derivation: {e}"),
        })?;
        let prelim_str = s.replace(claimed_scid, "{SCID}");
        let prelim: Value = serde_json::from_str(&prelim_str).map_err(|e| MalformedEntry {
            entry: i,
            message: format!("re-parse preliminary form: {e}"),
        })?;
        let derived_scid = derive_scid(&prelim);
        if derived_scid != claimed_scid {
            return Err(ScidMismatch {
                derived: derived_scid,
                claimed: claimed_scid.to_string(),
            });
        }
    }

    verify_proof(i, entry, doc_value, auth_keys)?;

    Ok(())
}

fn verify_proof(
    i: usize,
    entry: &DIDLogEntry,
    document: &Value,
    auth_keys: &[String],
) -> Result<(), DIDLogVerifyError> {
    use DIDLogVerifyError::*;

    let proofs = entry.data_integrity_proofs();
    if proofs.is_empty() {
        return Err(MissingProof(i));
    }
    let proof = &proofs[0];
    let proof_obj = proof.as_object().ok_or_else(|| MalformedProof {
        entry: i,
        message: "proof is not an object".into(),
    })?;

    let vm = proof_obj
        .get("verificationMethod")
        .and_then(Value::as_str)
        .ok_or_else(|| MalformedProof {
            entry: i,
            message: "verificationMethod missing or not a string".into(),
        })?;
    let multikey = parse_did_key_vm(vm).ok_or_else(|| MalformedProof {
        entry: i,
        message: format!("verificationMethod '{vm}' is not did:key:<mk>#<mk>"),
    })?;

    if !auth_keys.iter().any(|k| k == multikey) {
        return Err(ProofKeyNotAuthorized {
            entry: i,
            verification_method: vm.to_string(),
            multikey: multikey.to_string(),
        });
    }

    let vk_bytes = decode_ed25519_multikey(multikey).map_err(|m| MalformedProof {
        entry: i,
        message: m,
    })?;
    let vk = VerifyingKey::from_bytes(&vk_bytes).map_err(|e| MalformedProof {
        entry: i,
        message: format!("invalid Ed25519 verifying key: {e}"),
    })?;

    let mut config = proof_obj.clone();
    config.remove("proofValue");
    let config_value = Value::Object(config);

    let hash_data = eddsa_jcs_2022_hash(document, &config_value);

    let proof_value_str = proof_obj
        .get("proofValue")
        .and_then(Value::as_str)
        .ok_or_else(|| MalformedProof {
            entry: i,
            message: "proofValue missing or not a string".into(),
        })?;
    let pv_bytes = decode_multibase_z(proof_value_str).map_err(|m| MalformedProof {
        entry: i,
        message: m,
    })?;
    if pv_bytes.len() != 64 {
        return Err(MalformedProof {
            entry: i,
            message: format!("proofValue must decode to 64 bytes, got {}", pv_bytes.len()),
        });
    }
    let sig_bytes: [u8; 64] = pv_bytes.try_into().expect("checked length above");
    let signature = Signature::from_bytes(&sig_bytes);

    vk.verify(&hash_data, &signature)
        .map_err(|_| SignatureInvalid(i))?;

    Ok(())
}

fn parse_did_key_vm(vm: &str) -> Option<&str> {
    let after_prefix = vm.strip_prefix("did:key:")?;
    let (mk1, mk2) = after_prefix.split_once('#')?;
    if mk1 != mk2 {
        return None;
    }
    Some(mk1)
}

fn decode_ed25519_multikey(s: &str) -> Result<[u8; 32], String> {
    let mb = PublicKeyMultibase::from_str(s).map_err(|e| e.to_string())?;
    let bytes = mb.raw_key();
    if bytes.len() != 34 {
        return Err(format!(
            "Ed25519 multikey must decode to 34 bytes, got {}",
            bytes.len()
        ));
    }
    if bytes[0] != 0xed || bytes[1] != 0x01 {
        return Err(format!(
            "multikey is not Ed25519 (multicodec {:02x}{:02x})",
            bytes[0], bytes[1]
        ));
    }
    let key: [u8; 32] = bytes[2..].try_into().expect("checked length above");
    Ok(key)
}

fn decode_multibase_z(s: &str) -> Result<Vec<u8>, String> {
    let rest = s
        .strip_prefix('z')
        .ok_or_else(|| format!("not a base58btc multibase string (no 'z' prefix): '{s}'"))?;
    bs58::decode(rest)
        .into_vec()
        .map_err(|e| format!("base58 decode failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A valid 2-entry did:tdw 0.3 log for the DID below, captured from a real
    // run against the SWIYU integration registry. Both entries' contents are
    // public information (DIDs are designed to be published).
    const VALID_LOG: &str = include_str!("../../tests/fixtures/valid_tdw_log.jsonl");
    const VALID_DID: &str = "did:tdw:QmbMyQ4rMDWZyjRkYd11hg3mfja9TiG4789jCFeYsYDktE:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:bade5c46-2adb-4aee-a6aa-a4b93d5e7f3c";

    fn valid_did() -> DID {
        DID::parse(VALID_DID).expect("fixture DID parses")
    }

    fn load_valid() -> DIDLog {
        DIDLog::try_from_jsonl(VALID_LOG).expect("fixture log parses")
    }

    #[test]
    fn verifies_a_valid_log() {
        let log = load_valid();
        verify_log(&log, &valid_did()).expect("valid log should verify");
    }

    #[test]
    fn empty_log_rejected() {
        let log = DIDLog::try_from_jsonl("").unwrap();
        assert!(matches!(
            verify_log(&log, &valid_did()),
            Err(DIDLogVerifyError::Empty)
        ));
    }

    #[test]
    fn wrong_did_rejected() {
        let log = load_valid();
        // Different SCID (single-character mutation in the SCID portion).
        let other = DID::parse(
            "did:tdw:QmbMyQ4rMDWZyjRkYd11hg3mfja9TiG4789jCFeYsYDktX:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:bade5c46-2adb-4aee-a6aa-a4b93d5e7f3c"
        ).unwrap();
        let err = verify_log(&log, &other).unwrap_err();
        // The DID identifier in entry 0 doesn't match, which surfaces first.
        assert!(
            matches!(err, DIDLogVerifyError::DidIdentifierMismatch { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn tampered_proof_signature_rejected() {
        // Flip one byte in the genesis proofValue. We mutate the raw text and re-parse.
        let mut text = VALID_LOG.to_string();
        // The proofValue is a z-prefixed base58 string; swap the first base58 char.
        // Find it via the literal field name to avoid touching the wrong place.
        let needle = "\"proofValue\":\"z";
        let pos = text.find(needle).unwrap() + needle.len();
        // Flip a character in the signature body; pick one that's a valid base58 char.
        // (Bytes immediately after 'z' encode the signature.)
        let bytes = unsafe { text.as_bytes_mut() };
        bytes[pos] = if bytes[pos] == b'A' { b'B' } else { b'A' };

        let log = DIDLog::try_from_jsonl(&text).expect("tampered log still parses");
        let err = verify_log(&log, &valid_did()).unwrap_err();
        // The mutation invalidates the signature (or the base58 decoding); either
        // outcome is a reject.
        assert!(
            matches!(
                err,
                DIDLogVerifyError::SignatureInvalid(_) | DIDLogVerifyError::MalformedProof { .. }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn tampered_did_document_rejected() {
        // Swap an authentication-key kid character in the genesis DID document.
        // This breaks the entryHash (since the document is part of the entry hash
        // for genesis).
        let mut text = VALID_LOG.to_string();
        let needle = "\"kid\":\"authentication-key-01\"";
        let pos = text.find(needle).unwrap();
        // Replace the trailing '1' with '2'.
        let bytes = unsafe { text.as_bytes_mut() };
        let target_pos = pos + needle.len() - 2; // index of '1'
        assert_eq!(bytes[target_pos], b'1');
        bytes[target_pos] = b'2';

        let log = DIDLog::try_from_jsonl(&text).expect("tampered log still parses");
        let err = verify_log(&log, &valid_did()).unwrap_err();
        // The ScidMismatch fires before EntryHashMismatch in the genesis check
        // because re-derivation of the SCID also covers the document content.
        assert!(
            matches!(
                err,
                DIDLogVerifyError::ScidMismatch { .. }
                    | DIDLogVerifyError::EntryHashMismatch { .. }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn proof_key_not_in_update_keys_rejected() {
        // Mutate the announced updateKeys so that the actual proof signer is
        // no longer authorized. We swap a single character in the genesis
        // updateKeys multikey. Because the entry's content changes, the
        // entryHash (and SCID) will also fail — the verifier will surface
        // whichever check fires first.
        let mut text = VALID_LOG.to_string();
        let needle = "\"updateKeys\":[\"z";
        let pos = text.find(needle).unwrap() + needle.len();
        let bytes = unsafe { text.as_bytes_mut() };
        bytes[pos] = if bytes[pos] == b'A' { b'B' } else { b'A' };

        let log = DIDLog::try_from_jsonl(&text).expect("tampered log still parses");
        // Any rejection is acceptable here — we just need to confirm the
        // verifier does not accept this log.
        assert!(verify_log(&log, &valid_did()).is_err());
    }
}
