//! Helpers shared by the three saga DIDLog builders
//! (`create_issuer`, `deactivate_issuer`, `rotate_keys`).
//!
//! Each saga has its own `didlog_builder.rs` that constructs the
//! particular entry shape (genesis / deactivation / rotation), but
//! the public-key validators and the proof-signing flow are the same
//! across all three. They live here so the three builders share one
//! source of truth.

use serde_json::Value;
use thiserror::Error;

use swiyu_core::diddoc::public_keys::P256PublicKey;
use swiyu_core::didlog::LogEntryFormat;
use swiyu_core::didlog::entry_edits::append_proof;
use swiyu_core::proof::{Cryptosuite, DataIntegrityProof, ProofConfig, ProofPurpose};

use crate::domain::{KeyAlgorithm, KeyPairId, RawPublicKey, SigningEngine, SigningEngineError};

/// Lightweight error from the public-key validators. Each saga's
/// `BuildError` provides a `From<InvalidPublicKey>` impl that maps
/// this into its own `InvalidPublicKey { role, message }` variant.
#[derive(Debug)]
pub(crate) struct InvalidPublicKey {
    pub(crate) role: &'static str,
    pub(crate) message: String,
}

/// Failure modes shared by the two chained-saga DIDLog builders
/// (`deactivate_issuer`, `rotate_keys`). Each saga's `BuildError`
/// wraps this via a `Chained(ChainedBuildError)` variant and adds
/// the one saga-specific `Already*` variant on top.
///
/// `create_issuer/didlog_builder.rs` is structurally different (it
/// builds the genesis entry, with no prev tail to consult) and
/// keeps its own `BuildError` enum.
#[derive(Debug, Error)]
pub(crate) enum ChainedBuildError {
    #[error("issuer is not in state Active: {0}")]
    IssuerNotActive(String),

    #[error("issuer is missing required field: {0}")]
    MissingIssuerField(&'static str),

    #[error("registry returned an empty DID log — nothing to chain onto")]
    EmptyLog,

    #[error(
        "registry's tail entry uses a Patch state — chained operations require a full DID document"
    )]
    PreviousStateIsPatch,

    #[error("registry's tail DID document is malformed: {0}")]
    InvalidPredecessorDoc(String),

    #[error("invalid public key for {role}: {message}")]
    InvalidPublicKey { role: &'static str, message: String },

    #[error(transparent)]
    Engine(#[from] SigningEngineError),
}

impl From<InvalidPublicKey> for ChainedBuildError {
    fn from(e: InvalidPublicKey) -> Self {
        ChainedBuildError::InvalidPublicKey {
            role: e.role,
            message: e.message,
        }
    }
}

impl ChainedBuildError {
    /// Maps a build-failure variant to the stable `error_code` the
    /// step executor records on the operation task. The
    /// `engine_failure_code` argument carries the calling step's
    /// name (e.g. `"build_deactivation_didlog_failed"`,
    /// `"publish_didlog_failed"`).
    pub(crate) fn error_code(&self, engine_failure_code: &'static str) -> &'static str {
        match self {
            ChainedBuildError::IssuerNotActive(_) => "issuer_not_active",
            ChainedBuildError::MissingIssuerField(_) => "missing_issuer_field",
            ChainedBuildError::EmptyLog => "registry_empty_log",
            ChainedBuildError::PreviousStateIsPatch => "predecessor_state_is_patch",
            ChainedBuildError::InvalidPredecessorDoc(_) => "invalid_predecessor_doc",
            ChainedBuildError::InvalidPublicKey { .. } => "invalid_public_key",
            ChainedBuildError::Engine(_) => engine_failure_code,
        }
    }
}

/// Validates that `pk` carries a 32-byte Ed25519 public key and
/// returns it as a fixed-size byte array suitable for
/// [`ed25519_verifying_key_to_multikey`](swiyu_core::diddoc::public_keys::ed25519_verifying_key_to_multikey).
pub(crate) fn ed25519_bytes(
    role: &'static str,
    pk: &RawPublicKey,
) -> Result<[u8; 32], InvalidPublicKey> {
    if pk.algorithm != KeyAlgorithm::Ed25519 || pk.bytes.len() != 32 {
        return Err(InvalidPublicKey {
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

/// Validates that `pk` carries a 65-byte SEC1-uncompressed P-256
/// public key (`0x04` prefix + X + Y) and returns it as a typed
/// [`P256PublicKey`].
pub(crate) fn sec1_to_p256(
    role: &'static str,
    pk: &RawPublicKey,
) -> Result<P256PublicKey, InvalidPublicKey> {
    if pk.algorithm != KeyAlgorithm::EcdsaP256 {
        return Err(InvalidPublicKey {
            role,
            message: format!("expected ECDSA P-256, got {:?}", pk.algorithm),
        });
    }
    if pk.bytes.len() != 65 || pk.bytes[0] != 0x04 {
        return Err(InvalidPublicKey {
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

/// Builds and appends an `eddsa-jcs-2022` proof to a TDW 0.3 DIDLog
/// entry, signing with `signing_key_id`.
///
/// The caller must already have populated the entry's `versionId`
/// (via `set_version_id`); this helper signs the entry's document
/// content (`entry_value[3]["value"]`) and writes the proof into the
/// entry's proof slot. The `signing_multikey` is the did:key form of
/// the key behind `signing_key_id` and goes into the proof's
/// `verificationMethod`. `version_id` becomes the proof's `challenge`
/// and `now_iso` becomes its `created`.
pub(crate) async fn sign_and_append_proof<S: SigningEngine>(
    entry_value: &mut Value,
    signing_key_id: &KeyPairId,
    signing_multikey: &str,
    version_id: String,
    now_iso: String,
    engine: &S,
) -> Result<(), SigningEngineError> {
    // The DID Toolbox (Java) signs only the document content
    // (entry[3]["value"] for did:tdw 0.3), not the entire entry.
    // Mirroring that keeps signature bytes interoperable.
    let document_for_hash = entry_value[3]["value"].clone();
    let vm_id = format!("did:key:{signing_multikey}#{signing_multikey}");
    let proof_config = ProofConfig {
        cryptosuite: Cryptosuite::EddsaJcs2022,
        verification_method: vm_id,
        proof_purpose: ProofPurpose::Authentication,
        challenge: version_id,
        created: now_iso,
    };
    let hash_data = proof_config.signing_input(&document_for_hash);
    let signature = engine.sign(signing_key_id, &hash_data).await?;
    let proof = DataIntegrityProof::from_signature(proof_config, &signature.bytes);
    append_proof(entry_value, Value::from(proof), &LogEntryFormat::TDW03);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_bytes_extracts_32_bytes() {
        let pk = RawPublicKey {
            algorithm: KeyAlgorithm::Ed25519,
            bytes: vec![0xab; 32],
        };
        let bytes = ed25519_bytes("test", &pk).unwrap();
        assert_eq!(bytes, [0xab; 32]);
    }

    #[test]
    fn ed25519_bytes_rejects_wrong_length() {
        let pk = RawPublicKey {
            algorithm: KeyAlgorithm::Ed25519,
            bytes: vec![0xab; 16],
        };
        assert!(ed25519_bytes("test", &pk).is_err());
    }

    #[test]
    fn ed25519_bytes_rejects_wrong_algorithm() {
        let pk = RawPublicKey {
            algorithm: KeyAlgorithm::EcdsaP256,
            bytes: vec![0xab; 32],
        };
        assert!(ed25519_bytes("test", &pk).is_err());
    }

    #[test]
    fn sec1_to_p256_extracts_coordinates() {
        let pk = RawPublicKey {
            algorithm: KeyAlgorithm::EcdsaP256,
            bytes: {
                let mut v = vec![0x04];
                v.extend_from_slice(&[0xaa; 32]);
                v.extend_from_slice(&[0xbb; 32]);
                v
            },
        };
        let p256 = sec1_to_p256("test", &pk).unwrap();
        assert_eq!(p256.x, [0xaa; 32]);
        assert_eq!(p256.y, [0xbb; 32]);
    }

    #[test]
    fn sec1_to_p256_rejects_wrong_length() {
        let pk = RawPublicKey {
            algorithm: KeyAlgorithm::EcdsaP256,
            bytes: vec![0x04; 64],
        };
        assert!(sec1_to_p256("test", &pk).is_err());
    }

    #[test]
    fn sec1_to_p256_rejects_compressed_form() {
        let pk = RawPublicKey {
            algorithm: KeyAlgorithm::EcdsaP256,
            bytes: {
                let mut v = vec![0x02]; // compressed prefix
                v.extend_from_slice(&[0xaa; 64]);
                v
            },
        };
        assert!(sec1_to_p256("test", &pk).is_err());
    }

    #[test]
    fn sec1_to_p256_rejects_wrong_algorithm() {
        let pk = RawPublicKey {
            algorithm: KeyAlgorithm::Ed25519,
            bytes: vec![0; 65],
        };
        assert!(sec1_to_p256("test", &pk).is_err());
    }
}
