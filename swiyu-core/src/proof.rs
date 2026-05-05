//! Data Integrity proofs for DID-log entries.
//!
//! Currently supports the eddsa-jcs-2022 cryptosuite from W3C
//! VC Data Integrity EdDSA Cryptosuites, used by both did:tdw 0.3
//! and did:webvh 1.0. The module exposes typed wrappers around the
//! JSON shape so write-side code (issuer, didtool) constructs proofs
//! through one path and read-side code (verifier) destructures them
//! consistently.

use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Map, Value, json};
use std::fmt;
use std::str::FromStr;

use crate::didlog::eddsa_jcs_2022_hash;

const PROOF_TYPE: &str = "DataIntegrityProof";

#[derive(Debug)]
pub enum ProofError {
    UnknownCryptosuite(String),
    UnknownProofPurpose(String),
    MissingField(&'static str),
    InvalidField {
        field: &'static str,
        message: String,
    },
    InvalidEncoding(String),
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownCryptosuite(s) => write!(f, "unknown cryptosuite: {s}"),
            Self::UnknownProofPurpose(s) => write!(f, "unknown proof purpose: {s}"),
            Self::MissingField(field) => write!(f, "missing field: {field}"),
            Self::InvalidField { field, message } => {
                write!(f, "invalid field '{field}': {message}")
            }
            Self::InvalidEncoding(s) => write!(f, "invalid encoding: {s}"),
        }
    }
}

impl std::error::Error for ProofError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Cryptosuite {
    /// `eddsa-jcs-2022` from the W3C VC Data Integrity EdDSA
    /// Cryptosuites spec. Signs the 64-byte concatenation
    /// `SHA-256(JCS(proof_config)) || SHA-256(JCS(document))` with
    /// plain Ed25519 (not Ed25519ph). Used by `did:tdw` 0.3 and
    /// `did:webvh` 1.0.
    EddsaJcs2022,
}

impl Cryptosuite {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EddsaJcs2022 => "eddsa-jcs-2022",
        }
    }
}

impl FromStr for Cryptosuite {
    type Err = ProofError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "eddsa-jcs-2022" => Ok(Self::EddsaJcs2022),
            other => Err(ProofError::UnknownCryptosuite(other.into())),
        }
    }
}

/// The role the proof key plays for the document being signed.
/// Mapped to the `proofPurpose` field of the proof and constrained
/// to the two purposes used by the SWIYU DID methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProofPurpose {
    /// `authentication`. Used by `did:tdw` 0.3 — the genesis and
    /// every subsequent log entry are signed under this purpose.
    Authentication,

    /// `assertionMethod`. Used by `did:webvh` 1.0 log entries.
    AssertionMethod,
}

impl ProofPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::AssertionMethod => "assertionMethod",
        }
    }
}

impl FromStr for ProofPurpose {
    type Err = ProofError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "authentication" => Ok(Self::Authentication),
            "assertionMethod" => Ok(Self::AssertionMethod),
            other => Err(ProofError::UnknownProofPurpose(other.into())),
        }
    }
}

/// The "proof options" portion of a Data Integrity proof — every
/// field of the final proof except `proofValue`. The cryptosuite-
/// specific signing input is computed from this plus the document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofConfig {
    pub cryptosuite: Cryptosuite,
    pub verification_method: String,
    pub proof_purpose: ProofPurpose,
    pub challenge: String,
    pub created: String,
}

impl ProofConfig {
    /// Returns the bytes the cryptosuite specifies as the input to
    /// the signing operation. For eddsa-jcs-2022 these are 64 bytes:
    /// SHA-256(JCS(self)) || SHA-256(JCS(document)).
    pub fn signing_input(&self, document: &Value) -> Vec<u8> {
        match self.cryptosuite {
            Cryptosuite::EddsaJcs2022 => {
                eddsa_jcs_2022_hash(document, &Value::from(self.clone())).to_vec()
            }
        }
    }
}

impl From<ProofConfig> for Value {
    fn from(config: ProofConfig) -> Self {
        json!({
            "type": PROOF_TYPE,
            "cryptosuite": config.cryptosuite.as_str(),
            "verificationMethod": config.verification_method,
            "proofPurpose": config.proof_purpose.as_str(),
            "challenge": config.challenge,
            "created": config.created,
        })
    }
}

/// A complete Data Integrity proof: the config plus the multibase-z
/// signature in `proof_value`. This is the shape that gets serialised
/// into a DID-log entry's proof slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataIntegrityProof {
    pub config: ProofConfig,
    pub proof_value: String,
}

impl DataIntegrityProof {
    /// Signs `document` under `config` with `signer` and returns the
    /// assembled proof.
    ///
    /// The signing input is determined by the cryptosuite via
    /// [`ProofConfig::signing_input`]; for `eddsa-jcs-2022` that's the
    /// 64-byte `SHA-256(JCS(config)) || SHA-256(JCS(document))`.
    pub fn sign(signer: &SigningKey, document: &Value, config: ProofConfig) -> Self {
        let hash_data = config.signing_input(document);
        let signature = signer.sign(&hash_data);
        Self::from_signature(config, &signature.to_bytes())
    }

    /// Wraps a raw signature (64 bytes for eddsa-jcs-2022) in the
    /// multibase-z encoding the cryptosuite specifies, and returns
    /// the assembled proof.
    pub fn from_signature(config: ProofConfig, signature: &[u8]) -> Self {
        let proof_value = format!("z{}", bs58::encode(signature).into_string());
        Self {
            config,
            proof_value,
        }
    }

    /// Decodes `proof_value` from multibase-z (the `z` prefix marks
    /// bs58btc) into the raw signature bytes.
    pub fn decode_signature(&self) -> Result<Vec<u8>, ProofError> {
        let stripped = self.proof_value.strip_prefix('z').ok_or_else(|| {
            ProofError::InvalidEncoding("proofValue does not start with multibase-z prefix".into())
        })?;
        bs58::decode(stripped)
            .into_vec()
            .map_err(|e| ProofError::InvalidEncoding(format!("bs58 decode failed: {e}")))
    }
}

impl From<DataIntegrityProof> for Value {
    fn from(proof: DataIntegrityProof) -> Self {
        let DataIntegrityProof {
            config,
            proof_value,
        } = proof;
        let mut obj = match Value::from(config) {
            Value::Object(m) => m,
            _ => unreachable!("ProofConfig serialises to a JSON object"),
        };
        obj.insert("proofValue".into(), Value::String(proof_value));
        Value::Object(obj)
    }
}

impl TryFrom<&Value> for DataIntegrityProof {
    type Error = ProofError;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        let obj = value.as_object().ok_or_else(|| ProofError::InvalidField {
            field: "<proof>",
            message: "proof is not a JSON object".into(),
        })?;

        let proof_type = string_field(obj, "type")?;
        if proof_type != PROOF_TYPE {
            return Err(ProofError::InvalidField {
                field: "type",
                message: format!("expected '{PROOF_TYPE}', got '{proof_type}'"),
            });
        }

        let cryptosuite = Cryptosuite::from_str(&string_field(obj, "cryptosuite")?)?;
        let verification_method = string_field(obj, "verificationMethod")?;
        let proof_purpose = ProofPurpose::from_str(&string_field(obj, "proofPurpose")?)?;
        let challenge = string_field(obj, "challenge")?;
        let created = string_field(obj, "created")?;
        let proof_value = string_field(obj, "proofValue")?;

        Ok(Self {
            config: ProofConfig {
                cryptosuite,
                verification_method,
                proof_purpose,
                challenge,
                created,
            },
            proof_value,
        })
    }
}

fn string_field(obj: &Map<String, Value>, field: &'static str) -> Result<String, ProofError> {
    obj.get(field)
        .ok_or(ProofError::MissingField(field))?
        .as_str()
        .ok_or_else(|| ProofError::InvalidField {
            field,
            message: "must be a string".into(),
        })
        .map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_config() -> ProofConfig {
        ProofConfig {
            cryptosuite: Cryptosuite::EddsaJcs2022,
            verification_method: "did:key:z6Mk-abc#z6Mk-abc".into(),
            proof_purpose: ProofPurpose::Authentication,
            challenge: "1-Qm-entryhash".into(),
            created: "2026-05-04T12:00:00Z".into(),
        }
    }

    #[test]
    fn cryptosuite_round_trips() {
        assert_eq!(
            Cryptosuite::from_str("eddsa-jcs-2022").unwrap(),
            Cryptosuite::EddsaJcs2022
        );
        assert_eq!(Cryptosuite::EddsaJcs2022.as_str(), "eddsa-jcs-2022");
    }

    #[test]
    fn cryptosuite_parse_rejects_unknown() {
        assert!(Cryptosuite::from_str("eddsa-rdfc-2022").is_err());
    }

    #[test]
    fn proof_purpose_round_trips() {
        for purpose in [ProofPurpose::Authentication, ProofPurpose::AssertionMethod] {
            assert_eq!(ProofPurpose::from_str(purpose.as_str()).unwrap(), purpose);
        }
    }

    #[test]
    fn proof_purpose_parse_rejects_unknown() {
        assert!(ProofPurpose::from_str("capabilityInvocation").is_err());
    }

    #[test]
    fn proof_config_to_value_includes_type_and_all_fields() {
        let value = Value::from(fixture_config());
        assert_eq!(value["type"], "DataIntegrityProof");
        assert_eq!(value["cryptosuite"], "eddsa-jcs-2022");
        assert_eq!(value["verificationMethod"], "did:key:z6Mk-abc#z6Mk-abc");
        assert_eq!(value["proofPurpose"], "authentication");
        assert_eq!(value["challenge"], "1-Qm-entryhash");
        assert_eq!(value["created"], "2026-05-04T12:00:00Z");
    }

    #[test]
    fn signing_input_for_eddsa_jcs_2022_is_64_bytes() {
        let document = json!({"id": "did:tdw:example:abc"});
        let input = fixture_config().signing_input(&document);
        assert_eq!(input.len(), 64);
    }

    #[test]
    fn signing_input_is_deterministic() {
        let document = json!({"a": 1, "b": 2});
        let a = fixture_config().signing_input(&document);
        let b = fixture_config().signing_input(&document);
        assert_eq!(a, b);
    }

    #[test]
    fn sign_produces_proof_that_self_verifies() {
        use ed25519_dalek::Verifier;
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        let document = json!({"id": "did:tdw:example:abc"});

        let proof = DataIntegrityProof::sign(&signer, &document, fixture_config());

        let signature = proof.decode_signature().unwrap();
        let signature_arr: [u8; 64] = signature.try_into().unwrap();
        let hash_data = proof.config.signing_input(&document);
        signer
            .verifying_key()
            .verify(
                &hash_data,
                &ed25519_dalek::Signature::from_bytes(&signature_arr),
            )
            .unwrap();
    }

    #[test]
    fn data_integrity_proof_value_round_trips() {
        let signature = [0x42_u8; 64];
        let proof = DataIntegrityProof::from_signature(fixture_config(), &signature);

        let value = Value::from(proof.clone());
        assert_eq!(value["type"], "DataIntegrityProof");
        assert!(value["proofValue"].as_str().unwrap().starts_with('z'));

        let parsed = DataIntegrityProof::try_from(&value).unwrap();
        assert_eq!(parsed, proof);
    }

    #[test]
    fn decode_signature_recovers_raw_bytes() {
        let signature = (0..64_u8).collect::<Vec<u8>>();
        let proof = DataIntegrityProof::from_signature(fixture_config(), &signature);
        assert_eq!(proof.decode_signature().unwrap(), signature);
    }

    #[test]
    fn try_from_value_rejects_wrong_type() {
        let mut value = Value::from(DataIntegrityProof::from_signature(
            fixture_config(),
            &[0; 64],
        ));
        value["type"] = json!("VerifiableCredential");
        let err = DataIntegrityProof::try_from(&value).unwrap_err();
        assert!(matches!(
            err,
            ProofError::InvalidField { field: "type", .. }
        ));
    }

    #[test]
    fn try_from_value_rejects_missing_proof_value() {
        let mut value = Value::from(DataIntegrityProof::from_signature(
            fixture_config(),
            &[0; 64],
        ));
        value.as_object_mut().unwrap().remove("proofValue");
        let err = DataIntegrityProof::try_from(&value).unwrap_err();
        assert!(matches!(err, ProofError::MissingField("proofValue")));
    }

    #[test]
    fn try_from_value_rejects_unknown_cryptosuite() {
        let mut value = Value::from(DataIntegrityProof::from_signature(
            fixture_config(),
            &[0; 64],
        ));
        value["cryptosuite"] = json!("eddsa-rdfc-2022");
        let err = DataIntegrityProof::try_from(&value).unwrap_err();
        assert!(matches!(err, ProofError::UnknownCryptosuite(_)));
    }

    #[test]
    fn decode_signature_rejects_missing_z_prefix() {
        let proof = DataIntegrityProof {
            config: fixture_config(),
            proof_value: "abcdef".into(),
        };
        assert!(matches!(
            proof.decode_signature(),
            Err(ProofError::InvalidEncoding(_))
        ));
    }
}
