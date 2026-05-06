//! JWS (JSON Web Signature) verification keyed by a public key the
//! header carries inline as `jwk`.
//!
//! Two callers in this codebase share this shape:
//!
//! - swiyu-issuer's OIDC4VCI credential endpoint (the wallet
//!   proof-of-possession JWT).
//! - swiyu-didtool's `verify-pop` command.
//!
//! Both want to take a parsed JWS header, dispatch on `alg`, parse
//! the embedded `jwk` into a verifying key, and check the signature
//! over the JWS signing input. The supported set is the same in
//! both places: `EdDSA` (Ed25519) and `ES256` (P-256) — these are
//! the algorithms SD-JWT VC and OIDC4VCI wallet stacks actually use.
//!
//! Higher-level concerns (claim validation, JWT parsing, error
//! mapping) stay at the call site; this module is the cryptographic
//! primitive.
//!
//! # Example
//!
//! ```ignore
//! use serde_json::json;
//! use swiyu_core::jws::verify_with_embedded_jwk;
//!
//! let header = json!({
//!     "alg": "EdDSA",
//!     "jwk": { "kty": "OKP", "crv": "Ed25519", "x": "<base64url>" },
//! });
//! verify_with_embedded_jwk(&header, signing_input, &signature_bytes)?;
//! ```

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::Verifier as _;
use serde_json::Value;

use crate::diddoc::PublicKeyJWK;

#[derive(Debug)]
pub enum JwsVerifyError {
    /// Header `alg` is not one of the algorithms this module
    /// supports (`EdDSA` or `ES256`).
    UnsupportedAlg(String),
    /// Header `alg` is supported, but the embedded `jwk` describes
    /// a key for a different algorithm.
    AlgKeyMismatch { alg: String, jwk_alg: &'static str },
    /// `jwk` field is missing, has the wrong shape, or the encoded
    /// key material is invalid.
    MalformedJwk(String),
    /// Signature is the wrong number of bytes for the algorithm.
    /// EdDSA and ES256 (in JWS form, raw `R || S`) are both 64
    /// bytes.
    InvalidSignatureLength { expected: usize, actual: usize },
    /// Signature is well-formed but did not verify against the key.
    SignatureMismatch,
}

impl fmt::Display for JwsVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedAlg(alg) => write!(
                f,
                "unsupported alg {alg:?}; expected \"EdDSA\" or \"ES256\""
            ),
            Self::AlgKeyMismatch { alg, jwk_alg } => write!(
                f,
                "alg {alg:?} does not match the jwk type (jwk implies alg={jwk_alg:?})"
            ),
            Self::MalformedJwk(msg) => write!(f, "malformed jwk: {msg}"),
            Self::InvalidSignatureLength { expected, actual } => write!(
                f,
                "invalid signature length: expected {expected} bytes, got {actual}"
            ),
            Self::SignatureMismatch => write!(f, "signature did not verify"),
        }
    }
}

impl std::error::Error for JwsVerifyError {}

/// A verifying key parsed from a `jwk`. Two variants because that's
/// the closed set this codebase uses for JWS verification; extend
/// here when a new algorithm lands.
#[derive(Debug, Clone)]
pub enum VerifyingKey {
    Ed25519(ed25519_dalek::VerifyingKey),
    EcdsaP256(p256::ecdsa::VerifyingKey),
}

impl VerifyingKey {
    /// JWS `alg` value matching the key's algorithm.
    pub fn alg(&self) -> &'static str {
        match self {
            Self::Ed25519(_) => "EdDSA",
            Self::EcdsaP256(_) => "ES256",
        }
    }

    /// Verifies `signature` over `signing_input`. Both `EdDSA` and
    /// `ES256` produce 64-byte signatures in JWS form (raw `R || S`
    /// for ES256), so a non-64 length is rejected up front rather
    /// than letting the underlying verifier fail with a less
    /// specific error.
    pub fn verify(&self, signing_input: &[u8], signature: &[u8]) -> Result<(), JwsVerifyError> {
        if signature.len() != 64 {
            return Err(JwsVerifyError::InvalidSignatureLength {
                expected: 64,
                actual: signature.len(),
            });
        }
        match self {
            Self::Ed25519(pk) => {
                let bytes: [u8; 64] = signature
                    .try_into()
                    .expect("length checked above; conversion is infallible");
                let sig = ed25519_dalek::Signature::from_bytes(&bytes);
                pk.verify(signing_input, &sig)
                    .map_err(|_| JwsVerifyError::SignatureMismatch)
            }
            Self::EcdsaP256(pk) => {
                use p256::ecdsa::signature::Verifier;
                let sig = p256::ecdsa::Signature::from_slice(signature)
                    .map_err(|_| JwsVerifyError::SignatureMismatch)?;
                pk.verify(signing_input, &sig)
                    .map_err(|_| JwsVerifyError::SignatureMismatch)
            }
        }
    }
}

/// Parses a typed [`PublicKeyJWK`] into a [`VerifyingKey`] usable
/// for JWS signature verification. Accepts only the two shapes JWS
/// callers in this codebase actually use:
///
/// - `OKPKey` with `crv = "Ed25519"`
/// - `ECKey`  with `crv = "P-256"`
impl TryFrom<&PublicKeyJWK> for VerifyingKey {
    type Error = JwsVerifyError;

    fn try_from(jwk: &PublicKeyJWK) -> Result<Self, Self::Error> {
        match jwk {
            PublicKeyJWK::OKP(k) if k.crv() == "Ed25519" => {
                let x = URL_SAFE_NO_PAD
                    .decode(k.x())
                    .map_err(|e| JwsVerifyError::MalformedJwk(format!("`x` not base64url: {e}")))?;
                let arr: [u8; 32] = x.try_into().map_err(|v: Vec<u8>| {
                    JwsVerifyError::MalformedJwk(format!(
                        "`x` must decode to 32 bytes for Ed25519, got {}",
                        v.len()
                    ))
                })?;
                let vk = ed25519_dalek::VerifyingKey::from_bytes(&arr).map_err(|e| {
                    JwsVerifyError::MalformedJwk(format!("invalid Ed25519 public key: {e}"))
                })?;
                Ok(VerifyingKey::Ed25519(vk))
            }
            PublicKeyJWK::EC(k) if k.crv() == "P-256" => {
                let vk = p256::ecdsa::VerifyingKey::try_from(k)
                    .map_err(|e| JwsVerifyError::MalformedJwk(e.to_string()))?;
                Ok(VerifyingKey::EcdsaP256(vk))
            }
            other => Err(JwsVerifyError::MalformedJwk(format!(
                "unsupported jwk: kty={kty}, crv={crv:?}",
                kty = other.kty(),
                crv = other.crv(),
            ))),
        }
    }
}

/// One-shot verification of a JWS whose public key is embedded in
/// the header as `jwk`. `header` is the parsed JOSE header (a JSON
/// object with `alg` and `jwk` fields).
///
/// Combines `VerifyingKey::try_from(&PublicKeyJWK)` and
/// [`VerifyingKey::verify`] behind a single call; the lower-level
/// pieces stay public so callers that already have a
/// [`VerifyingKey`] (from a multikey or a DID-document lookup) can
/// skip parsing.
pub fn verify_with_embedded_jwk(
    header: &Value,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<(), JwsVerifyError> {
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| JwsVerifyError::MalformedJwk("header missing `alg`".into()))?;
    if alg != "EdDSA" && alg != "ES256" {
        return Err(JwsVerifyError::UnsupportedAlg(alg.to_string()));
    }
    let jwk_value = header
        .get("jwk")
        .ok_or_else(|| JwsVerifyError::MalformedJwk("header missing `jwk`".into()))?;
    let jwk = PublicKeyJWK::try_from(jwk_value)
        .map_err(|e| JwsVerifyError::MalformedJwk(e.to_string()))?;
    let key = VerifyingKey::try_from(&jwk)?;
    if alg != key.alg() {
        return Err(JwsVerifyError::AlgKeyMismatch {
            alg: alg.to_string(),
            jwk_alg: key.alg(),
        });
    }
    key.verify(signing_input, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::Signer as _;
    use ed25519_dalek::SigningKey as Ed25519SigningKey;
    use p256::ecdsa::SigningKey as EcdsaSigningKey;
    use serde_json::json;

    // Deterministic test keys; both backends accept arbitrary 32-byte
    // values as scalars (no group-order edge cases at these constants).
    const ED25519_SEED: [u8; 32] = [7u8; 32];
    const ECDSA_SCALAR: [u8; 32] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc,
        0xfe, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff, 0x01,
    ];

    fn ed25519_signer() -> Ed25519SigningKey {
        Ed25519SigningKey::from_bytes(&ED25519_SEED)
    }

    fn ecdsa_signer() -> EcdsaSigningKey {
        EcdsaSigningKey::from_slice(&ECDSA_SCALAR).expect("constant scalar is valid")
    }

    fn ed25519_jwk_value(pk: &ed25519_dalek::VerifyingKey) -> Value {
        let x_b64 = URL_SAFE_NO_PAD.encode(pk.to_bytes());
        json!({ "kty": "OKP", "crv": "Ed25519", "x": x_b64 })
    }

    fn ecdsa_jwk_value(pk: &p256::ecdsa::VerifyingKey) -> Value {
        let encoded = pk.to_encoded_point(false);
        let bytes = encoded.as_bytes();
        let x_b64 = URL_SAFE_NO_PAD.encode(&bytes[1..33]);
        let y_b64 = URL_SAFE_NO_PAD.encode(&bytes[33..65]);
        json!({ "kty": "EC", "crv": "P-256", "x": x_b64, "y": y_b64 })
    }

    fn parse_jwk(v: &Value) -> PublicKeyJWK {
        PublicKeyJWK::try_from(v).expect("fixture jwk parses")
    }

    #[test]
    fn ed25519_jwk_parses_and_verifies() {
        let signer = ed25519_signer();
        let jwk = parse_jwk(&ed25519_jwk_value(&signer.verifying_key()));
        let key = VerifyingKey::try_from(&jwk).unwrap();
        assert_eq!(key.alg(), "EdDSA");

        let signing_input = b"hello.world";
        let sig = signer.sign(signing_input);
        key.verify(signing_input, &sig.to_bytes()).unwrap();
    }

    #[test]
    fn ecdsa_p256_jwk_parses_and_verifies() {
        let signer = ecdsa_signer();
        let jwk = parse_jwk(&ecdsa_jwk_value(signer.verifying_key()));
        let key = VerifyingKey::try_from(&jwk).unwrap();
        assert_eq!(key.alg(), "ES256");

        let signing_input = b"hello.world";
        let sig: p256::ecdsa::Signature = signer.sign(signing_input);
        key.verify(signing_input, &sig.to_bytes()).unwrap();
    }

    #[test]
    fn verify_rejects_signature_over_different_input() {
        let signer = ed25519_signer();
        let jwk = parse_jwk(&ed25519_jwk_value(&signer.verifying_key()));
        let key = VerifyingKey::try_from(&jwk).unwrap();

        let sig = signer.sign(b"original");
        let err = key.verify(b"tampered", &sig.to_bytes()).unwrap_err();
        assert!(matches!(err, JwsVerifyError::SignatureMismatch));
    }

    #[test]
    fn verify_rejects_signature_of_wrong_length() {
        let signer = ed25519_signer();
        let jwk = parse_jwk(&ed25519_jwk_value(&signer.verifying_key()));
        let key = VerifyingKey::try_from(&jwk).unwrap();

        let err = key.verify(b"hi", &[0u8; 63]).unwrap_err();
        assert!(matches!(
            err,
            JwsVerifyError::InvalidSignatureLength {
                expected: 64,
                actual: 63
            }
        ));
    }

    #[test]
    fn try_from_jwk_rejects_x25519() {
        // X25519 OKP (an encryption key, not a signing key) must not
        // be accepted.
        let v = json!({ "kty": "OKP", "crv": "X25519", "x": URL_SAFE_NO_PAD.encode([0u8; 32]) });
        let jwk = parse_jwk(&v);
        let err = VerifyingKey::try_from(&jwk).unwrap_err();
        assert!(matches!(err, JwsVerifyError::MalformedJwk(_)));
    }

    #[test]
    fn try_from_jwk_rejects_p384() {
        let v = json!({
            "kty": "EC",
            "crv": "P-384",
            "x": URL_SAFE_NO_PAD.encode([0u8; 48]),
            "y": URL_SAFE_NO_PAD.encode([0u8; 48]),
        });
        let jwk = parse_jwk(&v);
        let err = VerifyingKey::try_from(&jwk).unwrap_err();
        assert!(matches!(err, JwsVerifyError::MalformedJwk(_)));
    }

    #[test]
    fn verify_with_embedded_jwk_happy_path_eddsa() {
        let signer = ed25519_signer();
        let header = json!({
            "alg": "EdDSA",
            "jwk": ed25519_jwk_value(&signer.verifying_key()),
        });
        let signing_input = b"a.b";
        let sig = signer.sign(signing_input);
        verify_with_embedded_jwk(&header, signing_input, &sig.to_bytes()).unwrap();
    }

    #[test]
    fn verify_with_embedded_jwk_happy_path_es256() {
        let signer = ecdsa_signer();
        let header = json!({
            "alg": "ES256",
            "jwk": ecdsa_jwk_value(signer.verifying_key()),
        });
        let signing_input = b"a.b";
        let sig: p256::ecdsa::Signature = signer.sign(signing_input);
        verify_with_embedded_jwk(&header, signing_input, &sig.to_bytes()).unwrap();
    }

    #[test]
    fn verify_with_embedded_jwk_rejects_unsupported_alg() {
        let signer = ed25519_signer();
        let header = json!({
            "alg": "RS256",
            "jwk": ed25519_jwk_value(&signer.verifying_key()),
        });
        let err = verify_with_embedded_jwk(&header, b"a.b", &[0u8; 64]).unwrap_err();
        assert!(matches!(err, JwsVerifyError::UnsupportedAlg(_)));
    }

    #[test]
    fn verify_with_embedded_jwk_rejects_alg_key_mismatch() {
        // alg=ES256 but the jwk is an Ed25519 OKP key.
        let signer = ed25519_signer();
        let header = json!({
            "alg": "ES256",
            "jwk": ed25519_jwk_value(&signer.verifying_key()),
        });
        let err = verify_with_embedded_jwk(&header, b"a.b", &[0u8; 64]).unwrap_err();
        assert!(matches!(err, JwsVerifyError::AlgKeyMismatch { .. }));
    }

    #[test]
    fn verify_with_embedded_jwk_rejects_missing_alg() {
        let signer = ed25519_signer();
        let header = json!({ "jwk": ed25519_jwk_value(&signer.verifying_key()) });
        let err = verify_with_embedded_jwk(&header, b"a.b", &[0u8; 64]).unwrap_err();
        assert!(matches!(err, JwsVerifyError::MalformedJwk(_)));
    }

    #[test]
    fn verify_with_embedded_jwk_rejects_missing_jwk() {
        let header = json!({ "alg": "EdDSA" });
        let err = verify_with_embedded_jwk(&header, b"a.b", &[0u8; 64]).unwrap_err();
        assert!(matches!(err, JwsVerifyError::MalformedJwk(_)));
    }
}
