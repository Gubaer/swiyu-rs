use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use std::fmt;
use std::str::FromStr;

use crate::diddoc::{DIDDoc, PublicKey, PublicKeyJWK, VerificationMethod, VerificationMethodOrRef};

const PREFIX: &str = "did:jwk:";

#[derive(Debug, PartialEq)]
pub enum DIDJwkError {
    MissingPrefix,
    InvalidBase64,
    InvalidJson(String),
    InvalidJwk(String),
    UnsupportedAlgorithm(String),
    PrivateKeyMaterial,
    Canonicalization(String),
}

impl fmt::Display for DIDJwkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPrefix => write!(f, "input does not start with 'did:jwk:'"),
            Self::InvalidBase64 => {
                write!(f, "did:jwk suffix is not valid unpadded base64url")
            }
            Self::InvalidJson(msg) => write!(f, "did:jwk payload is not valid JSON: {msg}"),
            Self::InvalidJwk(msg) => write!(f, "did:jwk payload is not a valid JWK: {msg}"),
            Self::UnsupportedAlgorithm(s) => {
                write!(f, "unsupported algorithm '{s}' in did:jwk payload")
            }
            Self::PrivateKeyMaterial => {
                write!(f, "did:jwk payload contains private key material")
            }
            Self::Canonicalization(msg) => {
                write!(f, "could not canonicalise JWK to JSON: {msg}")
            }
        }
    }
}

impl std::error::Error for DIDJwkError {}

/// A DID according to the [did:jwk][did-jwk-spec] DID method.
///
/// `did:jwk` is a self-contained DID method: the entire public key is encoded
/// directly in the identifier, so no registry lookup is required to resolve it.
/// In the Swiss Trust Infrastructure context, `did:jwk` is used to identify
/// credential holders (wallet keys), while issuers and verifiers use
/// `did:tdw` / `did:webvh`.
///
/// [did-jwk-spec]: https://github.com/quartzjer/did-jwk/blob/main/spec.md
#[derive(Debug, Clone, PartialEq)]
pub struct DIDJwk {
    /// The full `did:jwk:<base64url(json)>` identifier string. On `parse`, this
    /// preserves the input verbatim (without any DID URL fragment or query) so
    /// signatures over the DID string remain verifiable; on `from_jwk` it holds
    /// the canonical (JCS-encoded) form.
    did: String,
    /// The decoded public JWK. Always public-only: any private key components
    /// in the input cause `parse` to fail with [`DIDJwkError::PrivateKeyMaterial`].
    jwk: PublicKeyJWK,
}

impl DIDJwk {
    /// Parses a `did:jwk:<base64url(json)>` identifier.
    ///
    /// `input` is expected to be a bare DID. As a convenience for callers that
    /// pass a DID URL (e.g. `did:jwk:...#0`, the verification method id of the
    /// embedded key), any fragment or query component is stripped before
    /// decoding and discarded; [`as_str`](Self::as_str) returns the bare DID.
    ///
    /// The base64url suffix must be unpadded (RFC 4648 §5). The decoded JSON
    /// must be a public JWK with `kty` of `OKP` (curve `Ed25519`) or `EC`
    /// (curve `P-256`); other key types and curves return
    /// [`DIDJwkError::UnsupportedAlgorithm`]. JWKs containing private key
    /// components (`d`, `p`, `q`, `dp`, `dq`, `qi`, `k`) are rejected with
    /// [`DIDJwkError::PrivateKeyMaterial`].
    ///
    /// # Example
    ///
    /// ```
    /// use swiyu_core::didjwk::DIDJwk;
    ///
    /// let did = DIDJwk::parse(
    ///     "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91\
    ///      c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1L\
    ///      dG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9",
    /// )
    /// .unwrap();
    ///
    /// assert_eq!(did.jwk().kty(), "EC");
    /// assert_eq!(did.jwk().crv(), Some("P-256"));
    /// ```
    pub fn parse(input: &str) -> Result<Self, DIDJwkError> {
        let suffix = input
            .strip_prefix(PREFIX)
            .ok_or(DIDJwkError::MissingPrefix)?;

        // Accept callers that pass a DID URL (e.g. "did:jwk:...#0") by stripping
        // the fragment and query before decoding. The DIDJwk represents the bare DID.
        let suffix = match suffix.split_once(['#', '?']) {
            Some((s, _)) => s,
            None => suffix,
        };

        let decoded = URL_SAFE_NO_PAD
            .decode(suffix)
            .map_err(|_| DIDJwkError::InvalidBase64)?;

        let value: serde_json::Value = serde_json::from_slice(&decoded)
            .map_err(|e| DIDJwkError::InvalidJson(e.to_string()))?;

        let obj = value
            .as_object()
            .ok_or_else(|| DIDJwkError::InvalidJwk("payload is not a JSON object".into()))?;

        if has_private_key_material(obj) {
            return Err(DIDJwkError::PrivateKeyMaterial);
        }

        let kty = obj
            .get("kty")
            .and_then(|v| v.as_str())
            .ok_or_else(|| DIDJwkError::InvalidJwk("missing or non-string 'kty'".into()))?;

        if kty != "OKP" && kty != "EC" {
            return Err(DIDJwkError::UnsupportedAlgorithm(kty.into()));
        }

        let jwk =
            PublicKeyJWK::try_from(&value).map_err(|e| DIDJwkError::InvalidJwk(e.to_string()))?;

        validate_curve(&jwk)?;

        Ok(Self {
            did: format!("{PREFIX}{suffix}"),
            jwk,
        })
    }

    /// Constructs a `did:jwk` identifier from a public JWK.
    ///
    /// `jwk` must be a public key with a supported algorithm: `OKP` with curve
    /// `Ed25519`, or `EC` with curve `P-256`. Other key types and curves return
    /// [`DIDJwkError::UnsupportedAlgorithm`].
    ///
    /// The JWK is serialised in canonical form (JCS, RFC 8785) before
    /// base64url-encoding, so the resulting identifier is stable: two JWKs with
    /// equal field content always produce the same DID, regardless of how they
    /// were constructed.
    ///
    /// # Example
    ///
    /// ```
    /// use swiyu_core::didjwk::DIDJwk;
    /// use swiyu_core::diddoc::PublicKeyJWK;
    ///
    /// let jwk = PublicKeyJWK::new_okp(
    ///     "Ed25519".into(),
    ///     "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo".into(),
    /// );
    /// let did = DIDJwk::from_jwk(&jwk).unwrap();
    /// assert!(did.as_str().starts_with("did:jwk:"));
    ///
    /// // Parsing the produced DID recovers the original JWK byte-for-byte.
    /// let parsed = DIDJwk::parse(did.as_str()).unwrap();
    /// assert_eq!(parsed.jwk(), &jwk);
    /// ```
    pub fn from_jwk(jwk: &PublicKeyJWK) -> Result<Self, DIDJwkError> {
        validate_curve(jwk)?;

        let value = Value::from(jwk.clone());
        let canonical = serde_jcs::to_string(&value)
            .map_err(|e| DIDJwkError::Canonicalization(e.to_string()))?;
        let encoded = URL_SAFE_NO_PAD.encode(canonical.as_bytes());

        Ok(Self {
            did: format!("{PREFIX}{encoded}"),
            jwk: jwk.clone(),
        })
    }

    pub fn as_str(&self) -> &str {
        &self.did
    }

    pub fn jwk(&self) -> &PublicKeyJWK {
        &self.jwk
    }

    pub fn to_diddoc(&self) -> DIDDoc {
        let vm_id = format!("{}#0", self.did);
        let vm = VerificationMethod::new(
            vm_id.clone(),
            "JsonWebKey2020".into(),
            self.did.clone(),
            PublicKey::Jwk(Box::new(self.jwk.clone())),
        );
        let vm_ref = VerificationMethodOrRef::Reference(vm_id);

        DIDDoc::new(self.did.clone())
            .add_verification_method(vm)
            .add_authentication(vm_ref.clone())
            .add_assertion_method(vm_ref.clone())
            .add_capability_invocation(vm_ref.clone())
            .add_capability_delegation(vm_ref)
    }
}

impl FromStr for DIDJwk {
    type Err = DIDJwkError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for DIDJwk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.did)
    }
}

fn validate_curve(jwk: &PublicKeyJWK) -> Result<(), DIDJwkError> {
    match jwk {
        PublicKeyJWK::OKP(k) if k.crv() == "Ed25519" => Ok(()),
        PublicKeyJWK::EC(k) if k.crv() == "P-256" => Ok(()),
        PublicKeyJWK::OKP(k) => Err(DIDJwkError::UnsupportedAlgorithm(format!(
            "OKP/{}",
            k.crv()
        ))),
        PublicKeyJWK::EC(k) => Err(DIDJwkError::UnsupportedAlgorithm(format!("EC/{}", k.crv()))),
        PublicKeyJWK::RSA(_) => Err(DIDJwkError::UnsupportedAlgorithm("RSA".into())),
    }
}

fn has_private_key_material(obj: &serde_json::Map<String, serde_json::Value>) -> bool {
    const PRIVATE_FIELDS: [&str; 7] = ["d", "p", "q", "dp", "dq", "qi", "k"];
    PRIVATE_FIELDS.iter().any(|f| obj.contains_key(*f))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // P-256 example lifted from the did:jwk specification.
    const SPEC_EXAMPLE_P256: &str = "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91\
        c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1L\
        dG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9";

    #[test]
    fn parse_spec_example() {
        let did = DIDJwk::parse(SPEC_EXAMPLE_P256).expect("must parse spec example");
        assert_eq!(did.as_str(), SPEC_EXAMPLE_P256);
        assert_eq!(did.jwk().kty(), "EC");
        assert_eq!(did.jwk().crv(), Some("P-256"));
        assert_eq!(
            did.jwk().x(),
            Some("acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0")
        );
        assert_eq!(
            did.jwk().y(),
            Some("_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE")
        );
    }

    #[test]
    fn parse_strips_fragment_and_query() {
        let with_frag = format!("{SPEC_EXAMPLE_P256}#0");
        let did = DIDJwk::parse(&with_frag).expect("must parse DID URL with fragment");
        assert_eq!(did.as_str(), SPEC_EXAMPLE_P256);

        let with_query = format!("{SPEC_EXAMPLE_P256}?versionId=1");
        let did = DIDJwk::parse(&with_query).expect("must parse DID URL with query");
        assert_eq!(did.as_str(), SPEC_EXAMPLE_P256);
    }

    #[test]
    fn missing_prefix_is_rejected() {
        assert_eq!(
            DIDJwk::parse("did:tdw:somethingelse"),
            Err(DIDJwkError::MissingPrefix)
        );
    }

    #[test]
    fn padded_base64_is_rejected() {
        // valid OKP JWK encoded with padding -- the URL_SAFE_NO_PAD decoder must reject it.
        let padded = "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IjExcVlBWUt4Q3JmVlNfN1R5V1FIT2c3aGN2UGFwaU1scndJYWFQY0hVUm8ifQ==";
        assert_eq!(DIDJwk::parse(padded), Err(DIDJwkError::InvalidBase64));
    }

    #[test]
    fn private_key_material_is_rejected() {
        // OKP JWK with a "d" (private scalar) field.
        let jwk = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            "d": "private_scalar_must_be_rejected"
        });
        let encoded = URL_SAFE_NO_PAD.encode(jwk.to_string().as_bytes());
        let did = format!("{PREFIX}{encoded}");
        assert_eq!(DIDJwk::parse(&did), Err(DIDJwkError::PrivateKeyMaterial));
    }

    #[test]
    fn rsa_is_unsupported() {
        let jwk = json!({ "kty": "RSA", "n": "modulus", "e": "AQAB" });
        let encoded = URL_SAFE_NO_PAD.encode(jwk.to_string().as_bytes());
        let did = format!("{PREFIX}{encoded}");
        assert!(matches!(
            DIDJwk::parse(&did),
            Err(DIDJwkError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn oct_is_unsupported() {
        let jwk = json!({ "kty": "oct", "k": "secret_must_not_get_to_kty_check" });
        let encoded = URL_SAFE_NO_PAD.encode(jwk.to_string().as_bytes());
        let did = format!("{PREFIX}{encoded}");
        // Symmetric keys carry "k" which is private material; that check fires first.
        assert_eq!(DIDJwk::parse(&did), Err(DIDJwkError::PrivateKeyMaterial));
    }

    #[test]
    fn unsupported_curve_for_ec_is_rejected() {
        let jwk = json!({ "kty": "EC", "crv": "P-384", "x": "x", "y": "y" });
        let encoded = URL_SAFE_NO_PAD.encode(jwk.to_string().as_bytes());
        let did = format!("{PREFIX}{encoded}");
        assert!(matches!(
            DIDJwk::parse(&did),
            Err(DIDJwkError::UnsupportedAlgorithm(s)) if s == "EC/P-384"
        ));
    }

    #[test]
    fn unsupported_curve_for_okp_is_rejected() {
        let jwk = json!({ "kty": "OKP", "crv": "X25519", "x": "abc" });
        let encoded = URL_SAFE_NO_PAD.encode(jwk.to_string().as_bytes());
        let did = format!("{PREFIX}{encoded}");
        assert!(matches!(
            DIDJwk::parse(&did),
            Err(DIDJwkError::UnsupportedAlgorithm(s)) if s == "OKP/X25519"
        ));
    }

    #[test]
    fn from_jwk_roundtrip_okp() {
        let jwk = PublicKeyJWK::new_okp(
            "Ed25519".into(),
            "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo".into(),
        );
        let did = DIDJwk::from_jwk(&jwk).unwrap();
        let parsed = DIDJwk::parse(did.as_str()).unwrap();
        assert_eq!(parsed.jwk(), &jwk);
        assert_eq!(parsed.as_str(), did.as_str());
    }

    #[test]
    fn from_jwk_roundtrip_ec() {
        let jwk = PublicKeyJWK::new_ec("P-256".into(), "xval".into(), "yval".into());
        let did = DIDJwk::from_jwk(&jwk).unwrap();
        let parsed = DIDJwk::parse(did.as_str()).unwrap();
        assert_eq!(parsed.jwk(), &jwk);
    }

    #[test]
    fn from_jwk_canonical_encoding_is_stable() {
        // Two JWKs with the same content but field-order independence:
        // from_jwk must produce identical output regardless of how the source
        // JWK was constructed, because JCS sorts keys.
        let jwk_a = PublicKeyJWK::new_ec("P-256".into(), "X1".into(), "Y1".into());
        let jwk_b = PublicKeyJWK::new_ec("P-256".into(), "X1".into(), "Y1".into());
        assert_eq!(
            DIDJwk::from_jwk(&jwk_a).unwrap().as_str(),
            DIDJwk::from_jwk(&jwk_b).unwrap().as_str()
        );
    }

    #[test]
    fn from_jwk_rejects_rsa() {
        let jwk = PublicKeyJWK::new_rsa("modulus".into(), "AQAB".into());
        assert!(matches!(
            DIDJwk::from_jwk(&jwk),
            Err(DIDJwkError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn from_str_and_display() {
        let did: DIDJwk = SPEC_EXAMPLE_P256.parse().unwrap();
        assert_eq!(did.to_string(), SPEC_EXAMPLE_P256);
    }

    #[test]
    fn to_diddoc_has_expected_shape() {
        let did = DIDJwk::parse(SPEC_EXAMPLE_P256).unwrap();
        let doc = did.to_diddoc();
        let json = Value::from(doc);
        let expected_vm_id = format!("{SPEC_EXAMPLE_P256}#0");

        assert_eq!(json["id"], json!(SPEC_EXAMPLE_P256));

        let vms = json["verificationMethod"].as_array().unwrap();
        assert_eq!(vms.len(), 1);
        assert_eq!(vms[0]["id"], json!(expected_vm_id));
        assert_eq!(vms[0]["type"], json!("JsonWebKey2020"));
        assert_eq!(vms[0]["controller"], json!(SPEC_EXAMPLE_P256));
        assert_eq!(vms[0]["publicKeyJwk"]["kty"], json!("EC"));
        assert_eq!(vms[0]["publicKeyJwk"]["crv"], json!("P-256"));

        for relation in [
            "authentication",
            "assertionMethod",
            "capabilityInvocation",
            "capabilityDelegation",
        ] {
            let arr = json[relation].as_array().unwrap();
            assert_eq!(arr.len(), 1);
            assert_eq!(arr[0], json!(expected_vm_id));
        }

        // key_agreement is intentionally absent for Ed25519/P-256 signing keys.
        assert!(json.get("keyAgreement").is_none());
    }

    #[test]
    fn invalid_json_payload_is_rejected() {
        let encoded = URL_SAFE_NO_PAD.encode(b"not json at all");
        let did = format!("{PREFIX}{encoded}");
        assert!(matches!(
            DIDJwk::parse(&did),
            Err(DIDJwkError::InvalidJson(_))
        ));
    }

    #[test]
    fn non_object_payload_is_rejected() {
        let encoded = URL_SAFE_NO_PAD.encode(b"\"a string, not an object\"");
        let did = format!("{PREFIX}{encoded}");
        assert!(matches!(
            DIDJwk::parse(&did),
            Err(DIDJwkError::InvalidJwk(_))
        ));
    }

    #[test]
    fn missing_kty_is_rejected() {
        let encoded = URL_SAFE_NO_PAD.encode(b"{\"crv\":\"P-256\",\"x\":\"x\",\"y\":\"y\"}");
        let did = format!("{PREFIX}{encoded}");
        assert!(matches!(
            DIDJwk::parse(&did),
            Err(DIDJwkError::InvalidJwk(_))
        ));
    }
}
