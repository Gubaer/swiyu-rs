//! Public key types for DID verification methods.
//!
//! Provides [`PublicKeyJWK`] (RFC 7517/7518) and [`PublicKeyMultibase`] (base58btc multibase),
//! which are the two key representations used in W3C DID documents. Both are wrapped by the
//! [`PublicKey`] enum, which is embedded in every [`super::VerificationMethod`].

use serde_json::{Map, Value, json};
use std::fmt;

use super::{DIDDocError, DIDDocResult};

/// Intended use of a JWK key (RFC 7517 §4.2).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeyUse {
    /// Key is used for digital signature or MAC operations (`"sig"`).
    Sig,
    /// Key is used for encryption operations (`"enc"`).
    Enc,
}

impl KeyUse {
    fn try_from_str(s: &str) -> DIDDocResult<Self> {
        match s {
            "sig" => Ok(Self::Sig),
            "enc" => Ok(Self::Enc),
            other => Err(DIDDocError::InvalidFormat(format!(
                "unknown key use '{other}'; expected 'sig' or 'enc'"
            ))),
        }
    }
}

impl fmt::Display for KeyUse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Sig => "sig",
            Self::Enc => "enc",
        })
    }
}

/// Elliptic Curve public key (`kty = "EC"`). Curves: "P-256", "P-384", "P-521".
#[derive(Debug, Clone, PartialEq)]
pub struct ECKey {
    crv: String,
    x: String,
    y: String,
    use_: Option<KeyUse>,
    key_ops: Option<Vec<String>>,
    alg: Option<String>,
    kid: Option<String>,
}

impl ECKey {
    /// Creates an EC public key. `crv` is the curve name (e.g. `"P-256"`), `x` and `y` are the
    /// base64url-encoded public point coordinates.
    pub fn new(crv: String, x: String, y: String) -> Self {
        Self {
            crv,
            x,
            y,
            use_: None,
            key_ops: None,
            alg: None,
            kid: None,
        }
    }

    fn try_from_json(obj: &Map<String, Value>) -> DIDDocResult<Self> {
        Ok(Self {
            crv: super::required_string(obj, "crv")?,
            x: super::required_string(obj, "x")?,
            y: super::required_string(obj, "y")?,
            use_: parse_key_use(obj)?,
            key_ops: super::optional_string_array(obj, "key_ops")?,
            alg: super::optional_string(obj, "alg")?,
            kid: super::optional_string(obj, "kid")?,
        })
    }

    fn to_json(&self) -> Value {
        let mut map = Map::new();
        map.insert("kty".into(), json!("EC"));
        map.insert("crv".into(), json!(self.crv));
        map.insert("x".into(), json!(self.x));
        map.insert("y".into(), json!(self.y));
        insert_jwk_optional_fields(&mut map, &self.use_, &self.key_ops, &self.alg, &self.kid);
        Value::Object(map)
    }

    pub fn crv(&self) -> &str {
        &self.crv
    }

    pub fn x(&self) -> &str {
        &self.x
    }

    pub fn y(&self) -> &str {
        &self.y
    }

    /// Returns the intended use of the key. Corresponds to the `use` field in RFC 7517 §4.2.
    pub fn use_(&self) -> Option<KeyUse> {
        self.use_
    }

    /// Returns the permitted key operations (e.g. `"sign"`, `"verify"`, `"encrypt"`).
    /// Corresponds to the `key_ops` field in RFC 7517 §4.3.
    pub fn key_ops(&self) -> Option<&[String]> {
        self.key_ops.as_deref()
    }

    /// Returns the intended algorithm for use with the key (e.g. `"EdDSA"`, `"ES256"`, `"RS256"`).
    /// Corresponds to the `alg` field in RFC 7517 §4.4.
    pub fn alg(&self) -> Option<&str> {
        self.alg.as_deref()
    }

    /// Returns the key ID, which identifies a specific key within a key set.
    /// Corresponds to the `kid` field in RFC 7517 §4.5.
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }
}

/// Octet Key Pair public key (`kty = "OKP"`). Curves: "Ed25519", "X25519".
#[derive(Debug, Clone, PartialEq)]
pub struct OKPKey {
    crv: String,
    x: String,
    use_: Option<KeyUse>,
    key_ops: Option<Vec<String>>,
    alg: Option<String>,
    kid: Option<String>,
}

impl OKPKey {
    /// Creates an OKP public key. `crv` is the curve name (e.g. `"Ed25519"`), `x` is the
    /// base64url-encoded public key value.
    pub fn new(crv: String, x: String) -> Self {
        Self {
            crv,
            x,
            use_: None,
            key_ops: None,
            alg: None,
            kid: None,
        }
    }

    fn try_from_json(obj: &Map<String, Value>) -> DIDDocResult<Self> {
        Ok(Self {
            crv: super::required_string(obj, "crv")?,
            x: super::required_string(obj, "x")?,
            use_: parse_key_use(obj)?,
            key_ops: super::optional_string_array(obj, "key_ops")?,
            alg: super::optional_string(obj, "alg")?,
            kid: super::optional_string(obj, "kid")?,
        })
    }

    fn to_json(&self) -> Value {
        let mut map = Map::new();
        map.insert("kty".into(), json!("OKP"));
        map.insert("crv".into(), json!(self.crv));
        map.insert("x".into(), json!(self.x));
        insert_jwk_optional_fields(&mut map, &self.use_, &self.key_ops, &self.alg, &self.kid);
        Value::Object(map)
    }

    pub fn crv(&self) -> &str {
        &self.crv
    }

    pub fn x(&self) -> &str {
        &self.x
    }

    /// Returns the intended use of the key. Corresponds to the `use` field in RFC 7517 §4.2.
    pub fn use_(&self) -> Option<KeyUse> {
        self.use_
    }

    /// Returns the permitted key operations (e.g. `"sign"`, `"verify"`, `"encrypt"`).
    /// Corresponds to the `key_ops` field in RFC 7517 §4.3.
    pub fn key_ops(&self) -> Option<&[String]> {
        self.key_ops.as_deref()
    }

    /// Returns the intended algorithm for use with the key (e.g. `"EdDSA"`, `"ES256"`, `"RS256"`).
    /// Corresponds to the `alg` field in RFC 7517 §4.4.
    pub fn alg(&self) -> Option<&str> {
        self.alg.as_deref()
    }

    /// Returns the key ID, which identifies a specific key within a key set.
    /// Corresponds to the `kid` field in RFC 7517 §4.5.
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }
}

/// RSA public key (`kty = "RSA"`).
#[derive(Debug, Clone, PartialEq)]
pub struct RSAKey {
    n: String,
    e: String,
    use_: Option<KeyUse>,
    key_ops: Option<Vec<String>>,
    alg: Option<String>,
    kid: Option<String>,
}

impl RSAKey {
    /// Creates an RSA public key. `n` is the base64url-encoded modulus and `e` the public exponent.
    pub fn new(n: String, e: String) -> Self {
        Self {
            n,
            e,
            use_: None,
            key_ops: None,
            alg: None,
            kid: None,
        }
    }

    fn try_from_json(obj: &Map<String, Value>) -> DIDDocResult<Self> {
        Ok(Self {
            n: super::required_string(obj, "n")?,
            e: super::required_string(obj, "e")?,
            use_: parse_key_use(obj)?,
            key_ops: super::optional_string_array(obj, "key_ops")?,
            alg: super::optional_string(obj, "alg")?,
            kid: super::optional_string(obj, "kid")?,
        })
    }

    fn to_json(&self) -> Value {
        let mut map = Map::new();
        map.insert("kty".into(), json!("RSA"));
        map.insert("n".into(), json!(self.n));
        map.insert("e".into(), json!(self.e));
        insert_jwk_optional_fields(&mut map, &self.use_, &self.key_ops, &self.alg, &self.kid);
        Value::Object(map)
    }

    /// Returns the RSA modulus (base64url-encoded).
    pub fn n(&self) -> &str {
        &self.n
    }

    /// Returns the RSA public exponent (base64url-encoded).
    pub fn e(&self) -> &str {
        &self.e
    }

    /// Returns the intended use of the key. Corresponds to the `use` field in RFC 7517 §4.2.
    pub fn use_(&self) -> Option<KeyUse> {
        self.use_
    }

    /// Returns the permitted key operations (e.g. `"sign"`, `"verify"`, `"encrypt"`).
    /// Corresponds to the `key_ops` field in RFC 7517 §4.3.
    pub fn key_ops(&self) -> Option<&[String]> {
        self.key_ops.as_deref()
    }

    /// Returns the intended algorithm for use with the key (e.g. `"EdDSA"`, `"ES256"`, `"RS256"`).
    /// Corresponds to the `alg` field in RFC 7517 §4.4.
    pub fn alg(&self) -> Option<&str> {
        self.alg.as_deref()
    }

    /// Returns the key ID, which identifies a specific key within a key set.
    /// Corresponds to the `kid` field in RFC 7517 §4.5.
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }
}

/// Public key in JWK format (RFC 7517/7518), public key material only.
#[derive(Debug, Clone, PartialEq)]
pub enum PublicKeyJWK {
    EC(ECKey),
    OKP(OKPKey),
    RSA(RSAKey),
}

impl PublicKeyJWK {
    /// Creates an EC public key. `crv` is the curve name (e.g. `"P-256"`), `x` and `y` are the
    /// base64url-encoded public point coordinates.
    pub fn new_ec(crv: String, x: String, y: String) -> Self {
        Self::EC(ECKey::new(crv, x, y))
    }

    /// Creates an OKP public key. `crv` is the curve name (e.g. `"Ed25519"`), `x` is the
    /// base64url-encoded public key value.
    pub fn new_okp(crv: String, x: String) -> Self {
        Self::OKP(OKPKey::new(crv, x))
    }

    /// Creates an RSA public key. `n` is the base64url-encoded modulus and `e` the public exponent.
    pub fn new_rsa(n: String, e: String) -> Self {
        Self::RSA(RSAKey::new(n, e))
    }

    /// Parses a JWK public key from its JSON representation (RFC 7517).
    ///
    /// The `kty` field determines which variant is returned. Key-type-specific
    /// fields (`crv`, `x`, `y` for EC/OKP; `n`, `e` for RSA) are required and
    /// produce an error if absent. Returns [`DIDDocError::InvalidFormat`] for
    /// an unrecognised `kty`.
    ///
    /// # Example
    ///
    /// ```
    /// use swiyu_core::diddoc::{PublicKeyJWK, DIDDocError};
    /// use serde_json::json;
    ///
    /// let v = json!({ "kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" });
    /// let jwk = PublicKeyJWK::try_from_json(&v).unwrap();
    /// assert_eq!(jwk.kty(), "OKP");
    /// assert_eq!(jwk.crv(), Some("Ed25519"));
    ///
    /// let bad = json!({ "kty": "oct", "k": "secret" });
    /// assert!(matches!(PublicKeyJWK::try_from_json(&bad), Err(DIDDocError::InvalidFormat(_))));
    /// ```
    pub fn try_from_json(v: &Value) -> DIDDocResult<Self> {
        let obj = v.as_object().ok_or_else(|| {
            DIDDocError::InvalidFieldType("publicKeyJwk must be a JSON object".into())
        })?;
        let kty = super::required_string(obj, "kty")?;
        match kty.as_str() {
            "EC" => Ok(Self::EC(ECKey::try_from_json(obj)?)),
            "OKP" => Ok(Self::OKP(OKPKey::try_from_json(obj)?)),
            "RSA" => Ok(Self::RSA(RSAKey::try_from_json(obj)?)),
            other => Err(DIDDocError::InvalidFormat(format!(
                "unsupported JWK key type '{other}'; expected 'EC', 'OKP', or 'RSA'"
            ))),
        }
    }

    /// Serialises the key to its JWK JSON representation (RFC 7517).
    /// Only fields that are set are included; absent optional fields are omitted entirely.
    pub fn to_json(&self) -> Value {
        match self {
            Self::EC(key) => key.to_json(),
            Self::OKP(key) => key.to_json(),
            Self::RSA(key) => key.to_json(),
        }
    }

    /// Returns the key type: `"EC"`, `"OKP"`, or `"RSA"`.
    pub fn kty(&self) -> &str {
        match self {
            Self::EC(_) => "EC",
            Self::OKP(_) => "OKP",
            Self::RSA(_) => "RSA",
        }
    }

    /// Returns the curve name. Present for EC and OKP keys; `None` for RSA.
    pub fn crv(&self) -> Option<&str> {
        match self {
            Self::EC(key) => Some(key.crv()),
            Self::OKP(key) => Some(key.crv()),
            Self::RSA(_) => None,
        }
    }

    /// Returns the x coordinate / public key value. Present for EC and OKP keys; `None` for RSA.
    pub fn x(&self) -> Option<&str> {
        match self {
            Self::EC(key) => Some(key.x()),
            Self::OKP(key) => Some(key.x()),
            Self::RSA(_) => None,
        }
    }

    /// Returns the y coordinate. Present for EC keys only.
    pub fn y(&self) -> Option<&str> {
        match self {
            Self::EC(key) => Some(key.y()),
            _ => None,
        }
    }

    /// Returns the RSA modulus. Present for RSA keys only.
    pub fn n(&self) -> Option<&str> {
        match self {
            Self::RSA(key) => Some(key.n()),
            _ => None,
        }
    }

    /// Returns the RSA public exponent. Present for RSA keys only.
    pub fn e(&self) -> Option<&str> {
        match self {
            Self::RSA(key) => Some(key.e()),
            _ => None,
        }
    }

    /// Returns the intended use of the key. Corresponds to the `use` field in RFC 7517 §4.2.
    pub fn use_(&self) -> Option<KeyUse> {
        match self {
            Self::EC(key) => key.use_(),
            Self::OKP(key) => key.use_(),
            Self::RSA(key) => key.use_(),
        }
    }

    /// Returns the permitted key operations (e.g. `"sign"`, `"verify"`, `"encrypt"`).
    /// Corresponds to the `key_ops` field in RFC 7517 §4.3.
    pub fn key_ops(&self) -> Option<&[String]> {
        match self {
            Self::EC(key) => key.key_ops(),
            Self::OKP(key) => key.key_ops(),
            Self::RSA(key) => key.key_ops(),
        }
    }

    /// Returns the intended algorithm for use with the key (e.g. `"EdDSA"`, `"ES256"`, `"RS256"`).
    /// Corresponds to the `alg` field in RFC 7517 §4.4.
    pub fn alg(&self) -> Option<&str> {
        match self {
            Self::EC(key) => key.alg(),
            Self::OKP(key) => key.alg(),
            Self::RSA(key) => key.alg(),
        }
    }

    /// Returns the key ID, which identifies a specific key within a key set.
    /// Corresponds to the `kid` field in RFC 7517 §4.5.
    pub fn kid(&self) -> Option<&str> {
        match self {
            Self::EC(key) => key.kid(),
            Self::OKP(key) => key.kid(),
            Self::RSA(key) => key.kid(),
        }
    }
}

/// Public key encoded as a multibase string. Only base58btc encoding (prefix `z`) is supported,
/// as used by `Ed25519VerificationKey2020` and similar suites in DID documents.
#[derive(Debug, Clone, PartialEq)]
pub struct PublicKeyMultibase {
    /// Raw decoded public key bytes.
    key: Vec<u8>,
}

impl PublicKeyMultibase {
    /// Creates a `PublicKeyMultibase` from raw key bytes. `key` must be the decoded key data
    /// without any multibase prefix.
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }

    /// Parses a multibase-encoded public key string. Only the `z` prefix (base58btc) is supported.
    pub fn try_from_string(s: &str) -> DIDDocResult<Self> {
        let mut chars = s.chars();
        match chars.next() {
            Some('z') => {}
            Some(c) => {
                return Err(DIDDocError::InvalidFormat(format!(
                    "unsupported multibase prefix '{c}'; only 'z' (base58btc) is supported"
                )));
            }
            None => return Err(DIDDocError::InvalidFormat("empty multibase string".into())),
        }
        let key = bs58::decode(chars.as_str())
            .into_vec()
            .map_err(|e| DIDDocError::InvalidFormat(format!("invalid base58btc encoding: {e}")))?;
        Ok(Self { key })
    }

    pub fn raw_key(&self) -> &[u8] {
        &self.key
    }
}

impl fmt::Display for PublicKeyMultibase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "z{}", bs58::encode(&self.key).into_string())
    }
}

/// Encodes a raw Ed25519 public key as a multikey string using base58btc encoding,
/// as specified in the [Multikey data integrity cryptosuite][multikey].
///
/// [multikey]: https://www.w3.org/TR/vc-di-eddsa/
///
/// # Example
///
/// ```
/// use swiyu_core::diddoc::public_keys::ed25519_verifying_key_to_multikey;
///
/// // In practice, key_bytes comes from Ed25519VerifyingKey::as_bytes().
/// let key_bytes: [u8; 32] = [
///     0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
///     0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
///     0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
///     0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
/// ];
/// let multikey = ed25519_verifying_key_to_multikey(&key_bytes);
/// assert_eq!(multikey, "z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw");
/// ```
pub fn ed25519_verifying_key_to_multikey(key_bytes: &[u8; 32]) -> String {
    const MULTICODEC_ED25519: [u8; 2] = [0xed, 0x01];
    let mut bytes = Vec::with_capacity(MULTICODEC_ED25519.len() + key_bytes.len());
    bytes.extend_from_slice(&MULTICODEC_ED25519);
    bytes.extend_from_slice(key_bytes);
    format!("z{}", bs58::encode(&bytes).into_string())
}

/// The public key material of a verification method.
#[derive(Debug, Clone, PartialEq)]
pub enum PublicKey {
    /// Public key in JWK format (RFC 7517). Must not contain private key material.
    Jwk(Box<PublicKeyJWK>),
    /// Public key as a base58btc multibase string (prefix `z`).
    Multibase(PublicKeyMultibase),
}

fn parse_key_use(obj: &Map<String, Value>) -> DIDDocResult<Option<KeyUse>> {
    match obj.get("use") {
        None => Ok(None),
        Some(v) => {
            let s = v
                .as_str()
                .ok_or_else(|| DIDDocError::InvalidFieldType("'use' must be a string".into()))?;
            Ok(Some(KeyUse::try_from_str(s)?))
        }
    }
}

fn insert_jwk_optional_fields(
    map: &mut Map<String, Value>,
    use_: &Option<KeyUse>,
    key_ops: &Option<Vec<String>>,
    alg: &Option<String>,
    kid: &Option<String>,
) {
    if let Some(v) = use_ {
        map.insert("use".into(), json!(v.to_string()));
    }
    if let Some(v) = key_ops {
        map.insert("key_ops".into(), json!(v));
    }
    if let Some(v) = alg {
        map.insert("alg".into(), json!(v));
    }
    if let Some(v) = kid {
        map.insert("kid".into(), json!(v));
    }
}

#[cfg(test)]
mod tests {
    use super::super::DIDDocError;
    use super::*;
    use serde_json::json;

    #[test]
    fn ed25519_multikey_encoding() {
        let key_bytes = [0x42u8; 32];
        let multikey = ed25519_verifying_key_to_multikey(&key_bytes);

        assert!(multikey.starts_with('z'));

        let decoded = bs58::decode(&multikey[1..]).into_vec().unwrap();
        assert_eq!(&decoded[..2], &[0xed, 0x01]);
        assert_eq!(&decoded[2..], &key_bytes);
    }

    #[test]
    fn multibase_unsupported_prefix() {
        assert!(matches!(
            PublicKeyMultibase::try_from_string("mSomeBase64"),
            Err(DIDDocError::InvalidFormat(_))
        ));
    }

    #[test]
    fn jwk_okp_roundtrip() {
        let v = json!({ "kty": "OKP", "crv": "Ed25519", "x": "abc123" });
        let jwk = PublicKeyJWK::try_from_json(&v).unwrap();
        assert_eq!(jwk.kty(), "OKP");
        assert_eq!(jwk.crv(), Some("Ed25519"));
        assert_eq!(jwk.x(), Some("abc123"));
        assert_eq!(jwk.y(), None);
        assert_eq!(jwk.n(), None);
        assert_eq!(jwk.to_json(), v);
    }

    #[test]
    fn jwk_ec_roundtrip() {
        let v = json!({ "kty": "EC", "crv": "P-256", "x": "xval", "y": "yval" });
        let jwk = PublicKeyJWK::try_from_json(&v).unwrap();
        assert_eq!(jwk.kty(), "EC");
        assert_eq!(jwk.crv(), Some("P-256"));
        assert_eq!(jwk.x(), Some("xval"));
        assert_eq!(jwk.y(), Some("yval"));
        assert_eq!(jwk.n(), None);
        assert_eq!(jwk.to_json(), v);
    }

    #[test]
    fn jwk_rsa_roundtrip() {
        let v = json!({ "kty": "RSA", "n": "modulus", "e": "AQAB" });
        let jwk = PublicKeyJWK::try_from_json(&v).unwrap();
        assert_eq!(jwk.kty(), "RSA");
        assert_eq!(jwk.n(), Some("modulus"));
        assert_eq!(jwk.e(), Some("AQAB"));
        assert_eq!(jwk.crv(), None);
        assert_eq!(jwk.to_json(), v);
    }

    #[test]
    fn jwk_unknown_kty() {
        let v = json!({ "kty": "oct", "k": "secret" });
        assert!(matches!(
            PublicKeyJWK::try_from_json(&v).unwrap_err(),
            DIDDocError::InvalidFormat(_)
        ));
    }

    #[test]
    fn ec_key_direct_access() {
        let v = json!({ "kty": "EC", "crv": "P-256", "x": "xval", "y": "yval" });
        let PublicKeyJWK::EC(key) = PublicKeyJWK::try_from_json(&v).unwrap() else {
            panic!("expected EC");
        };
        assert_eq!(key.crv(), "P-256");
        assert_eq!(key.x(), "xval");
        assert_eq!(key.y(), "yval");
    }

    #[test]
    fn okp_key_direct_access() {
        let v = json!({ "kty": "OKP", "crv": "Ed25519", "x": "abc123" });
        let PublicKeyJWK::OKP(key) = PublicKeyJWK::try_from_json(&v).unwrap() else {
            panic!("expected OKP");
        };
        assert_eq!(key.crv(), "Ed25519");
        assert_eq!(key.x(), "abc123");
    }

    #[test]
    fn rsa_key_direct_access() {
        let v = json!({ "kty": "RSA", "n": "modulus", "e": "AQAB" });
        let PublicKeyJWK::RSA(key) = PublicKeyJWK::try_from_json(&v).unwrap() else {
            panic!("expected RSA");
        };
        assert_eq!(key.n(), "modulus");
        assert_eq!(key.e(), "AQAB");
    }
}
