//! SD-JWT selective-disclosure primitive: the `[salt, name, value]` disclosure.

use std::fmt;
use std::str::FromStr;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// A single SD-JWT object-property disclosure: the `[salt, name, value]` triple
/// for one selectively-disclosable claim.
///
/// The base64url encoding is captured once at construction and never recomputed,
/// so [`digest`][Self::digest] always hashes the exact bytes the disclosure was
/// built from or parsed out of. This matters on the read side: SD-JWT verifiers
/// must hash the disclosure *as received*, because a re-serialisation could differ
/// from the issuer's bytes (member ordering, whitespace, number formatting) and so
/// fail to match the digest in `_sd`.
#[derive(Debug, Clone)]
pub struct Disclosure {
    salt: String,
    name: String,
    value: Value,
    /// base64url(`[salt, name, value]`) — the exact wire bytes. Kept so
    /// [`digest`][Self::digest] hashes what was produced or received, never a
    /// re-encoding.
    encoded: String,
}

impl Disclosure {
    /// Builds a disclosure for one claim, encoding `[salt, name, value]` once.
    ///
    /// The caller supplies the salt; it should be a fresh, high-entropy,
    /// base64url-encoded value from a CSPRNG. Salt generation lives with the
    /// caller so this crate need not depend on a random-number source.
    pub fn new(salt: impl Into<String>, name: impl Into<String>, value: Value) -> Self {
        let salt = salt.into();
        let name = name.into();
        let array = Value::Array(vec![
            Value::String(salt.clone()),
            Value::String(name.clone()),
            value.clone(),
        ]);
        // Serialising a JSON array of two strings and an arbitrary `Value`
        // cannot fail: `serde_json::to_vec` only errors on Serialize impls that
        // return an error or maps with non-string keys, neither of which a
        // `Value` produces.
        let json = serde_json::to_vec(&array).expect("serialising a JSON array never fails");
        let encoded = URL_SAFE_NO_PAD.encode(json);
        Self {
            salt,
            name,
            value,
            encoded,
        }
    }

    pub fn salt(&self) -> &str {
        &self.salt
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn value(&self) -> &Value {
        &self.value
    }

    /// The digest the issuer lists in the JWT's `_sd` array to commit to this
    /// disclosure without revealing it.
    pub fn digest(&self) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(self.encoded.as_bytes()))
    }
}

/// Renders the disclosure as its base64url wire form — the segment that follows
/// the JWS, between `~` separators.
impl fmt::Display for Disclosure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.encoded)
    }
}

impl FromStr for Disclosure {
    type Err = DisclosureError;

    fn from_str(encoded: &str) -> Result<Self, Self::Err> {
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|e| DisclosureError::Base64(e.to_string()))?;
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|e| DisclosureError::Json(e.to_string()))?;
        let array = match value {
            Value::Array(array) => array,
            _ => return Err(DisclosureError::NotArray),
        };
        let [salt, name, value] = <[Value; 3]>::try_from(array)
            .map_err(|array| DisclosureError::WrongLength { got: array.len() })?;
        let salt = salt
            .as_str()
            .ok_or(DisclosureError::SaltNotString)?
            .to_string();
        let name = name
            .as_str()
            .ok_or(DisclosureError::NameNotString)?
            .to_string();
        Ok(Self {
            salt,
            name,
            value,
            encoded: encoded.to_string(),
        })
    }
}

#[derive(Debug)]
pub enum DisclosureError {
    /// The disclosure segment is not valid base64url.
    Base64(String),
    /// The decoded bytes are not valid JSON.
    Json(String),
    /// The disclosure decoded as JSON but is not an array.
    NotArray,
    /// The array does not have the three elements of an object-property
    /// disclosure. A two-element array-element disclosure lands here too.
    WrongLength { got: usize },
    /// The first array element (the salt) is not a string.
    SaltNotString,
    /// The second array element (the claim name) is not a string.
    NameNotString,
}

impl fmt::Display for DisclosureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Base64(reason) => write!(f, "disclosure is not base64url: {reason}"),
            Self::Json(reason) => write!(f, "disclosure is not JSON: {reason}"),
            Self::NotArray => write!(f, "disclosure is not a JSON array"),
            Self::WrongLength { got } => {
                write!(f, "disclosure must have 3 elements, got {got}")
            }
            Self::SaltNotString => write!(f, "disclosure salt is not a string"),
            Self::NameNotString => write!(f, "disclosure claim name is not a string"),
        }
    }
}

impl std::error::Error for DisclosureError {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn new_encodes_known_vector() {
        // Fixed salt + name + value lock the byte-level wire contract: JSON
        // array shape, base64url alphabet, no padding.
        let disclosure = Disclosure::new("MTIzNDU2Nzg5MGFiY2RlZg", "given_name", json!("Alice"));

        let expected_encoded =
            URL_SAFE_NO_PAD.encode(br#"["MTIzNDU2Nzg5MGFiY2RlZg","given_name","Alice"]"#);
        assert_eq!(disclosure.to_string(), expected_encoded);

        let expected_digest = URL_SAFE_NO_PAD.encode(Sha256::digest(expected_encoded.as_bytes()));
        assert_eq!(disclosure.digest(), expected_digest);
    }

    #[test]
    fn from_str_round_trips_a_built_disclosure() {
        let built = Disclosure::new("salt-1", "age", json!(30));
        let parsed: Disclosure = built.to_string().parse().unwrap();
        assert_eq!(parsed.salt(), "salt-1");
        assert_eq!(parsed.name(), "age");
        assert_eq!(parsed.value(), &json!(30));
        assert_eq!(parsed.digest(), built.digest());
    }

    #[test]
    fn object_valued_claim_is_carried_whole() {
        let address = json!({"street": "Bahnhofstrasse 1", "city": "Zürich"});
        let disclosure = Disclosure::new("salt-2", "address", address.clone());
        let parsed: Disclosure = disclosure.to_string().parse().unwrap();
        assert_eq!(parsed.value(), &address);
    }

    #[test]
    fn digest_hashes_received_bytes_not_a_reencoding() {
        // A disclosure that arrives with non-canonical whitespace must hash to
        // its received bytes, not to a re-serialisation. Parsing then re-encoding
        // would drop the spaces and produce a digest that no longer matches `_sd`.
        let raw = r#"[ "salt-3" , "n" , 1 ]"#;
        let encoded = URL_SAFE_NO_PAD.encode(raw.as_bytes());

        let parsed: Disclosure = encoded.parse().unwrap();
        assert_eq!(parsed.salt(), "salt-3");
        assert_eq!(parsed.name(), "n");
        assert_eq!(parsed.value(), &json!(1));

        let expected_digest = URL_SAFE_NO_PAD.encode(Sha256::digest(encoded.as_bytes()));
        assert_eq!(parsed.digest(), expected_digest);
        assert_eq!(parsed.to_string(), encoded);
    }

    #[test]
    fn from_str_rejects_non_base64url() {
        assert!(matches!(
            Disclosure::from_str("not valid base64!"),
            Err(DisclosureError::Base64(_))
        ));
    }

    #[test]
    fn from_str_rejects_non_json() {
        let encoded = URL_SAFE_NO_PAD.encode(b"not json");
        assert!(matches!(
            Disclosure::from_str(&encoded),
            Err(DisclosureError::Json(_))
        ));
    }

    #[test]
    fn from_str_rejects_non_array() {
        let encoded = URL_SAFE_NO_PAD.encode(br#"{"salt":"s"}"#);
        assert!(matches!(
            Disclosure::from_str(&encoded),
            Err(DisclosureError::NotArray)
        ));
    }

    #[test]
    fn from_str_rejects_array_element_form() {
        // Two-element array-element disclosure `[salt, value]` is out of profile.
        let encoded = URL_SAFE_NO_PAD.encode(br#"["salt","value"]"#);
        assert!(matches!(
            Disclosure::from_str(&encoded),
            Err(DisclosureError::WrongLength { got: 2 })
        ));
    }

    #[test]
    fn from_str_rejects_non_string_salt() {
        let encoded = URL_SAFE_NO_PAD.encode(br#"[1,"name","value"]"#);
        assert!(matches!(
            Disclosure::from_str(&encoded),
            Err(DisclosureError::SaltNotString)
        ));
    }

    #[test]
    fn from_str_rejects_non_string_name() {
        let encoded = URL_SAFE_NO_PAD.encode(br#"["salt",2,"value"]"#);
        assert!(matches!(
            Disclosure::from_str(&encoded),
            Err(DisclosureError::NameNotString)
        ));
    }
}
