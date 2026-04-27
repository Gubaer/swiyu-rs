//! SCID (Self-Certifying Identifier) parsing and representation for the did:tdw DID method.
//!
//! A SCID is a base58btc-encoded multihash derived from the DID's inception log entry. It appears
//! as the first path component of a `did:tdw` DID and binds the DID to its initial state.

use multihash::Multihash;
use std::fmt;

pub type SCIDResult<T> = Result<T, SCIDError>;

#[derive(Debug, PartialEq)]
pub enum SCIDError {
    InvalidEncoding(String),
    InvalidMultihash(String),
}

impl fmt::Display for SCIDError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SCIDError::InvalidEncoding(msg) => write!(f, "invalid base58 encoding: {msg}"),
            SCIDError::InvalidMultihash(msg) => write!(f, "invalid multihash: {msg}"),
        }
    }
}

impl std::error::Error for SCIDError {}

/// A SCID (Self-Certifying Identifier) — a base58btc-encoded multihash derived from a DID's
/// inception entry.
#[derive(Debug, Clone, PartialEq)]
pub struct SCID {
    /// Multihash codec code identifying the hash algorithm (e.g. 0x12 = SHA2-256).
    code: u64,
    /// Digest length in bytes as declared in the multihash header.
    size: u8,
    /// Raw digest bytes.
    digest: Vec<u8>,
}

impl SCID {
    /// Parses a SCID from its base58btc-encoded multihash string representation.
    ///
    /// Returns `SCIDError::InvalidEncoding` if the string is not valid base58btc, or
    /// `SCIDError::InvalidMultihash` if the decoded bytes are not a valid multihash.
    ///
    /// # Example
    ///
    /// ```
    /// use swiyu_core::didlog::scid::SCID;
    /// use multihash_codetable::{Code, MultihashDigest};
    ///
    /// let mh = Code::Sha2_256.digest(b"inception entry data");
    /// let encoded = bs58::encode(mh.to_bytes()).into_string();
    ///
    /// let scid = SCID::try_from_string(&encoded).unwrap();
    /// assert_eq!(scid.hash_algorithm(), 0x12); // SHA2-256
    /// assert_eq!(scid.hash_length(), 32);
    /// assert_eq!(scid.to_string(), encoded);
    /// ```
    pub fn try_from_string(s: &str) -> SCIDResult<Self> {
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|e| SCIDError::InvalidEncoding(e.to_string()))?;

        let mh = Multihash::<64>::from_bytes(&bytes)
            .map_err(|e| SCIDError::InvalidMultihash(e.to_string()))?;

        Ok(Self {
            code: mh.code(),
            size: mh.size(),
            digest: mh.digest().to_vec(),
        })
    }

    /// The multihash codec code identifying the hash algorithm (e.g. 0x12 = SHA2-256).
    /// The full list of codec codes is at <https://github.com/multiformats/multicodec/blob/master/table.csv>.
    pub fn hash_algorithm(&self) -> u64 {
        self.code
    }

    /// The length of the digest in bytes.
    pub fn hash_length(&self) -> usize {
        self.size as usize
    }

    /// The raw digest bytes.
    pub fn raw_hash(&self) -> &[u8] {
        &self.digest
    }
}

impl fmt::Display for SCID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // safe: digest was validated at construction time
        let mh = Multihash::<64>::wrap(self.code, &self.digest)
            .expect("digest was validated at construction");
        write!(f, "{}", bs58::encode(mh.to_bytes()).into_string())
    }
}

impl TryFrom<String> for SCID {
    type Error = SCIDError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        SCID::try_from_string(&s)
    }
}

impl TryFrom<&str> for SCID {
    type Error = SCIDError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        SCID::try_from_string(s)
    }
}

/// Derives the SCID from the genesis log entry.
///
/// `entry_json` is the compact JSON serialisation of the genesis log entry with `{SCID}` used
/// as a placeholder wherever the SCID would normally appear. The SCID is the base58btc-encoded
/// SHA-256 multihash of those bytes, as specified in the did:tdw / did:webvh log format.
pub fn derive_from_genesis_entry(entry_json: &str) -> String {
    use multihash_codetable::{Code, MultihashDigest};
    let mh = Code::Sha2_256.digest(entry_json.as_bytes());
    bs58::encode(mh.to_bytes()).into_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use multihash_codetable::{Code, MultihashDigest};

    fn sample_scid_string() -> String {
        let mh = Code::Sha2_256.digest(b"inception entry data");
        bs58::encode(mh.to_bytes()).into_string()
    }

    #[test]
    fn parse_valid_scid() {
        let s = sample_scid_string();
        let scid = SCID::try_from_string(&s).unwrap();
        assert_eq!(scid.hash_algorithm(), 0x12); // SHA2-256
        assert_eq!(scid.hash_length(), 32);
        assert_eq!(scid.raw_hash().len(), 32);
    }

    #[test]
    fn to_string_roundtrip() {
        let s = sample_scid_string();
        let scid = SCID::try_from_string(&s).unwrap();
        assert_eq!(scid.to_string(), s);
    }

    #[test]
    fn try_from_string_type() {
        let s: SCID = sample_scid_string().try_into().unwrap();
        assert_eq!(s.hash_length(), 32);
    }

    #[test]
    fn try_from_str_type() {
        let s = sample_scid_string();
        let scid: SCID = s.as_str().try_into().unwrap();
        assert_eq!(scid.hash_length(), 32);
    }

    #[test]
    fn derive_from_genesis_entry_produces_valid_scid() {
        let entry_json = r#"["1-{SCID}","2024-01-01T00:00:00Z",{"method":"did:webvh:1.0","scid":"{SCID}"},{"value":{"id":"did:webvh:{SCID}:example.com"}},{}]"#;
        let scid_str = derive_from_genesis_entry(entry_json);
        let scid = SCID::try_from_string(&scid_str)
            .expect("derive_from_genesis_entry must produce a valid SCID");
        assert_eq!(scid.hash_algorithm(), 0x12); // SHA2-256
        assert_eq!(scid.hash_length(), 32);
    }

    #[test]
    fn derive_from_genesis_entry_is_deterministic() {
        let entry_json = r#"["1-{SCID}","2024-01-01T00:00:00Z",{}]"#;
        assert_eq!(
            derive_from_genesis_entry(entry_json),
            derive_from_genesis_entry(entry_json),
        );
    }

    #[test]
    fn derive_from_genesis_entry_is_sensitive_to_input() {
        let a = derive_from_genesis_entry(r#"["1-{SCID}","2024-01-01T00:00:00Z"]"#);
        let b = derive_from_genesis_entry(r#"["1-{SCID}","2024-01-02T00:00:00Z"]"#);
        assert_ne!(a, b);
    }

    #[test]
    fn invalid_base58() {
        assert!(matches!(
            SCID::try_from_string("not$valid$base58"),
            Err(SCIDError::InvalidEncoding(_))
        ));
    }

    #[test]
    fn invalid_multihash() {
        // Valid base58 but not a valid multihash.
        let s = bs58::encode(b"not a multihash").into_string();
        assert!(matches!(
            SCID::try_from_string(&s),
            Err(SCIDError::InvalidMultihash(_))
        ));
    }
}
