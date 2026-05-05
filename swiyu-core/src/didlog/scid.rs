//! SCID (Self-Certifying Identifier) parsing and representation for the did:tdw DID method.
//!
//! A SCID is a base58btc-encoded multihash derived from the DID's inception log entry. It appears
//! as the first path component of a `did:tdw` DID and binds the DID to its initial state.

use multihash::Multihash;
use serde_json::Value;
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
/// let scid = SCID::try_from(encoded.as_str()).unwrap();
/// assert_eq!(scid.hash_algorithm(), 0x12); // SHA2-256
/// assert_eq!(scid.hash_length(), 32);
/// assert_eq!(scid.to_string(), encoded);
/// ```
impl TryFrom<&str> for SCID {
    type Error = SCIDError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
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
}

impl TryFrom<String> for SCID {
    type Error = SCIDError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::try_from(s.as_str())
    }
}

/// Derives the SCID from the preliminary genesis log entry, per the did:tdw 0.3 spec.
///
/// The caller must construct `preliminary_entry` as a 4-element JSON array (the proof slot
/// is excluded — *not* an empty array) where:
/// - element 0 (`versionId`) is the literal placeholder `"{SCID}"`,
/// - every other position that will hold the SCID (the `scid` parameter, the DID `id`,
///   `controller`, verification-method `id`s, ...) is also `"{SCID}"`.
///
/// The function JCS-canonicalises the entry and returns
/// `base58btc(multihash(SHA-256(jcs)))`.
pub fn derive_scid(preliminary_entry: &Value) -> String {
    hash_log_entry(preliminary_entry)
}

/// Derives the entryHash from a fully-resolved log entry, per the did:tdw 0.3 spec.
///
/// The caller must construct `entry` as a 4-element JSON array (proof slot excluded) where:
/// - the actual SCID value has been substituted into every SCID position,
/// - element 0 (`versionId`) is the previous entry's `versionId`, or — for the genesis
///   entry — the bare SCID with **no** `"1-"` prefix.
///
/// The function JCS-canonicalises the entry and returns
/// `base58btc(multihash(SHA-256(jcs)))`. Callers compose the final on-disk versionId as
/// `"<n>-<entryHash>"`.
pub fn derive_entry_hash(entry: &Value) -> String {
    hash_log_entry(entry)
}

fn hash_log_entry(value: &Value) -> String {
    use multihash_codetable::{Code, MultihashDigest};
    let jcs = serde_jcs::to_vec(value).expect("JSON value is serialisable to JCS");
    let mh = Code::Sha2_256.digest(&jcs);
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
        let scid = SCID::try_from(s.as_str()).unwrap();
        assert_eq!(scid.hash_algorithm(), 0x12); // SHA2-256
        assert_eq!(scid.hash_length(), 32);
        assert_eq!(scid.raw_hash().len(), 32);
    }

    #[test]
    fn to_string_roundtrip() {
        let s = sample_scid_string();
        let scid = SCID::try_from(s.as_str()).unwrap();
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
    fn invalid_base58() {
        assert!(matches!(
            SCID::try_from("not$valid$base58"),
            Err(SCIDError::InvalidEncoding(_))
        ));
    }

    #[test]
    fn invalid_multihash() {
        // Valid base58 but not a valid multihash.
        let s = bs58::encode(b"not a multihash").into_string();
        assert!(matches!(
            SCID::try_from(s.as_str()),
            Err(SCIDError::InvalidMultihash(_))
        ));
    }

    // Known-good genesis entry from the SWIYU integration environment. Used as a
    // ground-truth vector for both the SCID derivation and the entryHash derivation.
    fn known_good_entry() -> serde_json::Value {
        serde_json::from_str(KNOWN_GOOD_ENTRY).expect("fixture parses")
    }

    const KNOWN_GOOD_SCID: &str = "QmPAazvipE6c5RgGhR5moLsrerxhbd1r6nm8kwryo9eATk";
    const KNOWN_GOOD_ENTRY_HASH: &str = "QmRHBgSjdFzLJUW4gDV4M1tpwDje8YZRkRdgrxN7DrUAE3";

    const KNOWN_GOOD_ENTRY: &str = r#"[
        "1-QmRHBgSjdFzLJUW4gDV4M1tpwDje8YZRkRdgrxN7DrUAE3",
        "2026-04-18T19:02:30Z",
        {
            "method": "did:tdw:0.3",
            "scid": "QmPAazvipE6c5RgGhR5moLsrerxhbd1r6nm8kwryo9eATk",
            "updateKeys": ["z6MkfdyZFfvG2EJFHLstDfo4RfT8CRF7G5qgfpzh2vLNhrYW"],
            "portable": false
        },
        {
            "value": {
                "@context": [
                    "https://www.w3.org/ns/did/v1",
                    "https://w3id.org/security/jwk/v1"
                ],
                "id": "did:tdw:QmPAazvipE6c5RgGhR5moLsrerxhbd1r6nm8kwryo9eATk:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:fce949f2-32c4-4915-8b60-0ee2f705231d",
                "authentication": [
                    "did:tdw:QmPAazvipE6c5RgGhR5moLsrerxhbd1r6nm8kwryo9eATk:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:fce949f2-32c4-4915-8b60-0ee2f705231d#auth-key-01"
                ],
                "assertionMethod": [
                    "did:tdw:QmPAazvipE6c5RgGhR5moLsrerxhbd1r6nm8kwryo9eATk:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:fce949f2-32c4-4915-8b60-0ee2f705231d#assert-key-01"
                ],
                "verificationMethod": [
                    {
                        "id": "did:tdw:QmPAazvipE6c5RgGhR5moLsrerxhbd1r6nm8kwryo9eATk:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:fce949f2-32c4-4915-8b60-0ee2f705231d#auth-key-01",
                        "controller": "did:tdw:QmPAazvipE6c5RgGhR5moLsrerxhbd1r6nm8kwryo9eATk:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:fce949f2-32c4-4915-8b60-0ee2f705231d",
                        "type": "JsonWebKey2020",
                        "publicKeyJwk": {
                            "kty": "EC",
                            "crv": "P-256",
                            "x": "aFlS4IeLCTjb_7nNkVIe6eLbb82zdJvMUz8f-IQGfA4",
                            "y": "FPg_NxIzeRSB-sTgBPwdHCg-rEQeeb-dU1jaM9LFyD0",
                            "kid": "auth-key-01"
                        }
                    },
                    {
                        "id": "did:tdw:QmPAazvipE6c5RgGhR5moLsrerxhbd1r6nm8kwryo9eATk:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:fce949f2-32c4-4915-8b60-0ee2f705231d#assert-key-01",
                        "controller": "did:tdw:QmPAazvipE6c5RgGhR5moLsrerxhbd1r6nm8kwryo9eATk:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:fce949f2-32c4-4915-8b60-0ee2f705231d",
                        "type": "JsonWebKey2020",
                        "publicKeyJwk": {
                            "kty": "EC",
                            "crv": "P-256",
                            "x": "5pIKL3uUSpOFBsSAYTgKcI6A0l3O2F3Tus_EdwKRsl4",
                            "y": "3yipUf6qCxa5D366IEUPrMpLsjqMU09jeXr8UKDCAMU",
                            "kid": "assert-key-01"
                        }
                    }
                ]
            }
        },
        []
    ]"#;

    #[test]
    fn derive_scid_matches_known_good_vector() {
        // Build the preliminary entry: 4-element array (proof slot excluded);
        // versionId = "{SCID}"; every SCID instance replaced with the placeholder.
        let serialised = serde_json::to_string(&known_good_entry()).unwrap();
        let with_placeholders = serialised.replace(KNOWN_GOOD_SCID, "{SCID}");
        let mut prelim: Value = serde_json::from_str(&with_placeholders).unwrap();
        let arr = prelim.as_array_mut().unwrap();
        arr.pop(); // drop the proof slot
        arr[0] = serde_json::json!("{SCID}"); // versionId placeholder

        assert_eq!(derive_scid(&prelim), KNOWN_GOOD_SCID);
    }

    #[test]
    fn derive_entry_hash_matches_known_good_vector() {
        // Build the entryHash input: 4-element array; SCID is the actual value;
        // versionId is the bare SCID (no "1-" prefix), per the genesis rule.
        let mut input = known_good_entry();
        let arr = input.as_array_mut().unwrap();
        arr.pop(); // drop the proof slot
        arr[0] = serde_json::json!(KNOWN_GOOD_SCID);

        assert_eq!(derive_entry_hash(&input), KNOWN_GOOD_ENTRY_HASH);
    }
}
