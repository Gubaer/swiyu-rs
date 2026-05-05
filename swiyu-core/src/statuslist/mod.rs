//! Status-list types and decoding for the SD-JWT VC status mechanism used by
//! SWIYU (`SwissTokenStatusList-1.0`, layered on the IETF Token Status List
//! draft).
//!
//! Two distinct concepts:
//!
//! - [`StatusListPointer`] — the small object embedded at `payload.status.status_list`
//!   of an SD-JWT VC. Tells a verifier *where* to fetch the list and *which slot* in
//!   it represents the credential.
//! - [`StatusList`] — the decoded, decompressed bitstring carried by the status-list
//!   JWT itself. Constructed from the JWT's `payload.status_list` object via
//!   [`StatusList::from_payload`]; queried with [`StatusList::value_at`].
//!
//! This module is intentionally I/O-free. Fetching the JWT and verifying its
//! signature live in the consuming application; this module only handles the
//! wire-format decode and the slot-value semantics.

use std::fmt;
use std::io::Read;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use flate2::read::ZlibDecoder;
use serde_json::Value;

#[derive(Debug, PartialEq)]
pub enum StatusListError {
    /// `payload.status_list` is missing or not an object.
    MissingStatusList,
    /// A required field is missing from the payload.
    MissingField(&'static str),
    /// A field has the wrong JSON type.
    InvalidFieldType(&'static str),
    /// `bits` is something other than `1` or `2`.
    UnsupportedBits(u8),
    /// `lst` is not valid base64url.
    InvalidBase64,
    /// zlib decompression of `lst` failed.
    Decompress(String),
    /// Slot index lies past the end of the bitstring.
    IdxOutOfRange { idx: u64, slots: u64 },
}

impl fmt::Display for StatusListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingStatusList => write!(f, "missing 'status_list' in payload"),
            Self::MissingField(name) => write!(f, "missing '{name}' in status_list"),
            Self::InvalidFieldType(name) => {
                write!(f, "field '{name}' has the wrong type in status_list")
            }
            Self::UnsupportedBits(b) => {
                write!(f, "unsupported 'bits' value {b} (expected 1 or 2)")
            }
            Self::InvalidBase64 => write!(f, "'lst' is not valid base64url"),
            Self::Decompress(msg) => write!(f, "decompressing 'lst' failed: {msg}"),
            Self::IdxOutOfRange { idx, slots } => {
                write!(f, "idx {idx} exceeds bitstring length ({slots} slots)")
            }
        }
    }
}

impl std::error::Error for StatusListError {}

/// Pointer at `payload.status.status_list` of an SD-JWT VC, identifying the
/// status list to consult and the slot within it.
#[derive(Debug, Clone, PartialEq)]
pub struct StatusListPointer {
    /// Issuer-supplied type tag, e.g. `"SwissTokenStatusList-1.0"`. Stored
    /// verbatim; not interpreted by this crate (slot-width interpretation comes
    /// from the fetched list's `bits` field, not this tag).
    type_: String,
    /// 0-based index of this credential's slot in the bitstring.
    idx: u64,
    /// HTTPS URL where the status-list JWT is served.
    uri: String,
}

impl StatusListPointer {
    pub fn new(type_: String, idx: u64, uri: String) -> Self {
        Self { type_, idx, uri }
    }

    pub fn type_(&self) -> &str {
        &self.type_
    }

    pub fn idx(&self) -> u64 {
        self.idx
    }

    pub fn uri(&self) -> &str {
        &self.uri
    }
}

/// Parses the `status_list` object embedded inside an SD-JWT VC's
/// `payload.status` claim. Expects `type`, `idx`, `uri` fields.
impl TryFrom<&Value> for StatusListPointer {
    type Error = StatusListError;

    fn try_from(v: &Value) -> Result<Self, Self::Error> {
        let obj = v
            .as_object()
            .ok_or(StatusListError::InvalidFieldType("status_list"))?;
        let type_ = obj
            .get("type")
            .ok_or(StatusListError::MissingField("type"))?
            .as_str()
            .ok_or(StatusListError::InvalidFieldType("type"))?
            .to_string();
        let idx = obj
            .get("idx")
            .ok_or(StatusListError::MissingField("idx"))?
            .as_u64()
            .ok_or(StatusListError::InvalidFieldType("idx"))?;
        let uri = obj
            .get("uri")
            .ok_or(StatusListError::MissingField("uri"))?
            .as_str()
            .ok_or(StatusListError::InvalidFieldType("uri"))?
            .to_string();
        Ok(Self { type_, idx, uri })
    }
}

/// Semantic interpretation of a status-list slot value.
///
/// For 2-bit lists (the SWIYU default) the four codepoints are `Valid` (0),
/// `Revoked` (1), `Suspended` (2), and `Reserved` (3). For 1-bit lists only
/// `Valid` (0) and `Revoked` (1) appear.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusValue {
    Valid,
    Revoked,
    Suspended,
    /// Any non-{0,1,2} value. Carries the raw bit pattern for diagnostics.
    Reserved(u8),
}

impl StatusValue {
    /// Translates the raw bit-pattern into the semantic enum. Width must be the
    /// list's `bits` value so that 1-bit lists never produce `Suspended`.
    fn from_raw(raw: u8, bits: u8) -> Self {
        match (bits, raw) {
            (_, 0) => Self::Valid,
            (_, 1) => Self::Revoked,
            (2, 2) => Self::Suspended,
            _ => Self::Reserved(raw),
        }
    }

    /// Returns true iff the credential is currently considered valid by the
    /// issuer of the status list.
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }
}

/// A decoded status list: the decompressed bitstring plus the slot width.
///
/// Constructed from a status-list JWT's `payload.status_list` via
/// [`StatusList::from_payload`]. Read individual slots with
/// [`StatusList::value_at`].
#[derive(Debug, Clone)]
pub struct StatusList {
    bits: u8,
    bytes: Vec<u8>,
}

impl StatusList {
    pub fn bits(&self) -> u8 {
        self.bits
    }

    /// Total number of slots the bitstring can represent. For a 2-bit list of
    /// 25,000 bytes this returns 100,000.
    pub fn len(&self) -> u64 {
        let slots_per_byte = (8 / self.bits) as u64;
        self.bytes.len() as u64 * slots_per_byte
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Reads the slot at `idx`. Errors with [`StatusListError::IdxOutOfRange`]
    /// if `idx` lies past the end of the bitstring.
    pub fn value_at(&self, idx: u64) -> Result<StatusValue, StatusListError> {
        let raw = match self.bits {
            1 => {
                let byte_idx = (idx / 8) as usize;
                let bit_idx = (idx % 8) as u8;
                let byte = self
                    .bytes
                    .get(byte_idx)
                    .ok_or(StatusListError::IdxOutOfRange {
                        idx,
                        slots: self.len(),
                    })?;
                (byte >> bit_idx) & 1
            }
            2 => {
                let byte_idx = (idx / 4) as usize;
                let shift = ((idx % 4) * 2) as u8;
                let byte = self
                    .bytes
                    .get(byte_idx)
                    .ok_or(StatusListError::IdxOutOfRange {
                        idx,
                        slots: self.len(),
                    })?;
                (byte >> shift) & 0b11
            }
            other => return Err(StatusListError::UnsupportedBits(other)),
        };
        Ok(StatusValue::from_raw(raw, self.bits))
    }

    /// Parses the status-list JWT's `payload.status_list` object: reads `bits`
    /// (default `1` per the IETF draft), base64url-decodes `lst`, and zlib-
    /// decompresses to obtain the raw bitstring.
    pub fn from_payload(payload: &Value) -> Result<Self, StatusListError> {
        let sl = payload
            .get("status_list")
            .ok_or(StatusListError::MissingStatusList)?;
        let obj = sl
            .as_object()
            .ok_or(StatusListError::InvalidFieldType("status_list"))?;
        let bits = obj.get("bits").map_or(Ok(1u8), |v| {
            v.as_u64()
                .and_then(|n| u8::try_from(n).ok())
                .ok_or(StatusListError::InvalidFieldType("bits"))
        })?;
        if bits != 1 && bits != 2 {
            return Err(StatusListError::UnsupportedBits(bits));
        }
        let lst = obj
            .get("lst")
            .ok_or(StatusListError::MissingField("lst"))?
            .as_str()
            .ok_or(StatusListError::InvalidFieldType("lst"))?;
        let compressed = URL_SAFE_NO_PAD
            .decode(lst)
            .map_err(|_| StatusListError::InvalidBase64)?;
        let mut bytes = Vec::new();
        ZlibDecoder::new(&compressed[..])
            .read_to_end(&mut bytes)
            .map_err(|e| StatusListError::Decompress(e.to_string()))?;
        Ok(Self { bits, bytes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use serde_json::json;
    use std::io::Write;

    fn encode_lst(bytes: &[u8]) -> String {
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(bytes).unwrap();
        let compressed = enc.finish().unwrap();
        URL_SAFE_NO_PAD.encode(compressed)
    }

    fn payload_with(bits: Option<u8>, bytes: &[u8]) -> Value {
        let mut sl = serde_json::Map::new();
        if let Some(b) = bits {
            sl.insert("bits".into(), json!(b));
        }
        sl.insert("lst".into(), json!(encode_lst(bytes)));
        json!({ "status_list": sl })
    }

    #[test]
    fn from_payload_two_bit() {
        // 0x55 = 0b01_01_01_01 → slots 0..3 read as 1 (revoked).
        let payload = payload_with(Some(2), &[0x55]);
        let list = StatusList::from_payload(&payload).unwrap();
        assert_eq!(list.bits(), 2);
        assert_eq!(list.len(), 4);
        assert_eq!(list.value_at(0).unwrap(), StatusValue::Revoked);
        assert_eq!(list.value_at(3).unwrap(), StatusValue::Revoked);
    }

    #[test]
    fn from_payload_one_bit_default() {
        // No 'bits' field → defaults to 1.
        let payload = payload_with(None, &[0b00010000]);
        let list = StatusList::from_payload(&payload).unwrap();
        assert_eq!(list.bits(), 1);
        assert_eq!(list.value_at(0).unwrap(), StatusValue::Valid);
        assert_eq!(list.value_at(4).unwrap(), StatusValue::Revoked);
    }

    #[test]
    fn value_at_two_bit_codepoints() {
        // 0b11_10_01_00 → slots: 0=Valid, 1=Revoked, 2=Suspended, 3=Reserved(3)
        let payload = payload_with(Some(2), &[0b11_10_01_00]);
        let list = StatusList::from_payload(&payload).unwrap();
        assert_eq!(list.value_at(0).unwrap(), StatusValue::Valid);
        assert_eq!(list.value_at(1).unwrap(), StatusValue::Revoked);
        assert_eq!(list.value_at(2).unwrap(), StatusValue::Suspended);
        assert_eq!(list.value_at(3).unwrap(), StatusValue::Reserved(3));
    }

    #[test]
    fn value_at_idx_out_of_range() {
        let payload = payload_with(Some(2), &[0x00]);
        let list = StatusList::from_payload(&payload).unwrap();
        let err = list.value_at(10).unwrap_err();
        assert!(matches!(
            err,
            StatusListError::IdxOutOfRange { idx: 10, slots: 4 }
        ));
    }

    #[test]
    fn unsupported_bits_rejected() {
        let payload = payload_with(Some(4), &[0]);
        assert_eq!(
            StatusList::from_payload(&payload).unwrap_err(),
            StatusListError::UnsupportedBits(4)
        );
    }

    #[test]
    fn missing_status_list() {
        let payload = json!({});
        assert_eq!(
            StatusList::from_payload(&payload).unwrap_err(),
            StatusListError::MissingStatusList
        );
    }

    #[test]
    fn missing_lst() {
        let payload = json!({ "status_list": { "bits": 2 } });
        assert_eq!(
            StatusList::from_payload(&payload).unwrap_err(),
            StatusListError::MissingField("lst")
        );
    }

    #[test]
    fn invalid_base64_lst() {
        let payload = json!({ "status_list": { "bits": 2, "lst": "!!!not-base64!!!" } });
        assert_eq!(
            StatusList::from_payload(&payload).unwrap_err(),
            StatusListError::InvalidBase64
        );
    }

    #[test]
    fn invalid_zlib_data() {
        // Valid base64url but the bytes aren't a zlib stream.
        let bad = URL_SAFE_NO_PAD.encode(b"not-zlib-data");
        let payload = json!({ "status_list": { "bits": 2, "lst": bad } });
        assert!(matches!(
            StatusList::from_payload(&payload).unwrap_err(),
            StatusListError::Decompress(_)
        ));
    }

    #[test]
    fn pointer_round_trip() {
        let v = json!({
            "type": "SwissTokenStatusList-1.0",
            "idx": 643u64,
            "uri": "https://status-reg.example.com/list.jwt",
        });
        let p = StatusListPointer::try_from(&v).unwrap();
        assert_eq!(p.type_(), "SwissTokenStatusList-1.0");
        assert_eq!(p.idx(), 643);
        assert_eq!(p.uri(), "https://status-reg.example.com/list.jwt");
    }

    #[test]
    fn pointer_missing_idx() {
        let v = json!({ "type": "x", "uri": "y" });
        assert_eq!(
            StatusListPointer::try_from(&v).unwrap_err(),
            StatusListError::MissingField("idx")
        );
    }

    #[test]
    fn pointer_idx_wrong_type() {
        let v = json!({ "type": "x", "idx": "643", "uri": "y" });
        assert_eq!(
            StatusListPointer::try_from(&v).unwrap_err(),
            StatusListError::InvalidFieldType("idx")
        );
    }

    #[test]
    fn status_value_is_valid() {
        assert!(StatusValue::Valid.is_valid());
        assert!(!StatusValue::Revoked.is_valid());
        assert!(!StatusValue::Suspended.is_valid());
        assert!(!StatusValue::Reserved(3).is_valid());
    }

    #[test]
    fn len_for_two_bit_list() {
        let payload = payload_with(Some(2), &vec![0u8; 25_000]);
        let list = StatusList::from_payload(&payload).unwrap();
        assert_eq!(list.len(), 100_000);
    }
}
