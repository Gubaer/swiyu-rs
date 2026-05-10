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
//!   `TryFrom<&Value>`; queried with [`StatusList::value_at`].
//!
//! This module is intentionally I/O-free. Fetching the JWT and verifying its
//! signature live in the consuming application; this module only handles the
//! wire-format decode and the slot-value semantics.

use std::fmt;
use std::io::{Read, Write};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use serde_json::{Value, json};

// SWIYU-profile parameters: the values producer (issuer) and consumer
// (verifier) must agree on. Centralised here so the agreement is structural
// rather than coincidental.

/// Type tag carried in the SD-JWT VC's `status.status_list.type` field. Names
/// the SWIYU profile so verifiers know how to interpret the bitstring.
pub const SWIYU_STATUS_LIST_TYPE: &str = "SwissTokenStatusList-1.0";

/// Slot width SWIYU uses for its combined revocation+suspension list.
pub const SWIYU_STATUS_LIST_BITS: u8 = 2;

/// Number of slots per SWIYU status list. At [`SWIYU_STATUS_LIST_BITS`] the
/// bitstring is 32_768 bytes long.
pub const SWIYU_STATUS_LIST_CAPACITY: u64 = 131_072;

/// JOSE `typ` value for the wallet-facing status-list JWT, content-typed
/// `application/statuslist+jwt`.
pub const STATUSLIST_JWT_TYP: &str = "statuslist+jwt";

#[derive(Debug, PartialEq)]
pub enum StatusListError {
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
    /// `capacity * bits` is not a multiple of 8 (would leave a
    /// trailing partial byte).
    InvalidCapacity { capacity: u64, bits: u8 },
    /// A `StatusValue` does not fit in the list's `bits` width
    /// (e.g. `Suspended` or `Reserved(2..)` written to a 1-bit list).
    ValueOutOfRange { raw: u8, bits: u8 },
}

impl fmt::Display for StatusListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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
            Self::InvalidCapacity { capacity, bits } => {
                write!(
                    f,
                    "capacity {capacity} at bits={bits} does not align to whole bytes"
                )
            }
            Self::ValueOutOfRange { raw, bits } => {
                write!(f, "value {raw} does not fit in bits={bits}")
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

/// Emits the `status_list` object an SD-JWT VC issuer embeds at
/// `payload.status.status_list`. Inverse of `TryFrom<&Value>`.
impl From<&StatusListPointer> for Value {
    fn from(pointer: &StatusListPointer) -> Self {
        json!({
            "type": pointer.type_,
            "idx": pointer.idx,
            "uri": pointer.uri,
        })
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

    /// Inverse of [`Self::from_raw`]: encodes the semantic value as the
    /// raw bit pattern for a list of width `bits`. Errors if the value
    /// does not fit (e.g. `Suspended` on a 1-bit list).
    fn to_raw(self, bits: u8) -> Result<u8, StatusListError> {
        let raw = u8::from(self);
        let max = match bits {
            1 => 1u8,
            2 => 0b11,
            other => return Err(StatusListError::UnsupportedBits(other)),
        };
        if raw > max {
            return Err(StatusListError::ValueOutOfRange { raw, bits });
        }
        Ok(raw)
    }
}

/// Width-agnostic numeric encoding: `Valid` → 0, `Revoked` → 1,
/// `Suspended` → 2, `Reserved(n)` → `n`. The width-aware variant
/// (which fails when a value doesn't fit) lives on `StatusList::set_at`.
impl From<StatusValue> for u8 {
    fn from(value: StatusValue) -> Self {
        match value {
            StatusValue::Valid => 0,
            StatusValue::Revoked => 1,
            StatusValue::Suspended => 2,
            StatusValue::Reserved(n) => n,
        }
    }
}

/// Width-agnostic decoding: 0/1/2 map to the named variants, anything
/// else falls into `Reserved`. For width-aware decoding (which never
/// returns `Suspended` for a 1-bit list), use [`StatusList::value_at`].
impl From<u8> for StatusValue {
    fn from(raw: u8) -> Self {
        match raw {
            0 => Self::Valid,
            1 => Self::Revoked,
            2 => Self::Suspended,
            other => Self::Reserved(other),
        }
    }
}

/// A decoded status list: the decompressed bitstring plus the slot width.
///
/// Constructed from a status-list JWT's `payload.status_list` object
/// via `TryFrom<&Value>`. Read individual slots with
/// [`StatusList::value_at`]; serialise back to a JSON value via
/// `From<&StatusList>` (produces the inner object the caller embeds
/// at `status_list`).
#[derive(Debug, Clone)]
pub struct StatusList {
    bits: u8,
    bytes: Vec<u8>,
}

impl StatusList {
    /// Constructs an all-zero status list of the given width and capacity.
    ///
    /// `bits` must be 1 or 2; other widths are reserved by the IETF
    /// draft and rejected here. `capacity * bits` must be a multiple
    /// of 8 — partial trailing bytes are disallowed so that
    /// [`Self::len`] always equals the capacity the caller asked for.
    pub fn new(bits: u8, capacity: u64) -> Result<Self, StatusListError> {
        if bits != 1 && bits != 2 {
            return Err(StatusListError::UnsupportedBits(bits));
        }
        let total_bits = capacity
            .checked_mul(bits as u64)
            .ok_or(StatusListError::InvalidCapacity { capacity, bits })?;
        if total_bits % 8 != 0 {
            return Err(StatusListError::InvalidCapacity { capacity, bits });
        }
        let bytes_len = (total_bits / 8) as usize;
        Ok(Self {
            bits,
            bytes: vec![0u8; bytes_len],
        })
    }

    /// Wraps an already-decompressed bitstring. Use this when the bytes
    /// have come from somewhere other than a JWT payload — e.g. a
    /// database column on the issuer side. `bits` must be 1 or 2;
    /// any `bytes.len()` is accepted and yields a list whose
    /// [`Self::len`] is `bytes.len() * (8 / bits)`.
    pub fn from_raw(bits: u8, bytes: Vec<u8>) -> Result<Self, StatusListError> {
        if bits != 1 && bits != 2 {
            return Err(StatusListError::UnsupportedBits(bits));
        }
        Ok(Self { bits, bytes })
    }

    pub fn bits(&self) -> u8 {
        self.bits
    }

    /// Borrowed view of the decompressed bitstring. Use when persisting
    /// the list verbatim (e.g. writing the issuer-side `bitstring`
    /// column) or computing a hash over the raw layout.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
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

    /// Writes the slot at `idx`. Mirror of [`Self::value_at`].
    ///
    /// Errors with [`StatusListError::IdxOutOfRange`] for out-of-range
    /// indices and with [`StatusListError::ValueOutOfRange`] when
    /// `value` does not fit in the list's width (e.g. `Suspended` on a
    /// 1-bit list).
    pub fn set_at(&mut self, idx: u64, value: StatusValue) -> Result<(), StatusListError> {
        let raw = value.to_raw(self.bits)?;
        let slots = self.len();
        match self.bits {
            1 => {
                let byte_idx = (idx / 8) as usize;
                let bit = (idx % 8) as u8;
                let byte = self
                    .bytes
                    .get_mut(byte_idx)
                    .ok_or(StatusListError::IdxOutOfRange { idx, slots })?;
                *byte = (*byte & !(1 << bit)) | ((raw & 1) << bit);
            }
            2 => {
                let byte_idx = (idx / 4) as usize;
                let shift = ((idx % 4) * 2) as u8;
                let byte = self
                    .bytes
                    .get_mut(byte_idx)
                    .ok_or(StatusListError::IdxOutOfRange { idx, slots })?;
                *byte = (*byte & !(0b11 << shift)) | ((raw & 0b11) << shift);
            }
            other => return Err(StatusListError::UnsupportedBits(other)),
        }
        Ok(())
    }
}

/// Parses the inner `status_list` object from a status-list JWT's
/// payload: reads `bits` (default `1` per the IETF draft),
/// base64url-decodes `lst`, and zlib-decompresses to obtain the raw
/// bitstring. The caller is responsible for extracting `status_list`
/// from the outer payload.
impl TryFrom<&Value> for StatusList {
    type Error = StatusListError;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        let obj = value
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

/// Encodes this list as the inner `status_list` JSON object: zlib-
/// compresses the bitstring (default level), base64url-encodes
/// (`URL_SAFE_NO_PAD`) the result, and emits `{ "bits": …, "lst": … }`.
/// Caller wraps with `{ "status_list": <value> }` when they want the
/// outer envelope. Round-trips exactly through `TryFrom<&Value>`.
impl From<&StatusList> for Value {
    fn from(list: &StatusList) -> Self {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(&list.bytes)
            .expect("ZlibEncoder over Vec is infallible");
        let compressed = encoder
            .finish()
            .expect("ZlibEncoder finish over Vec is infallible");
        let lst = URL_SAFE_NO_PAD.encode(compressed);
        json!({
            "bits": list.bits,
            "lst": lst,
        })
    }
}

/// JOSE header for a status-list JWT (`application/statuslist+jwt`).
///
/// Producer side (issuer crate) builds one and emits it with
/// `Value::from(&header)`; verifier side parses with
/// `StatusListJwtHeader::try_from(&value)`. Application policy on
/// `alg` and `kid` (e.g. requiring `ES256`, anchoring `kid` to a
/// known issuer DID) lives in the consumer; this struct only owns
/// the wire shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusListJwtHeader {
    alg: String,
    typ: String,
    kid: String,
}

impl StatusListJwtHeader {
    pub fn new(alg: String, typ: String, kid: String) -> Self {
        Self { alg, typ, kid }
    }

    pub fn alg(&self) -> &str {
        &self.alg
    }

    pub fn typ(&self) -> &str {
        &self.typ
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }
}

impl TryFrom<&Value> for StatusListJwtHeader {
    type Error = StatusListError;

    fn try_from(v: &Value) -> Result<Self, Self::Error> {
        let obj = v
            .as_object()
            .ok_or(StatusListError::InvalidFieldType("header"))?;
        let alg = obj
            .get("alg")
            .ok_or(StatusListError::MissingField("alg"))?
            .as_str()
            .ok_or(StatusListError::InvalidFieldType("alg"))?
            .to_string();
        let typ = obj
            .get("typ")
            .ok_or(StatusListError::MissingField("typ"))?
            .as_str()
            .ok_or(StatusListError::InvalidFieldType("typ"))?
            .to_string();
        let kid = obj
            .get("kid")
            .ok_or(StatusListError::MissingField("kid"))?
            .as_str()
            .ok_or(StatusListError::InvalidFieldType("kid"))?
            .to_string();
        Ok(Self { alg, typ, kid })
    }
}

impl From<&StatusListJwtHeader> for Value {
    fn from(header: &StatusListJwtHeader) -> Self {
        json!({
            "alg": header.alg,
            "typ": header.typ,
            "kid": header.kid,
        })
    }
}

/// Payload of a status-list JWT: the issuer DID, the registry URL the
/// JWT is hosted at, the issued-at timestamp, optional expiry, and
/// the `StatusList` itself.
///
/// `From<&StatusListJwtPayload>` for `Value` produces the full
/// payload object, with `status_list` set to the inner
/// `{ "bits", "lst" }` shape `StatusList` already serialises to.
/// `TryFrom<&Value>` is the inverse and replaces the hand-rolled
/// `payload.get("status_list")` extraction the verifier would otherwise
/// have to do.
#[derive(Debug, Clone)]
pub struct StatusListJwtPayload {
    iss: String,
    sub: String,
    iat: u64,
    exp: Option<u64>,
    list: StatusList,
}

impl StatusListJwtPayload {
    pub fn new(
        iss: String,
        sub: String,
        iat: u64,
        exp: Option<u64>,
        list: StatusList,
    ) -> Self {
        Self {
            iss,
            sub,
            iat,
            exp,
            list,
        }
    }

    pub fn iss(&self) -> &str {
        &self.iss
    }

    pub fn sub(&self) -> &str {
        &self.sub
    }

    pub fn iat(&self) -> u64 {
        self.iat
    }

    pub fn exp(&self) -> Option<u64> {
        self.exp
    }

    pub fn list(&self) -> &StatusList {
        &self.list
    }

    pub fn into_list(self) -> StatusList {
        self.list
    }
}

impl TryFrom<&Value> for StatusListJwtPayload {
    type Error = StatusListError;

    fn try_from(v: &Value) -> Result<Self, Self::Error> {
        let obj = v
            .as_object()
            .ok_or(StatusListError::InvalidFieldType("payload"))?;
        let iss = obj
            .get("iss")
            .ok_or(StatusListError::MissingField("iss"))?
            .as_str()
            .ok_or(StatusListError::InvalidFieldType("iss"))?
            .to_string();
        let sub = obj
            .get("sub")
            .ok_or(StatusListError::MissingField("sub"))?
            .as_str()
            .ok_or(StatusListError::InvalidFieldType("sub"))?
            .to_string();
        let iat = obj
            .get("iat")
            .ok_or(StatusListError::MissingField("iat"))?
            .as_u64()
            .ok_or(StatusListError::InvalidFieldType("iat"))?;
        let exp = match obj.get("exp") {
            None => None,
            Some(Value::Null) => None,
            Some(v) => Some(
                v.as_u64()
                    .ok_or(StatusListError::InvalidFieldType("exp"))?,
            ),
        };
        let inner = obj
            .get("status_list")
            .ok_or(StatusListError::MissingField("status_list"))?;
        let list = StatusList::try_from(inner)?;
        Ok(Self {
            iss,
            sub,
            iat,
            exp,
            list,
        })
    }
}

impl From<&StatusListJwtPayload> for Value {
    fn from(payload: &StatusListJwtPayload) -> Self {
        let mut obj = serde_json::Map::new();
        obj.insert("iss".into(), Value::String(payload.iss.clone()));
        obj.insert("sub".into(), Value::String(payload.sub.clone()));
        obj.insert("iat".into(), Value::Number(payload.iat.into()));
        if let Some(exp) = payload.exp {
            obj.insert("exp".into(), Value::Number(exp.into()));
        }
        obj.insert("status_list".into(), Value::from(&payload.list));
        Value::Object(obj)
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

    fn inner_with(bits: Option<u8>, bytes: &[u8]) -> Value {
        let mut sl = serde_json::Map::new();
        if let Some(b) = bits {
            sl.insert("bits".into(), json!(b));
        }
        sl.insert("lst".into(), json!(encode_lst(bytes)));
        Value::Object(sl)
    }

    #[test]
    fn try_from_two_bit() {
        // 0x55 = 0b01_01_01_01 → slots 0..3 read as 1 (revoked).
        let inner = inner_with(Some(2), &[0x55]);
        let list = StatusList::try_from(&inner).unwrap();
        assert_eq!(list.bits(), 2);
        assert_eq!(list.len(), 4);
        assert_eq!(list.value_at(0).unwrap(), StatusValue::Revoked);
        assert_eq!(list.value_at(3).unwrap(), StatusValue::Revoked);
    }

    #[test]
    fn try_from_one_bit_default() {
        // No 'bits' field → defaults to 1.
        let inner = inner_with(None, &[0b00010000]);
        let list = StatusList::try_from(&inner).unwrap();
        assert_eq!(list.bits(), 1);
        assert_eq!(list.value_at(0).unwrap(), StatusValue::Valid);
        assert_eq!(list.value_at(4).unwrap(), StatusValue::Revoked);
    }

    #[test]
    fn value_at_two_bit_codepoints() {
        // 0b11_10_01_00 → slots: 0=Valid, 1=Revoked, 2=Suspended, 3=Reserved(3)
        let inner = inner_with(Some(2), &[0b11_10_01_00]);
        let list = StatusList::try_from(&inner).unwrap();
        assert_eq!(list.value_at(0).unwrap(), StatusValue::Valid);
        assert_eq!(list.value_at(1).unwrap(), StatusValue::Revoked);
        assert_eq!(list.value_at(2).unwrap(), StatusValue::Suspended);
        assert_eq!(list.value_at(3).unwrap(), StatusValue::Reserved(3));
    }

    #[test]
    fn value_at_idx_out_of_range() {
        let inner = inner_with(Some(2), &[0x00]);
        let list = StatusList::try_from(&inner).unwrap();
        let err = list.value_at(10).unwrap_err();
        assert!(matches!(
            err,
            StatusListError::IdxOutOfRange { idx: 10, slots: 4 }
        ));
    }

    #[test]
    fn unsupported_bits_rejected() {
        let inner = inner_with(Some(4), &[0]);
        assert_eq!(
            StatusList::try_from(&inner).unwrap_err(),
            StatusListError::UnsupportedBits(4)
        );
    }

    #[test]
    fn try_from_rejects_non_object() {
        assert_eq!(
            StatusList::try_from(&json!("not an object")).unwrap_err(),
            StatusListError::InvalidFieldType("status_list"),
        );
    }

    #[test]
    fn missing_lst() {
        let inner = json!({ "bits": 2 });
        assert_eq!(
            StatusList::try_from(&inner).unwrap_err(),
            StatusListError::MissingField("lst")
        );
    }

    #[test]
    fn invalid_base64_lst() {
        let inner = json!({ "bits": 2, "lst": "!!!not-base64!!!" });
        assert_eq!(
            StatusList::try_from(&inner).unwrap_err(),
            StatusListError::InvalidBase64
        );
    }

    #[test]
    fn invalid_zlib_data() {
        // Valid base64url but the bytes aren't a zlib stream.
        let bad = URL_SAFE_NO_PAD.encode(b"not-zlib-data");
        let inner = json!({ "bits": 2, "lst": bad });
        assert!(matches!(
            StatusList::try_from(&inner).unwrap_err(),
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
        let inner = inner_with(Some(2), &vec![0u8; 25_000]);
        let list = StatusList::try_from(&inner).unwrap();
        assert_eq!(list.len(), 100_000);
    }

    #[test]
    fn new_creates_zero_bitstring_of_correct_length() {
        let list = StatusList::new(2, 131_072).unwrap();
        assert_eq!(list.bits(), 2);
        assert_eq!(list.len(), 131_072);
        assert_eq!(list.bytes.len(), 32_768);
        assert!(list.bytes.iter().all(|b| *b == 0));
    }

    #[test]
    fn new_one_bit_capacity_aligns_to_byte_boundary() {
        let list = StatusList::new(1, 64).unwrap();
        assert_eq!(list.bytes.len(), 8);
        assert_eq!(list.len(), 64);
    }

    #[test]
    fn new_rejects_unsupported_bits() {
        assert_eq!(
            StatusList::new(4, 32).unwrap_err(),
            StatusListError::UnsupportedBits(4),
        );
    }

    #[test]
    fn new_rejects_misaligned_capacity() {
        assert_eq!(
            StatusList::new(1, 5).unwrap_err(),
            StatusListError::InvalidCapacity {
                capacity: 5,
                bits: 1,
            },
        );
        assert_eq!(
            StatusList::new(2, 3).unwrap_err(),
            StatusListError::InvalidCapacity {
                capacity: 3,
                bits: 2,
            },
        );
    }

    #[test]
    fn set_at_two_bit_lays_out_lsb_first() {
        // Layout (LSB-first):
        //   byte = | idx 3 (bits 7..6) | idx 2 (5..4) | idx 1 (3..2) | idx 0 (1..0) |
        // idx 0 = Revoked (01), idx 1 = Suspended (10),
        // idx 2 = Revoked (01), idx 3 = Suspended (10).
        // → 0b10_01_10_01 = 0x99
        let mut list = StatusList::new(2, 4).unwrap();
        list.set_at(0, StatusValue::Revoked).unwrap();
        list.set_at(1, StatusValue::Suspended).unwrap();
        list.set_at(2, StatusValue::Revoked).unwrap();
        list.set_at(3, StatusValue::Suspended).unwrap();
        assert_eq!(list.bytes[0], 0b10_01_10_01);
    }

    #[test]
    fn set_at_one_bit_writes_only_the_named_bit() {
        let mut list = StatusList::new(1, 16).unwrap();
        list.set_at(0, StatusValue::Revoked).unwrap();
        list.set_at(7, StatusValue::Revoked).unwrap();
        list.set_at(8, StatusValue::Revoked).unwrap();
        // bits 0 and 7 of byte 0; bit 0 of byte 1.
        assert_eq!(list.bytes[0], 0b1000_0001);
        assert_eq!(list.bytes[1], 0b0000_0001);
    }

    #[test]
    fn set_at_overwrites_previous_value() {
        let mut list = StatusList::new(2, 8).unwrap();
        list.set_at(2, StatusValue::Revoked).unwrap();
        assert_eq!(list.value_at(2).unwrap(), StatusValue::Revoked);
        list.set_at(2, StatusValue::Suspended).unwrap();
        assert_eq!(list.value_at(2).unwrap(), StatusValue::Suspended);
        list.set_at(2, StatusValue::Valid).unwrap();
        assert_eq!(list.value_at(2).unwrap(), StatusValue::Valid);
    }

    #[test]
    fn set_at_does_not_disturb_neighbouring_slots() {
        let mut list = StatusList::new(2, 8).unwrap();
        list.set_at(0, StatusValue::Revoked).unwrap();
        list.set_at(1, StatusValue::Suspended).unwrap();
        list.set_at(2, StatusValue::Revoked).unwrap();
        list.set_at(3, StatusValue::Suspended).unwrap();
        // Rewrite only slot 1; the others must keep their values.
        list.set_at(1, StatusValue::Valid).unwrap();
        assert_eq!(list.value_at(0).unwrap(), StatusValue::Revoked);
        assert_eq!(list.value_at(1).unwrap(), StatusValue::Valid);
        assert_eq!(list.value_at(2).unwrap(), StatusValue::Revoked);
        assert_eq!(list.value_at(3).unwrap(), StatusValue::Suspended);
    }

    #[test]
    fn set_at_rejects_suspended_on_one_bit_list() {
        let mut list = StatusList::new(1, 8).unwrap();
        assert_eq!(
            list.set_at(0, StatusValue::Suspended).unwrap_err(),
            StatusListError::ValueOutOfRange { raw: 2, bits: 1 },
        );
    }

    #[test]
    fn set_at_rejects_reserved_value_that_overflows_bits() {
        let mut list = StatusList::new(2, 8).unwrap();
        assert_eq!(
            list.set_at(0, StatusValue::Reserved(4)).unwrap_err(),
            StatusListError::ValueOutOfRange { raw: 4, bits: 2 },
        );
    }

    #[test]
    fn set_at_idx_out_of_range() {
        let mut list = StatusList::new(2, 4).unwrap();
        assert_eq!(
            list.set_at(4, StatusValue::Revoked).unwrap_err(),
            StatusListError::IdxOutOfRange { idx: 4, slots: 4 },
        );
    }

    #[test]
    fn value_from_emits_bits_and_lst() {
        let list = StatusList::new(2, 8).unwrap();
        let value = Value::from(&list);
        let obj = value.as_object().unwrap();
        assert_eq!(obj.get("bits").and_then(Value::as_u64).unwrap(), 2);
        assert!(obj.get("lst").and_then(Value::as_str).is_some());
    }

    #[test]
    fn value_round_trips_through_try_from() {
        let mut list = StatusList::new(2, 32).unwrap();
        let writes = [
            (0u64, StatusValue::Revoked),
            (1, StatusValue::Suspended),
            (5, StatusValue::Revoked),
            (16, StatusValue::Suspended),
            (31, StatusValue::Revoked),
        ];
        for (idx, value) in writes {
            list.set_at(idx, value).unwrap();
        }
        let serialized = Value::from(&list);
        let decoded = StatusList::try_from(&serialized).unwrap();
        assert_eq!(decoded.bits(), 2);
        assert_eq!(decoded.len(), 32);
        for (idx, expected) in writes {
            assert_eq!(decoded.value_at(idx).unwrap(), expected);
        }
        // Untouched slots remain Valid.
        assert_eq!(decoded.value_at(2).unwrap(), StatusValue::Valid);
        assert_eq!(decoded.value_at(30).unwrap(), StatusValue::Valid);
    }

    #[test]
    fn from_raw_wraps_bytes_unmodified() {
        let raw = vec![0x12, 0x34, 0x56];
        let list = StatusList::from_raw(2, raw.clone()).unwrap();
        assert_eq!(list.bits(), 2);
        assert_eq!(list.as_bytes(), raw.as_slice());
        assert_eq!(list.len(), 12);
    }

    #[test]
    fn from_raw_rejects_unsupported_bits() {
        assert_eq!(
            StatusList::from_raw(4, vec![0u8; 8]).unwrap_err(),
            StatusListError::UnsupportedBits(4),
        );
    }

    #[test]
    fn from_raw_round_trips_through_value_serialisation() {
        // Build a list via from_raw, mutate, serialise to JSON, parse
        // back, confirm both the raw bytes and the slot values match.
        let mut list = StatusList::from_raw(2, vec![0u8; 64]).unwrap();
        list.set_at(0, StatusValue::Revoked).unwrap();
        list.set_at(7, StatusValue::Suspended).unwrap();
        list.set_at(255, StatusValue::Revoked).unwrap();

        let original_bytes = list.as_bytes().to_vec();
        let value = Value::from(&list);
        let decoded = StatusList::try_from(&value).unwrap();
        assert_eq!(decoded.as_bytes(), original_bytes.as_slice());
        assert_eq!(decoded.value_at(0).unwrap(), StatusValue::Revoked);
        assert_eq!(decoded.value_at(7).unwrap(), StatusValue::Suspended);
        assert_eq!(decoded.value_at(255).unwrap(), StatusValue::Revoked);
    }

    #[test]
    fn pointer_value_round_trip() {
        let original = StatusListPointer::new(
            SWIYU_STATUS_LIST_TYPE.to_string(),
            42,
            "https://example.com/list.jwt".to_string(),
        );
        let value = Value::from(&original);
        let parsed = StatusListPointer::try_from(&value).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn status_value_to_u8() {
        assert_eq!(u8::from(StatusValue::Valid), 0);
        assert_eq!(u8::from(StatusValue::Revoked), 1);
        assert_eq!(u8::from(StatusValue::Suspended), 2);
        assert_eq!(u8::from(StatusValue::Reserved(7)), 7);
    }

    #[test]
    fn status_value_from_u8() {
        assert_eq!(StatusValue::from(0u8), StatusValue::Valid);
        assert_eq!(StatusValue::from(1u8), StatusValue::Revoked);
        assert_eq!(StatusValue::from(2u8), StatusValue::Suspended);
        assert_eq!(StatusValue::from(3u8), StatusValue::Reserved(3));
        assert_eq!(StatusValue::from(255u8), StatusValue::Reserved(255));
    }

    #[test]
    fn status_value_u8_round_trip() {
        for raw in 0u8..=255 {
            assert_eq!(u8::from(StatusValue::from(raw)), raw);
        }
    }

    #[test]
    fn header_round_trip() {
        let original = StatusListJwtHeader::new(
            "ES256".to_string(),
            STATUSLIST_JWT_TYP.to_string(),
            "did:tdw:example.com:abc#assertion-key-01".to_string(),
        );
        let value = Value::from(&original);
        let parsed = StatusListJwtHeader::try_from(&value).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn header_missing_alg() {
        let v = json!({ "typ": "statuslist+jwt", "kid": "did#k" });
        assert_eq!(
            StatusListJwtHeader::try_from(&v).unwrap_err(),
            StatusListError::MissingField("alg"),
        );
    }

    #[test]
    fn header_rejects_non_object() {
        assert_eq!(
            StatusListJwtHeader::try_from(&json!("nope")).unwrap_err(),
            StatusListError::InvalidFieldType("header"),
        );
    }

    #[test]
    fn payload_round_trip() {
        let mut list = StatusList::new(2, 32).unwrap();
        list.set_at(3, StatusValue::Suspended).unwrap();
        list.set_at(5, StatusValue::Revoked).unwrap();

        let original = StatusListJwtPayload::new(
            "did:tdw:example.com:abc".to_string(),
            "https://status-reg.example.com/lists/abc.jwt".to_string(),
            1_700_000_000,
            Some(1_800_000_000),
            list,
        );
        let value = Value::from(&original);
        let parsed = StatusListJwtPayload::try_from(&value).unwrap();
        assert_eq!(parsed.iss(), original.iss());
        assert_eq!(parsed.sub(), original.sub());
        assert_eq!(parsed.iat(), original.iat());
        assert_eq!(parsed.exp(), original.exp());
        assert_eq!(parsed.list().bits(), 2);
        assert_eq!(parsed.list().value_at(3).unwrap(), StatusValue::Suspended);
        assert_eq!(parsed.list().value_at(5).unwrap(), StatusValue::Revoked);
        assert_eq!(parsed.list().value_at(0).unwrap(), StatusValue::Valid);
    }

    #[test]
    fn payload_omits_exp_when_none() {
        let payload = StatusListJwtPayload::new(
            "iss".to_string(),
            "sub".to_string(),
            1,
            None,
            StatusList::new(2, 8).unwrap(),
        );
        let value = Value::from(&payload);
        assert!(value.as_object().unwrap().get("exp").is_none());
        let parsed = StatusListJwtPayload::try_from(&value).unwrap();
        assert_eq!(parsed.exp(), None);
    }

    #[test]
    fn payload_accepts_null_exp() {
        let v = json!({
            "iss": "iss",
            "sub": "sub",
            "iat": 1,
            "exp": null,
            "status_list": Value::from(&StatusList::new(2, 8).unwrap()),
        });
        let parsed = StatusListJwtPayload::try_from(&v).unwrap();
        assert_eq!(parsed.exp(), None);
    }

    #[test]
    fn payload_missing_iss() {
        let v = json!({
            "sub": "sub",
            "iat": 1,
            "status_list": Value::from(&StatusList::new(2, 8).unwrap()),
        });
        assert_eq!(
            StatusListJwtPayload::try_from(&v).unwrap_err(),
            StatusListError::MissingField("iss"),
        );
    }

    #[test]
    fn payload_missing_status_list() {
        let v = json!({ "iss": "iss", "sub": "sub", "iat": 1 });
        assert_eq!(
            StatusListJwtPayload::try_from(&v).unwrap_err(),
            StatusListError::MissingField("status_list"),
        );
    }

    #[test]
    fn payload_iat_wrong_type() {
        let v = json!({
            "iss": "iss",
            "sub": "sub",
            "iat": "not-a-number",
            "status_list": Value::from(&StatusList::new(2, 8).unwrap()),
        });
        assert_eq!(
            StatusListJwtPayload::try_from(&v).unwrap_err(),
            StatusListError::InvalidFieldType("iat"),
        );
    }

    #[test]
    fn payload_propagates_inner_status_list_errors() {
        let v = json!({
            "iss": "iss",
            "sub": "sub",
            "iat": 1,
            "status_list": { "bits": 2 },
        });
        assert_eq!(
            StatusListJwtPayload::try_from(&v).unwrap_err(),
            StatusListError::MissingField("lst"),
        );
    }

    #[test]
    fn swiyu_profile_constants_have_expected_shape() {
        assert_eq!(SWIYU_STATUS_LIST_TYPE, "SwissTokenStatusList-1.0");
        assert_eq!(SWIYU_STATUS_LIST_BITS, 2);
        assert_eq!(SWIYU_STATUS_LIST_CAPACITY, 131_072);
        assert_eq!(STATUSLIST_JWT_TYP, "statuslist+jwt");
        // The SWIYU profile must round-trip through the StatusList constructor.
        let list = StatusList::new(SWIYU_STATUS_LIST_BITS, SWIYU_STATUS_LIST_CAPACITY).unwrap();
        assert_eq!(list.as_bytes().len(), 32_768);
    }
}
