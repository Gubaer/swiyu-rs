pub mod entry_edits;
pub mod scid;
pub mod verify;

use multihash_codetable::{Code, MultihashDigest};
use serde_json::{Map, Value, json};
use std::fmt;

use crate::diddoc::DIDDoc;
use crate::diddoc::public_keys::P256PublicKey;

pub type DIDLogResult<T> = Result<T, DIDLogError>;

#[derive(Debug)]
pub enum DIDLogError {
    InvalidFormat(String),
    MissingField(String),
    InvalidFieldType(String),
}

impl fmt::Display for DIDLogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DIDLogError::InvalidFormat(msg) => write!(f, "invalid format: {msg}"),
            DIDLogError::MissingField(field) => write!(f, "missing required field: {field}"),
            DIDLogError::InvalidFieldType(msg) => write!(f, "invalid field type: {msg}"),
        }
    }
}

impl std::error::Error for DIDLogError {}

/// Identifies the wire format of a DID log entry.
///
/// `did:tdw` v0.3 and `did:webvh` v1.0 are the same DID method under two names, but they use
/// incompatible wire formats: v0.3 encodes each log entry as a five-element JSON array, while
/// v1.0 uses a named-field JSON object. Both formats are in active use — v0.3 in the current
/// Beta Swiss Trust Infrastructure, v1.0 in the future production infrastructure — so full
/// round-trip support for both is required.
///
/// This enum is carried by [`DIDLogEntry`] and [`LogParameters`] to drive format-specific
/// parsing and serialisation without affecting any other logic.
#[derive(Debug, Clone, PartialEq)]
pub enum LogEntryFormat {
    /// `did:tdw` v0.3 — log entry is a five-element JSON array.
    TDW03,
    /// `did:webvh` v1.0 — log entry is a named-field JSON object.
    WebVH10,
}

/// The state of the DID document in a log entry — either a full replacement or an incremental patch.
#[derive(Debug, Clone)]
pub enum DIDDocState {
    Value(Value),
    Patch(Value),
}

impl DIDDocState {
    fn try_from_json(v: &Value) -> DIDLogResult<Self> {
        let obj = v.as_object().ok_or_else(|| {
            DIDLogError::InvalidFieldType("DIDDocState must be a JSON object".into())
        })?;
        if let Some(value) = obj.get("value") {
            Ok(DIDDocState::Value(value.clone()))
        } else if let Some(patch) = obj.get("patch") {
            Ok(DIDDocState::Patch(patch.clone()))
        } else {
            Err(DIDLogError::InvalidFormat(
                "DIDDocState must contain 'value' or 'patch'".into(),
            ))
        }
    }

    fn to_json(&self) -> Value {
        match self {
            DIDDocState::Value(v) => json!({ "value": v }),
            DIDDocState::Patch(p) => json!({ "patch": p }),
        }
    }
}

/// The parameters field of a log entry, controlling DID generation and verification.
///
/// Covers both `did:tdw` v0.3 and `did:webvh` v1.0. Fields introduced in v1.0 are noted inline.
#[derive(Debug, Clone)]
pub struct LogParameters {
    format: LogEntryFormat,
    /// The DID method version string (e.g. `did:tdw:0.3` or `did:webvh:1.0`). Present only in
    /// the first log entry.
    method: Option<String>,
    /// The self-certifying identifier hash. Present only in the first log entry.
    scid: Option<String>,
    /// The keys authorized to sign subsequent log entries.
    update_keys: Option<Vec<String>>,
    /// When `true`, the next-key-hashes commitment is active and key rotation takes effect
    /// immediately upon publishing the current entry.
    prerotation: Option<bool>,
    /// Hashes of the next update keys, committing to a future rotation.
    next_key_hashes: Option<Vec<String>>,
    /// When `true`, the DID may be moved to a different domain.
    portable: Option<bool>,
    /// When `true`, the DID is deactivated and resolvers withhold the DID document.
    deactivated: Option<bool>,
    /// How long resolvers may cache the DID document, in seconds. Defaults to 3600 s in
    /// `did:webvh` 1.0 when absent.
    ttl: Option<u64>,
    /// Witness configuration. Uses a weighted-approval model in `did:tdw` v0.3 and a
    /// simpler count-based model in `did:webvh` 1.0.
    witness: Option<Value>,
    /// URLs of monitoring services that independently cache and observe the DID log. Introduced
    /// in `did:webvh` 1.0.
    watchers: Option<Vec<String>>,
}

impl LogParameters {
    // The parameters object in the DID log spec has this many fields by design.
    #[allow(clippy::too_many_arguments)]
    pub fn new_tdw(
        method: Option<String>,
        scid: Option<String>,
        update_keys: Option<Vec<String>>,
        prerotation: Option<bool>,
        next_key_hashes: Option<Vec<String>>,
        portable: Option<bool>,
        deactivated: Option<bool>,
        ttl: Option<u64>,
        witness: Option<Value>,
    ) -> Self {
        Self {
            format: LogEntryFormat::TDW03,
            method,
            scid,
            update_keys,
            prerotation,
            next_key_hashes,
            portable,
            deactivated,
            ttl,
            witness,
            watchers: None,
        }
    }

    /// Convenience constructor for the common did:tdw genesis-entry shape:
    /// `method`, `scid`, and `update_keys` are explicit; every other
    /// parameter is `None`.
    pub fn new_tdw_minimal(method: String, scid: String, update_keys: Vec<String>) -> Self {
        Self::new_tdw(
            Some(method),
            Some(scid),
            Some(update_keys),
            None,
            None,
            None,
            None,
            None,
            None,
        )
    }

    // The parameters object in the DID log spec has this many fields by design.
    #[allow(clippy::too_many_arguments)]
    pub fn new_webvh(
        method: Option<String>,
        scid: Option<String>,
        update_keys: Option<Vec<String>>,
        prerotation: Option<bool>,
        next_key_hashes: Option<Vec<String>>,
        portable: Option<bool>,
        deactivated: Option<bool>,
        ttl: Option<u64>,
        witness: Option<Value>,
        watchers: Option<Vec<String>>,
    ) -> Self {
        Self {
            format: LogEntryFormat::WebVH10,
            method,
            scid,
            update_keys,
            prerotation,
            next_key_hashes,
            portable,
            deactivated,
            ttl,
            witness,
            watchers,
        }
    }

    /// Convenience constructor for the common did:webvh genesis-entry
    /// shape: `method`, `scid`, and `update_keys` are explicit; every
    /// other parameter is `None`.
    pub fn new_webvh_minimal(method: String, scid: String, update_keys: Vec<String>) -> Self {
        Self::new_webvh(
            Some(method),
            Some(scid),
            Some(update_keys),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
    }

    fn try_from_json(v: &Value, format: LogEntryFormat) -> DIDLogResult<Self> {
        let obj = v.as_object().ok_or_else(|| {
            DIDLogError::InvalidFieldType("parameters must be a JSON object".into())
        })?;

        let method = string_field(obj, "method")?;
        let scid = string_field(obj, "scid")?;
        let update_keys = string_array_field(obj, "updateKeys")?;
        let prerotation = bool_field(obj, "prerotation")?;
        let next_key_hashes = string_array_field(obj, "nextKeyHashes")?;
        let portable = bool_field(obj, "portable")?;
        let deactivated = bool_field(obj, "deactivated")?;
        let ttl = u64_field(obj, "ttl")?;
        let witness = obj.get("witness").cloned();
        let watchers = if format == LogEntryFormat::WebVH10 {
            string_array_field(obj, "watchers")?
        } else {
            None
        };

        Ok(Self {
            format,
            method,
            scid,
            update_keys,
            prerotation,
            next_key_hashes,
            portable,
            deactivated,
            ttl,
            witness,
            watchers,
        })
    }

    fn to_json(&self) -> Value {
        let mut map = Map::new();
        if let Some(v) = &self.method {
            map.insert("method".into(), json!(v));
        }
        if let Some(v) = &self.scid {
            map.insert("scid".into(), json!(v));
        }
        if let Some(v) = &self.update_keys {
            map.insert("updateKeys".into(), json!(v));
        }
        if let Some(v) = self.prerotation {
            map.insert("prerotation".into(), json!(v));
        }
        if let Some(v) = &self.next_key_hashes {
            map.insert("nextKeyHashes".into(), json!(v));
        }
        // For did:tdw 0.3 genesis entries we emit `portable` explicitly to
        // mirror the Java DID Toolbox — the field is part of the JCS-
        // canonicalised input the SCID and proof are computed over, so
        // omitting it would change those bytes and break interop with the
        // Beta SWIYU registry. Subsequent did:tdw entries (no `scid`)
        // inherit the genesis value and stay silent on round-trip.
        // did:webvh 1.0 has no equivalent reference implementation to
        // mirror; it omits when not set, regardless of position.
        let is_tdw_genesis = self.format == LogEntryFormat::TDW03 && self.scid.is_some();
        match (is_tdw_genesis, self.portable) {
            (_, Some(v)) => {
                map.insert("portable".into(), json!(v));
            }
            (true, None) => {
                map.insert("portable".into(), json!(false));
            }
            (false, None) => {}
        }
        if let Some(v) = self.deactivated {
            map.insert("deactivated".into(), json!(v));
        }
        if let Some(v) = self.ttl {
            map.insert("ttl".into(), json!(v));
        }
        if let Some(v) = &self.witness {
            map.insert("witness".into(), v.clone());
        }
        if self.format == LogEntryFormat::WebVH10
            && let Some(v) = &self.watchers
        {
            map.insert("watchers".into(), json!(v));
        }
        Value::Object(map)
    }

    pub fn format(&self) -> &LogEntryFormat {
        &self.format
    }

    pub fn method(&self) -> Option<&str> {
        self.method.as_deref()
    }

    pub fn scid(&self) -> Option<&str> {
        self.scid.as_deref()
    }

    pub fn update_keys(&self) -> Option<&[String]> {
        self.update_keys.as_deref()
    }

    pub fn prerotation(&self) -> Option<bool> {
        self.prerotation
    }

    pub fn next_key_hashes(&self) -> Option<&[String]> {
        self.next_key_hashes.as_deref()
    }

    pub fn portable(&self) -> Option<bool> {
        self.portable
    }

    pub fn deactivated(&self) -> Option<bool> {
        self.deactivated
    }

    pub fn ttl(&self) -> Option<u64> {
        self.ttl
    }

    pub fn witness(&self) -> Option<&Value> {
        self.witness.as_ref()
    }

    pub fn watchers(&self) -> Option<&[String]> {
        self.watchers.as_deref()
    }
}

/// A single entry in the DID log. The internal representation is identical for both versions;
/// `format` records only the wire format used for parsing and serialisation.
#[derive(Debug, Clone)]
pub struct DIDLogEntry {
    /// Wire format of this entry, determines how it is parsed and serialised.
    format: LogEntryFormat,
    /// Unique identifier for this version of the DID document, composed of the sequence number
    /// and a hash of the entry (e.g. `1-QmHash…`).
    version_id: String,
    /// ISO 8601 timestamp at which this version was published.
    version_time: String,
    /// Control parameters for this log entry, such as update keys, pre-rotation commitments,
    /// and witness configuration.
    parameters: LogParameters,
    /// The DID document state introduced by this entry — either a full replacement or a patch.
    did_doc_state: DIDDocState,
    /// Data integrity proofs authorising this log entry.
    data_integrity_proofs: Vec<Value>,
}

impl DIDLogEntry {
    pub fn new_tdw(
        version_id: String,
        version_time: String,
        parameters: LogParameters,
        did_doc_state: DIDDocState,
        data_integrity_proofs: Vec<Value>,
    ) -> Self {
        Self {
            format: LogEntryFormat::TDW03,
            version_id,
            version_time,
            parameters,
            did_doc_state,
            data_integrity_proofs,
        }
    }

    pub fn new_webvh(
        version_id: String,
        version_time: String,
        parameters: LogParameters,
        did_doc_state: DIDDocState,
        data_integrity_proofs: Vec<Value>,
    ) -> Self {
        Self {
            format: LogEntryFormat::WebVH10,
            version_id,
            version_time,
            parameters,
            did_doc_state,
            data_integrity_proofs,
        }
    }

    /// Constructs the genesis DID-log entry, with `{SCID}` placeholders
    /// in `versionId` and the embedded DID strings. Callers compute the
    /// SCID over this preliminary entry, substitute the placeholders,
    /// then compute the entryHash and append the proof.
    ///
    /// Takes the `authentication` and `assertion` P-256 public keys
    /// (which appear in the DID document) and the `authorized`
    /// public key as its multikey string (which goes into
    /// `parameters.updateKeys`); the caller is responsible for
    /// converting from whatever keystore shape they use.
    pub fn new_genesis(
        format: &LogEntryFormat,
        authorized_multikey: &str,
        did_placeholder: &str,
        authentication: &P256PublicKey,
        assertion: &P256PublicKey,
        now: &str,
    ) -> Self {
        let method_str = match format {
            LogEntryFormat::TDW03 => "did:tdw:0.3",
            LogEntryFormat::WebVH10 => "did:webvh:1.0",
        };

        // Wire-format quirks (e.g. did:tdw emitting `portable: false`
        // explicitly) are encoded inside `LogParameters::to_json`; the
        // construction site here stays format-agnostic.
        let parameters = match format {
            LogEntryFormat::TDW03 => LogParameters::new_tdw_minimal(
                method_str.into(),
                "{SCID}".into(),
                vec![authorized_multikey.into()],
            ),
            LogEntryFormat::WebVH10 => LogParameters::new_webvh_minimal(
                method_str.into(),
                "{SCID}".into(),
                vec![authorized_multikey.into()],
            ),
        };

        let genesis_doc = DIDDoc::new_genesis(did_placeholder, authentication, assertion);
        let state = DIDDocState::Value(Value::from(genesis_doc));

        match format {
            LogEntryFormat::TDW03 => {
                Self::new_tdw("{SCID}".into(), now.into(), parameters, state, vec![])
            }
            LogEntryFormat::WebVH10 => {
                Self::new_webvh("{SCID}".into(), now.into(), parameters, state, vec![])
            }
        }
    }

    /// Constructs a deactivation DID-log entry with `version_id` set
    /// to the predecessor's value. Mirrors [`Self::new_genesis`] in
    /// shape: callers compute the entryHash over the unsigned entry,
    /// substitute the real `<n+1>-<entryHash>` via
    /// `entry_edits::set_version_id`, sign, and append the proof.
    ///
    /// Carries the previous DID document forward unchanged in
    /// `DIDDocState::Value`. The `parameters` block intentionally
    /// holds only `deactivated = true` and an empty `update_keys`
    /// list — `method`, `scid`, `portable`, etc. are not present in
    /// non-genesis entries. did:tdw 0.3 and did:webvh 1.0 share the
    /// same body shape; only the wire encoding differs and that is
    /// handled by the `From<DIDLogEntry> for Value` impl.
    pub fn new_deactivation(
        format: &LogEntryFormat,
        prev_version_id: &str,
        prev_did_doc: &DIDDoc,
        new_version_time: &str,
    ) -> Self {
        let parameters = match format {
            LogEntryFormat::TDW03 => LogParameters::new_tdw(
                None,
                None,
                Some(vec![]),
                None,
                None,
                None,
                Some(true),
                None,
                None,
            ),
            LogEntryFormat::WebVH10 => LogParameters::new_webvh(
                None,
                None,
                Some(vec![]),
                None,
                None,
                None,
                Some(true),
                None,
                None,
                None,
            ),
        };

        let state = DIDDocState::Value(Value::from(prev_did_doc.clone()));

        match format {
            LogEntryFormat::TDW03 => Self::new_tdw(
                prev_version_id.into(),
                new_version_time.into(),
                parameters,
                state,
                vec![],
            ),
            LogEntryFormat::WebVH10 => Self::new_webvh(
                prev_version_id.into(),
                new_version_time.into(),
                parameters,
                state,
                vec![],
            ),
        }
    }

    /// Constructs a key-rotation DID-log entry with `version_id`
    /// set to the predecessor's value. Mirrors [`Self::new_genesis`]
    /// and [`Self::new_deactivation`] in shape: callers compute the
    /// entryHash over the unsigned entry, substitute the real
    /// `<n+1>-<entryHash>` via `entry_edits::set_version_id`, sign
    /// with the **outgoing** Authorized private key, and append the
    /// proof. The new Authorized key only signs the *next* entry —
    /// even when the rotation rotates Authorized itself.
    ///
    /// `parameters.updateKeys` carries the multikey of the *new*
    /// Authorized public key (the announcement that this is now the
    /// signing key). The embedded DID document carries verification
    /// methods for the new Authentication and Assertion keys. The
    /// DID id stays the same across rotations.
    pub fn new_rotation(
        format: &LogEntryFormat,
        prev_version_id: &str,
        did: &str,
        new_authorized_multikey: &str,
        new_authentication: &P256PublicKey,
        new_assertion: &P256PublicKey,
        new_version_time: &str,
    ) -> Self {
        let parameters = match format {
            LogEntryFormat::TDW03 => LogParameters::new_tdw(
                None,
                None,
                Some(vec![new_authorized_multikey.into()]),
                None,
                None,
                None,
                None,
                None,
                None,
            ),
            LogEntryFormat::WebVH10 => LogParameters::new_webvh(
                None,
                None,
                Some(vec![new_authorized_multikey.into()]),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ),
        };

        let new_doc = DIDDoc::new_genesis(did, new_authentication, new_assertion);
        let state = DIDDocState::Value(Value::from(new_doc));

        match format {
            LogEntryFormat::TDW03 => Self::new_tdw(
                prev_version_id.into(),
                new_version_time.into(),
                parameters,
                state,
                vec![],
            ),
            LogEntryFormat::WebVH10 => Self::new_webvh(
                prev_version_id.into(),
                new_version_time.into(),
                parameters,
                state,
                vec![],
            ),
        }
    }

    fn try_from_json_array(v: &Value) -> DIDLogResult<Self> {
        let arr = v.as_array().unwrap(); // caller verified v.is_array()
        if arr.len() != 5 {
            return Err(DIDLogError::InvalidFormat(format!(
                "v0.3 log entry must have exactly 5 elements, got {}",
                arr.len()
            )));
        }

        let version_id = arr[0]
            .as_str()
            .ok_or_else(|| DIDLogError::InvalidFieldType("versionId must be a string".into()))?
            .to_string();

        let version_time = arr[1]
            .as_str()
            .ok_or_else(|| DIDLogError::InvalidFieldType("versionTime must be a string".into()))?
            .to_string();

        let parameters = LogParameters::try_from_json(&arr[2], LogEntryFormat::TDW03)?;
        let did_doc_state = DIDDocState::try_from_json(&arr[3])?;

        let data_integrity_proofs = arr[4]
            .as_array()
            .ok_or_else(|| {
                DIDLogError::InvalidFieldType("DataIntegrityProof must be a JSON array".into())
            })?
            .clone();

        Ok(Self {
            format: LogEntryFormat::TDW03,
            version_id,
            version_time,
            parameters,
            did_doc_state,
            data_integrity_proofs,
        })
    }

    fn try_from_json_object(v: &Value) -> DIDLogResult<Self> {
        let obj = v.as_object().unwrap(); // caller verified v.is_object()

        let version_id = string_field(obj, "versionId")?
            .ok_or_else(|| DIDLogError::MissingField("versionId".into()))?;

        let version_time = string_field(obj, "versionTime")?
            .ok_or_else(|| DIDLogError::MissingField("versionTime".into()))?;

        let parameters = LogParameters::try_from_json(
            obj.get("parameters")
                .ok_or_else(|| DIDLogError::MissingField("parameters".into()))?,
            LogEntryFormat::WebVH10,
        )?;

        let did_doc_state = DIDDocState::try_from_json(
            obj.get("state")
                .ok_or_else(|| DIDLogError::MissingField("state".into()))?,
        )?;

        let data_integrity_proofs = obj
            .get("proof")
            .ok_or_else(|| DIDLogError::MissingField("proof".into()))?
            .as_array()
            .ok_or_else(|| DIDLogError::InvalidFieldType("proof must be a JSON array".into()))?
            .clone();

        Ok(Self {
            format: LogEntryFormat::WebVH10,
            version_id,
            version_time,
            parameters,
            did_doc_state,
            data_integrity_proofs,
        })
    }

    pub fn format(&self) -> &LogEntryFormat {
        &self.format
    }

    pub fn version_id(&self) -> &str {
        &self.version_id
    }

    pub fn version_time(&self) -> &str {
        &self.version_time
    }

    pub fn parameters(&self) -> &LogParameters {
        &self.parameters
    }

    pub fn did_doc_state(&self) -> &DIDDocState {
        &self.did_doc_state
    }

    pub fn data_integrity_proofs(&self) -> &[Value] {
        &self.data_integrity_proofs
    }
}

impl From<DIDLogEntry> for Value {
    fn from(entry: DIDLogEntry) -> Self {
        match entry.format {
            LogEntryFormat::TDW03 => json!([
                entry.version_id,
                entry.version_time,
                entry.parameters.to_json(),
                entry.did_doc_state.to_json(),
                entry.data_integrity_proofs,
            ]),
            LogEntryFormat::WebVH10 => {
                let mut map = Map::new();
                map.insert("versionId".into(), Value::String(entry.version_id));
                map.insert("versionTime".into(), Value::String(entry.version_time));
                map.insert("parameters".into(), entry.parameters.to_json());
                map.insert("state".into(), entry.did_doc_state.to_json());
                map.insert("proof".into(), Value::Array(entry.data_integrity_proofs));
                Value::Object(map)
            }
        }
    }
}

impl TryFrom<&Value> for DIDLogEntry {
    type Error = DIDLogError;

    fn try_from(v: &Value) -> Result<Self, Self::Error> {
        if v.is_array() {
            Self::try_from_json_array(v)
        } else if v.is_object() {
            Self::try_from_json_object(v)
        } else {
            Err(DIDLogError::InvalidFormat(
                "log entry must be a JSON array (v0.3) or object (v1.0)".into(),
            ))
        }
    }
}

/// The full DID log: a sequential list of log entries stored as JSON Lines (did.jsonl).
#[derive(Debug)]
pub struct DIDLog {
    entries: Vec<DIDLogEntry>,
}

impl DIDLog {
    pub fn new(entries: Vec<DIDLogEntry>) -> Self {
        Self { entries }
    }

    pub fn entries(&self) -> &[DIDLogEntry] {
        &self.entries
    }

    /// Consumes the log and returns its owned entries. Mirrors
    /// `String::into_bytes` / `Vec::into_boxed_slice`. Useful when a
    /// caller needs `Vec<DIDLogEntry>` rather than the borrow that
    /// [`Self::entries`] hands out — for example, an HTTP-client
    /// adapter that parses the JSONL body and surfaces a typed
    /// entry list to its own callers.
    pub fn into_entries(self) -> Vec<DIDLogEntry> {
        self.entries
    }

    /// Parses a DID log from JSONL text.
    ///
    /// Blank lines are skipped. Each line must be a single JSON value that parses via
    /// the `TryFrom<&Value> for DIDLogEntry` impl; on failure, the 1-based line number
    /// is included in the error message.
    pub fn try_from_jsonl(text: &str) -> DIDLogResult<Self> {
        let mut entries = Vec::new();
        for (i, line) in text.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let v: Value = serde_json::from_str(trimmed)
                .map_err(|e| DIDLogError::InvalidFormat(format!("line {}: {}", i + 1, e)))?;
            let entry = DIDLogEntry::try_from(&v).map_err(|e| match e {
                DIDLogError::InvalidFormat(m) => {
                    DIDLogError::InvalidFormat(format!("line {}: {}", i + 1, m))
                }
                DIDLogError::MissingField(f) => {
                    DIDLogError::InvalidFormat(format!("line {}: missing field '{}'", i + 1, f))
                }
                DIDLogError::InvalidFieldType(m) => {
                    DIDLogError::InvalidFormat(format!("line {}: {}", i + 1, m))
                }
            })?;
            entries.push(entry);
        }
        Ok(DIDLog { entries })
    }
}

/// Computes the hash input for an `eddsa-jcs-2022` data integrity proof.
///
/// Returns 64 bytes: SHA-256 of the JCS-canonicalised `proof_config` (the proof options without
/// `proofValue`) followed by SHA-256 of the JCS-canonicalised `document` (the entry without the
/// `proof` field). The caller signs this value with the authorised Ed25519 key.
///
/// Follows the hashing algorithm defined in the
/// [VC Data Integrity EdDSA Cryptosuites](https://www.w3.org/TR/vc-di-eddsa/) specification.
pub fn eddsa_jcs_2022_hash(document: &Value, proof_config: &Value) -> [u8; 64] {
    let proof_bytes = serde_jcs::to_vec(proof_config).expect("proof config is serialisable");
    let doc_bytes = serde_jcs::to_vec(document).expect("document is serialisable");
    let proof_hash = Code::Sha2_256.digest(&proof_bytes);
    let doc_hash = Code::Sha2_256.digest(&doc_bytes);
    let mut result = [0u8; 64];
    result[..32].copy_from_slice(proof_hash.digest());
    result[32..].copy_from_slice(doc_hash.digest());
    result
}

// --- helpers for parsing optional typed fields from a JSON object ---

fn string_field(obj: &Map<String, Value>, key: &str) -> DIDLogResult<Option<String>> {
    match obj.get(key) {
        None => Ok(None),
        Some(v) => v
            .as_str()
            .map(|s| Some(s.to_string()))
            .ok_or_else(|| DIDLogError::InvalidFieldType(format!("'{key}' must be a string"))),
    }
}

fn bool_field(obj: &Map<String, Value>, key: &str) -> DIDLogResult<Option<bool>> {
    match obj.get(key) {
        None => Ok(None),
        Some(v) => v
            .as_bool()
            .map(Some)
            .ok_or_else(|| DIDLogError::InvalidFieldType(format!("'{key}' must be a boolean"))),
    }
}

fn u64_field(obj: &Map<String, Value>, key: &str) -> DIDLogResult<Option<u64>> {
    match obj.get(key) {
        None => Ok(None),
        Some(v) => v
            .as_u64()
            .map(Some)
            .ok_or_else(|| DIDLogError::InvalidFieldType(format!("'{key}' must be a number"))),
    }
}

fn string_array_field(obj: &Map<String, Value>, key: &str) -> DIDLogResult<Option<Vec<String>>> {
    let arr = match obj.get(key) {
        None => return Ok(None),
        Some(v) => v
            .as_array()
            .ok_or_else(|| DIDLogError::InvalidFieldType(format!("'{key}' must be an array")))?,
    };
    let strings = arr
        .iter()
        .map(|v| {
            v.as_str().map(|s| s.to_string()).ok_or_else(|| {
                DIDLogError::InvalidFieldType(format!("'{key}' elements must be strings"))
            })
        })
        .collect::<DIDLogResult<Vec<_>>>()?;
    Ok(Some(strings))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture_p256() -> P256PublicKey {
        P256PublicKey {
            x: [1u8; 32],
            y: [2u8; 32],
        }
    }

    #[test]
    fn new_genesis_tdw_carries_scid_placeholder() {
        let entry = DIDLogEntry::new_genesis(
            &LogEntryFormat::TDW03,
            "z6Mk-authorized",
            "did:tdw:example.com:{SCID}",
            &fixture_p256(),
            &fixture_p256(),
            "2026-05-03T12:00:00Z",
        );
        let value = Value::from(entry);
        assert_eq!(value[0], "{SCID}");
        assert_eq!(value[1], "2026-05-03T12:00:00Z");
    }

    #[test]
    fn new_genesis_webvh_carries_scid_placeholder() {
        let entry = DIDLogEntry::new_genesis(
            &LogEntryFormat::WebVH10,
            "z6Mk-authorized",
            "did:webvh:example.com:{SCID}",
            &fixture_p256(),
            &fixture_p256(),
            "2026-05-03T12:00:00Z",
        );
        let value = Value::from(entry);
        assert_eq!(value["versionId"], "{SCID}");
        assert_eq!(value["versionTime"], "2026-05-03T12:00:00Z");
    }

    fn fixture_did_doc() -> DIDDoc {
        DIDDoc::new_genesis("did:tdw:example.com:abc", &fixture_p256(), &fixture_p256())
    }

    #[test]
    fn new_deactivation_tdw_carries_prev_version_id() {
        let entry = DIDLogEntry::new_deactivation(
            &LogEntryFormat::TDW03,
            "1-QmPrevHash",
            &fixture_did_doc(),
            "2026-05-04T09:00:00Z",
        );
        let value = Value::from(entry);
        assert_eq!(value[0], "1-QmPrevHash");
        assert_eq!(value[1], "2026-05-04T09:00:00Z");
    }

    #[test]
    fn new_deactivation_tdw_parameters_hold_only_deactivated_and_empty_update_keys() {
        let entry = DIDLogEntry::new_deactivation(
            &LogEntryFormat::TDW03,
            "1-QmPrevHash",
            &fixture_did_doc(),
            "2026-05-04T09:00:00Z",
        );
        let value = Value::from(entry);
        let params = value[2].as_object().expect("parameters must be an object");
        assert_eq!(params["deactivated"], json!(true));
        assert_eq!(params["updateKeys"], json!([]));
        // No genesis-only fields leak in: method, scid, portable, etc.
        assert!(!params.contains_key("method"));
        assert!(!params.contains_key("scid"));
        assert!(!params.contains_key("portable"));
    }

    #[test]
    fn new_deactivation_tdw_carries_prev_did_doc_unchanged() {
        let prev = fixture_did_doc();
        let entry = DIDLogEntry::new_deactivation(
            &LogEntryFormat::TDW03,
            "1-QmPrevHash",
            &prev,
            "2026-05-04T09:00:00Z",
        );
        let value = Value::from(entry);
        assert_eq!(value[3]["value"], Value::from(prev));
    }

    #[test]
    fn new_deactivation_tdw_has_no_proofs() {
        let entry = DIDLogEntry::new_deactivation(
            &LogEntryFormat::TDW03,
            "1-QmPrevHash",
            &fixture_did_doc(),
            "2026-05-04T09:00:00Z",
        );
        let value = Value::from(entry);
        assert_eq!(value[4], json!([]));
    }

    #[test]
    fn new_deactivation_webvh_carries_prev_version_id() {
        let entry = DIDLogEntry::new_deactivation(
            &LogEntryFormat::WebVH10,
            "1-QmPrevHash",
            &fixture_did_doc(),
            "2026-05-04T09:00:00Z",
        );
        let value = Value::from(entry);
        assert_eq!(value["versionId"], "1-QmPrevHash");
        assert_eq!(value["versionTime"], "2026-05-04T09:00:00Z");
        let params = value["parameters"]
            .as_object()
            .expect("parameters must be an object");
        assert_eq!(params["deactivated"], json!(true));
        assert_eq!(params["updateKeys"], json!([]));
        assert!(!params.contains_key("method"));
        assert_eq!(value["proof"], json!([]));
    }

    #[test]
    fn new_rotation_tdw_carries_prev_version_id() {
        let entry = DIDLogEntry::new_rotation(
            &LogEntryFormat::TDW03,
            "2-QmPrevHash",
            "did:tdw:example.com:abc",
            "z6Mk-new-authorized",
            &fixture_p256(),
            &fixture_p256(),
            "2026-05-04T09:00:00Z",
        );
        let value = Value::from(entry);
        assert_eq!(value[0], "2-QmPrevHash");
        assert_eq!(value[1], "2026-05-04T09:00:00Z");
    }

    #[test]
    fn new_rotation_tdw_parameters_hold_only_new_update_keys() {
        let entry = DIDLogEntry::new_rotation(
            &LogEntryFormat::TDW03,
            "2-QmPrevHash",
            "did:tdw:example.com:abc",
            "z6Mk-new-authorized",
            &fixture_p256(),
            &fixture_p256(),
            "2026-05-04T09:00:00Z",
        );
        let value = Value::from(entry);
        let params = value[2].as_object().expect("parameters must be an object");
        assert_eq!(params["updateKeys"], json!(["z6Mk-new-authorized"]));
        // No genesis-only or deactivation-only fields leak in.
        assert!(!params.contains_key("method"));
        assert!(!params.contains_key("scid"));
        assert!(!params.contains_key("portable"));
        assert!(!params.contains_key("deactivated"));
    }

    #[test]
    fn new_rotation_tdw_did_doc_carries_supplied_did_id() {
        let entry = DIDLogEntry::new_rotation(
            &LogEntryFormat::TDW03,
            "2-QmPrevHash",
            "did:tdw:example.com:abc",
            "z6Mk-new-authorized",
            &fixture_p256(),
            &fixture_p256(),
            "2026-05-04T09:00:00Z",
        );
        let value = Value::from(entry);
        assert_eq!(value[3]["value"]["id"], "did:tdw:example.com:abc");
    }

    #[test]
    fn new_rotation_tdw_has_no_proofs() {
        let entry = DIDLogEntry::new_rotation(
            &LogEntryFormat::TDW03,
            "2-QmPrevHash",
            "did:tdw:example.com:abc",
            "z6Mk-new-authorized",
            &fixture_p256(),
            &fixture_p256(),
            "2026-05-04T09:00:00Z",
        );
        let value = Value::from(entry);
        assert_eq!(value[4], json!([]));
    }

    #[test]
    fn new_rotation_webvh_carries_prev_version_id() {
        let entry = DIDLogEntry::new_rotation(
            &LogEntryFormat::WebVH10,
            "2-QmPrevHash",
            "did:webvh:example.com:abc",
            "z6Mk-new-authorized",
            &fixture_p256(),
            &fixture_p256(),
            "2026-05-04T09:00:00Z",
        );
        let value = Value::from(entry);
        assert_eq!(value["versionId"], "2-QmPrevHash");
        assert_eq!(value["versionTime"], "2026-05-04T09:00:00Z");
        let params = value["parameters"]
            .as_object()
            .expect("parameters must be an object");
        assert_eq!(params["updateKeys"], json!(["z6Mk-new-authorized"]));
        assert!(!params.contains_key("method"));
        assert!(!params.contains_key("deactivated"));
        assert_eq!(value["proof"], json!([]));
    }

    fn tdw_genesis_with_portable(portable: Option<bool>) -> LogParameters {
        let mut params = LogParameters::new_tdw(
            Some("did:tdw:0.3".into()),
            Some("Qm-scid".into()),
            Some(vec!["z6Mk-auth".into()]),
            None,
            None,
            portable,
            None,
            None,
            None,
        );
        // scid being Some marks this as a genesis entry, which is what
        // drives the to_json portable rule. Use a non-genesis fixture by
        // clearing scid below in the relevant tests.
        params.scid = Some("Qm-scid".into());
        params
    }

    #[test]
    fn tdw_genesis_to_json_emits_portable_false_when_unset() {
        let params = tdw_genesis_with_portable(None);
        let value = params.to_json();
        assert_eq!(value["portable"], json!(false));
    }

    #[test]
    fn tdw_genesis_to_json_preserves_explicit_portable() {
        let params = tdw_genesis_with_portable(Some(true));
        let value = params.to_json();
        assert_eq!(value["portable"], json!(true));
    }

    #[test]
    fn tdw_subsequent_to_json_omits_portable_when_unset() {
        let mut params = tdw_genesis_with_portable(None);
        params.scid = None;
        params.method = None;
        let value = params.to_json();
        assert!(value.as_object().unwrap().get("portable").is_none());
    }

    #[test]
    fn webvh_genesis_to_json_omits_portable_when_unset() {
        let params = LogParameters::new_webvh(
            Some("did:webvh:1.0".into()),
            Some("Qm-scid".into()),
            Some(vec!["z6Mk-auth".into()]),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let value = params.to_json();
        assert!(value.as_object().unwrap().get("portable").is_none());
    }

    fn tdw_entry_json() -> Value {
        json!([
            "1-QmdwvukAYUU6VYwqM4jQbSiKk1ctg12j5hMTY6EfbbkyEJ",
            "2024-07-29T17:00:27Z",
            {
                "method": "did:tdw:0.3",
                "scid": "QmZz",
                "updateKeys": ["z6Mk..."],
                "prerotation": false,
                "portable": true
            },
            {
                "value": {
                    "id": "did:tdw:QmZz:example.com",
                    "@context": ["https://www.w3.org/ns/did/v1"]
                }
            },
            [
                { "type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022" }
            ]
        ])
    }

    fn webvh_entry_json() -> Value {
        json!({
            "versionId": "1-QmdwvukAYUU6VYwqM4jQbSiKk1ctg12j5hMTY6EfbbkyEJ",
            "versionTime": "2024-07-29T17:00:27Z",
            "parameters": {
                "method": "did:webvh:1.0",
                "scid": "QmZz",
                "updateKeys": ["z6Mk..."],
                "prerotation": false,
                "portable": true,
                "watchers": ["https://watcher.example.com/"]
            },
            "state": {
                "value": {
                    "id": "did:webvh:QmZz:example.com",
                    "@context": ["https://www.w3.org/ns/did/v1"]
                }
            },
            "proof": [
                { "type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "proofPurpose": "assertionMethod" }
            ]
        })
    }

    #[test]
    fn parse_tdw_entry() {
        let entry = DIDLogEntry::try_from(&tdw_entry_json()).unwrap();
        assert_eq!(entry.format(), &LogEntryFormat::TDW03);
        assert_eq!(
            entry.version_id(),
            "1-QmdwvukAYUU6VYwqM4jQbSiKk1ctg12j5hMTY6EfbbkyEJ"
        );
        assert_eq!(entry.version_time(), "2024-07-29T17:00:27Z");
        assert_eq!(entry.parameters().method(), Some("did:tdw:0.3"));
        assert_eq!(entry.parameters().scid(), Some("QmZz"));
        assert_eq!(entry.parameters().prerotation(), Some(false));
        assert_eq!(entry.parameters().portable(), Some(true));
        assert_eq!(entry.parameters().watchers(), None);
        assert_eq!(entry.data_integrity_proofs().len(), 1);
    }

    #[test]
    fn parse_webvh_entry() {
        let entry = DIDLogEntry::try_from(&webvh_entry_json()).unwrap();
        assert_eq!(entry.format(), &LogEntryFormat::WebVH10);
        assert_eq!(
            entry.version_id(),
            "1-QmdwvukAYUU6VYwqM4jQbSiKk1ctg12j5hMTY6EfbbkyEJ"
        );
        assert_eq!(entry.version_time(), "2024-07-29T17:00:27Z");
        assert_eq!(entry.parameters().method(), Some("did:webvh:1.0"));
        assert_eq!(
            entry.parameters().watchers(),
            Some(&[String::from("https://watcher.example.com/")][..])
        );
        assert_eq!(entry.data_integrity_proofs().len(), 1);
    }

    #[test]
    fn roundtrip_tdw() {
        let original = tdw_entry_json();
        let entry = DIDLogEntry::try_from(&original).unwrap();
        assert_eq!(Value::from(entry), original);
    }

    #[test]
    fn roundtrip_webvh() {
        let original = webvh_entry_json();
        let entry = DIDLogEntry::try_from(&original).unwrap();
        assert_eq!(Value::from(entry), original);
    }

    #[test]
    fn tdw_does_not_emit_watchers() {
        // watchers must not appear in v0.3 output even if the struct field were set
        let entry = DIDLogEntry::try_from(&tdw_entry_json()).unwrap();
        let json = Value::from(entry);
        let params = &json.as_array().unwrap()[2];
        assert!(params.get("watchers").is_none());
    }

    #[test]
    fn parse_tdw_entry_with_patch() {
        let v = json!([
            "2-Qm...",
            "2024-07-30T10:00:00Z",
            {},
            { "patch": [{ "op": "add", "path": "/service", "value": [] }] },
            []
        ]);
        let entry = DIDLogEntry::try_from(&v).unwrap();
        assert!(matches!(entry.did_doc_state(), DIDDocState::Patch(_)));
    }

    #[test]
    fn parse_wrong_element_count() {
        let v = json!(["a", "b", {}, {}]);
        assert!(matches!(
            DIDLogEntry::try_from(&v).unwrap_err(),
            DIDLogError::InvalidFormat(_)
        ));
    }

    #[test]
    fn parse_not_array_or_object() {
        let v = json!("a string");
        assert!(matches!(
            DIDLogEntry::try_from(&v).unwrap_err(),
            DIDLogError::InvalidFormat(_)
        ));
    }

    #[test]
    fn parse_webvh_missing_field() {
        let v = json!({
            "versionId": "1-Qm",
            "versionTime": "2024-07-29T17:00:27Z",
            "parameters": {}
            // "state" and "proof" missing
        });
        assert!(matches!(
            DIDLogEntry::try_from(&v).unwrap_err(),
            DIDLogError::MissingField(_)
        ));
    }

    #[test]
    fn eddsa_jcs_2022_hash_structure() {
        let doc = json!({"id": "did:example:123", "b": 2, "a": 1});
        let proof_config = json!({"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022"});

        let result = eddsa_jcs_2022_hash(&doc, &proof_config);

        let expected_proof_hash = Code::Sha2_256
            .digest(&serde_jcs::to_vec(&proof_config).unwrap())
            .digest()
            .to_vec();
        let expected_doc_hash = Code::Sha2_256
            .digest(&serde_jcs::to_vec(&doc).unwrap())
            .digest()
            .to_vec();

        assert_eq!(&result[..32], expected_proof_hash.as_slice());
        assert_eq!(&result[32..], expected_doc_hash.as_slice());
    }

    #[test]
    fn eddsa_jcs_2022_hash_is_key_order_independent() {
        let doc_a = json!({"b": 2, "a": 1});
        let doc_b = json!({"a": 1, "b": 2});
        let proof_config = json!({"type": "DataIntegrityProof"});

        assert_eq!(
            eddsa_jcs_2022_hash(&doc_a, &proof_config),
            eddsa_jcs_2022_hash(&doc_b, &proof_config),
        );
    }

    #[test]
    fn log_entries_getter() {
        let entry = DIDLogEntry::try_from(&tdw_entry_json()).unwrap();
        let log = DIDLog::new(vec![entry]);
        assert_eq!(log.entries().len(), 1);
        assert_eq!(
            log.entries()[0].version_id(),
            "1-QmdwvukAYUU6VYwqM4jQbSiKk1ctg12j5hMTY6EfbbkyEJ"
        );
    }

    #[test]
    fn try_from_jsonl_parses_tdw_entries() {
        let line = serde_json::to_string(&tdw_entry_json()).unwrap();
        let text = format!("{line}\n{line}\n");
        let log = DIDLog::try_from_jsonl(&text).unwrap();
        assert_eq!(log.entries().len(), 2);
    }

    #[test]
    fn try_from_jsonl_skips_blank_lines() {
        let line = serde_json::to_string(&webvh_entry_json()).unwrap();
        let text = format!("\n{line}\n\n{line}\n  \n");
        let log = DIDLog::try_from_jsonl(&text).unwrap();
        assert_eq!(log.entries().len(), 2);
    }

    #[test]
    fn try_from_jsonl_reports_line_number_on_invalid_json() {
        let line = serde_json::to_string(&tdw_entry_json()).unwrap();
        let text = format!("{line}\nthis is not json\n");
        let err = DIDLog::try_from_jsonl(&text).unwrap_err();
        match err {
            DIDLogError::InvalidFormat(msg) => assert!(msg.contains("line 2")),
            other => panic!("expected InvalidFormat, got {other:?}"),
        }
    }

    #[test]
    fn try_from_jsonl_reports_line_number_on_invalid_entry() {
        let text = "[\"1-x\", \"2024-01-01T00:00:00Z\"]\n";
        let err = DIDLog::try_from_jsonl(text).unwrap_err();
        match err {
            DIDLogError::InvalidFormat(msg) => assert!(msg.contains("line 1")),
            other => panic!("expected InvalidFormat, got {other:?}"),
        }
    }

    #[test]
    fn into_entries_returns_owned_vec() {
        let line = serde_json::to_string(&tdw_entry_json()).unwrap();
        let text = format!("{line}\n{line}\n");
        let log = DIDLog::try_from_jsonl(&text).unwrap();
        let entries = log.into_entries();
        assert_eq!(entries.len(), 2);
    }
}
