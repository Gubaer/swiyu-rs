pub mod scid;

use serde_json::{json, Map, Value};
use std::fmt;

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

/// The state of the DID document in a log entry — either a full replacement or an incremental patch.
#[derive(Debug)]
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
#[derive(Debug)]
pub struct LogParameters {
    method: Option<String>,
    scid: Option<String>,
    update_keys: Option<Vec<String>>,
    prerotation: Option<bool>,
    next_key_hashes: Option<Vec<String>>,
    portable: Option<bool>,
    deactivated: Option<bool>,
    ttl: Option<u64>,
    witness: Option<Value>,
}

impl LogParameters {
    // The parameters object in the did:tdw spec has this many fields by design.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
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
            method,
            scid,
            update_keys,
            prerotation,
            next_key_hashes,
            portable,
            deactivated,
            ttl,
            witness,
        }
    }

    fn try_from_json(v: &Value) -> DIDLogResult<Self> {
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

        Ok(Self {
            method,
            scid,
            update_keys,
            prerotation,
            next_key_hashes,
            portable,
            deactivated,
            ttl,
            witness,
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
        if let Some(v) = self.portable {
            map.insert("portable".into(), json!(v));
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
        Value::Object(map)
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
}

// A single entry in the DID log. The wire format is a 5-element JSON array:
// [versionId, versionTime, parameters, didDocState, proofs]
#[derive(Debug)]
pub struct DIDTDWLogEntry {
    version_id: String,
    version_time: String,
    parameters: LogParameters,
    did_doc_state: DIDDocState,
    data_integrity_proofs: Vec<Value>,
}

impl DIDTDWLogEntry {
    pub fn new(
        version_id: String,
        version_time: String,
        parameters: LogParameters,
        did_doc_state: DIDDocState,
        data_integrity_proofs: Vec<Value>,
    ) -> Self {
        Self {
            version_id,
            version_time,
            parameters,
            did_doc_state,
            data_integrity_proofs,
        }
    }

    pub fn try_from_json(v: &Value) -> DIDLogResult<Self> {
        let arr = v.as_array().ok_or_else(|| {
            DIDLogError::InvalidFormat("log entry must be a JSON array".into())
        })?;
        if arr.len() != 5 {
            return Err(DIDLogError::InvalidFormat(format!(
                "log entry must have exactly 5 elements, got {}",
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

        let parameters = LogParameters::try_from_json(&arr[2])?;
        let did_doc_state = DIDDocState::try_from_json(&arr[3])?;

        let data_integrity_proofs = arr[4]
            .as_array()
            .ok_or_else(|| {
                DIDLogError::InvalidFieldType("data integrity proofs must be a JSON array".into())
            })?
            .clone();

        Ok(Self { version_id, version_time, parameters, did_doc_state, data_integrity_proofs })
    }

    pub fn to_json(&self) -> Value {
        json!([
            self.version_id,
            self.version_time,
            self.parameters.to_json(),
            self.did_doc_state.to_json(),
            self.data_integrity_proofs,
        ])
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

/// The full DID log: a sequential list of log entries stored as JSON Lines (did.jsonl).
#[derive(Debug)]
pub struct DIDTDWLog {
    entries: Vec<DIDTDWLogEntry>,
}

impl DIDTDWLog {
    pub fn new(entries: Vec<DIDTDWLogEntry>) -> Self {
        Self { entries }
    }

    pub fn entries(&self) -> &[DIDTDWLogEntry] {
        &self.entries
    }
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
        Some(v) => v.as_array().ok_or_else(|| {
            DIDLogError::InvalidFieldType(format!("'{key}' must be an array"))
        })?,
    };
    let strings = arr
        .iter()
        .map(|v| {
            v.as_str()
                .map(|s| s.to_string())
                .ok_or_else(|| DIDLogError::InvalidFieldType(format!("'{key}' elements must be strings")))
        })
        .collect::<DIDLogResult<Vec<_>>>()?;
    Ok(Some(strings))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_entry_json() -> Value {
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

    #[test]
    fn parse_entry() {
        let entry = DIDTDWLogEntry::try_from_json(&sample_entry_json()).unwrap();
        assert_eq!(entry.version_id(), "1-QmdwvukAYUU6VYwqM4jQbSiKk1ctg12j5hMTY6EfbbkyEJ");
        assert_eq!(entry.version_time(), "2024-07-29T17:00:27Z");
        assert_eq!(entry.parameters().method(), Some("did:tdw:0.3"));
        assert_eq!(entry.parameters().scid(), Some("QmZz"));
        assert_eq!(entry.parameters().prerotation(), Some(false));
        assert_eq!(entry.parameters().portable(), Some(true));
        assert_eq!(entry.data_integrity_proofs().len(), 1);
    }

    #[test]
    fn parse_entry_with_patch() {
        let v = json!([
            "2-Qm...",
            "2024-07-30T10:00:00Z",
            {},
            { "patch": [{ "op": "add", "path": "/service", "value": [] }] },
            []
        ]);
        let entry = DIDTDWLogEntry::try_from_json(&v).unwrap();
        assert!(matches!(entry.did_doc_state(), DIDDocState::Patch(_)));
    }

    #[test]
    fn roundtrip_to_json() {
        let original = sample_entry_json();
        let entry = DIDTDWLogEntry::try_from_json(&original).unwrap();
        assert_eq!(entry.to_json(), original);
    }

    #[test]
    fn parse_wrong_element_count() {
        let v = json!(["a", "b", {}, {}]);
        assert!(matches!(
            DIDTDWLogEntry::try_from_json(&v).unwrap_err(),
            DIDLogError::InvalidFormat(_)
        ));
    }

    #[test]
    fn parse_not_array() {
        let v = json!({ "versionId": "1-Qm" });
        assert!(matches!(
            DIDTDWLogEntry::try_from_json(&v).unwrap_err(),
            DIDLogError::InvalidFormat(_)
        ));
    }

    #[test]
    fn log_entries_getter() {
        let entry = DIDTDWLogEntry::try_from_json(&sample_entry_json()).unwrap();
        let log = DIDTDWLog::new(vec![entry]);
        assert_eq!(log.entries().len(), 1);
        assert_eq!(
            log.entries()[0].version_id(),
            "1-QmdwvukAYUU6VYwqM4jQbSiKk1ctg12j5hMTY6EfbbkyEJ"
        );
    }
}
