//! Small mutators that edit a serialised DID log entry in place
//! during the SCID/entry-hash/proof derivation pipeline.
//!
//! They operate on `serde_json::Value` rather than the typed
//! `DIDLogEntry` because the pipeline is bytes-sensitive: the SCID
//! is derived by string-replacing `{SCID}` in the JSON text, the
//! entry hash is computed over a specific serialised form, and the
//! proof signs over a serialised view of the document. Going
//! through the typed model would invalidate any hash already
//! computed over a prior form.
//!
//! Pure: no I/O, no async, no dependence on any specific keystore.
//! Callers — `swiyu-didtool` for CLI flows, `swiyu-issuer` for the
//! issuer-management task flow — splice these in between the
//! typed `DIDLogEntry::new_genesis` constructor and the final
//! serialised entry.

use serde_json::{Value, json};

use super::LogEntryFormat;

/// Removes the proof slot from a serialised entry so the SCID and
/// entryHash can be computed over the four-element preliminary form.
///
/// Both formats follow the same convention: `did:tdw` 0.3 stores the
/// proof as the trailing element of a five-element JSON array;
/// `did:webvh` 1.0 carries it as the `proof` field of the entry object.
pub fn strip_proof_slot(entry: &mut Value, format: &LogEntryFormat) {
    match format {
        LogEntryFormat::TDW03 => {
            if let Some(arr) = entry.as_array_mut() {
                arr.pop();
            }
        }
        LogEntryFormat::WebVH10 => {
            if let Some(obj) = entry.as_object_mut() {
                obj.remove("proof");
            }
        }
    }
}

/// Sets the `versionId` of a serialised entry. For `did:tdw` 0.3 the
/// `versionId` is the first element of the JSON array; for `did:webvh`
/// 1.0 it is the `versionId` field of the entry object.
pub fn set_version_id(entry: &mut Value, version_id: &str, format: &LogEntryFormat) {
    match format {
        LogEntryFormat::TDW03 => {
            if let Some(arr) = entry.as_array_mut()
                && let Some(slot) = arr.first_mut()
            {
                *slot = json!(version_id);
            }
        }
        LogEntryFormat::WebVH10 => {
            if let Some(obj) = entry.as_object_mut() {
                obj.insert("versionId".into(), json!(version_id));
            }
        }
    }
}

/// Appends a Data Integrity proof to a serialised entry. The proof
/// arrives as a single object; both formats wrap it in a one-element
/// JSON array per the cryptosuite convention.
pub fn append_proof(entry: &mut Value, proof: Value, format: &LogEntryFormat) {
    match format {
        LogEntryFormat::TDW03 => {
            if let Some(arr) = entry.as_array_mut() {
                arr.push(json!([proof]));
            }
        }
        LogEntryFormat::WebVH10 => {
            if let Some(obj) = entry.as_object_mut() {
                obj.insert("proof".into(), json!([proof]));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_proof_slot_drops_array_tail_for_tdw() {
        let mut entry = json!(["v1", "now", {}, {"value": {}}, [{"proofValue": "..."}]]);
        strip_proof_slot(&mut entry, &LogEntryFormat::TDW03);
        let arr = entry.as_array().unwrap();
        assert_eq!(arr.len(), 4);
    }

    #[test]
    fn strip_proof_slot_removes_proof_field_for_webvh() {
        let mut entry = json!({"versionId": "v1", "proof": [{"proofValue": "..."}]});
        strip_proof_slot(&mut entry, &LogEntryFormat::WebVH10);
        assert!(entry.as_object().unwrap().get("proof").is_none());
        assert_eq!(entry["versionId"], "v1");
    }

    #[test]
    fn set_version_id_replaces_placeholder_in_tdw() {
        let mut entry = json!(["{SCID}", "now", {}, {"value": {}}]);
        set_version_id(&mut entry, "1-abcdef", &LogEntryFormat::TDW03);
        assert_eq!(entry[0], "1-abcdef");
    }

    #[test]
    fn set_version_id_writes_field_in_webvh() {
        let mut entry = json!({"versionId": "{SCID}"});
        set_version_id(&mut entry, "1-abcdef", &LogEntryFormat::WebVH10);
        assert_eq!(entry["versionId"], "1-abcdef");
    }

    #[test]
    fn append_proof_adds_array_element_for_tdw() {
        let mut entry = json!(["v1", "now", {}, {"value": {}}]);
        let proof = json!({"proofValue": "..."});
        append_proof(&mut entry, proof, &LogEntryFormat::TDW03);
        let arr = entry.as_array().unwrap();
        assert_eq!(arr.len(), 5);
        assert!(arr[4].is_array());
    }

    #[test]
    fn append_proof_adds_proof_field_for_webvh() {
        let mut entry = json!({"versionId": "v1"});
        let proof = json!({"proofValue": "..."});
        append_proof(&mut entry, proof, &LogEntryFormat::WebVH10);
        assert!(entry["proof"].is_array());
        assert_eq!(entry["proof"][0]["proofValue"], "...");
    }
}
