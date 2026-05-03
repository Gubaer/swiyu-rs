//! Builders that construct DID log entries from raw key material.
//!
//! These functions are pure: no I/O, no async, no dependence on any
//! specific keystore. They produce the entry skeletons and the small
//! mutators (set version id, append proof, strip proof slot) that
//! callers — `swiyu-didtool` for CLI flows, `swiyu-issuer` for the
//! issuer-management task flow — splice into during the multi-step
//! process of deriving the SCID, the entry hash, and the proof.

use serde_json::{Value, json};

use super::{DIDDocState, DIDLogEntry, LogEntryFormat, LogParameters};
use crate::diddoc::builder::build_initial_did_doc;

/// Constructs the genesis DID log entry, with `{SCID}` placeholders
/// in `versionId` and any embedded DID strings. Callers compute the
/// SCID from this preliminary entry, substitute the placeholders,
/// then compute the entryHash and append the proof.
///
/// Takes the authentication and assertion public keys as P-256 (x, y)
/// coordinates and the authorized public key as its multikey string;
/// the caller is responsible for converting from whatever keystore
/// shape they use.
pub fn build_initial_entry(
    format: &LogEntryFormat,
    authorized_multikey: &str,
    did_placeholder: &str,
    authentication_xy: &([u8; 32], [u8; 32]),
    assertion_xy: &([u8; 32], [u8; 32]),
    now: &str,
) -> DIDLogEntry {
    let method_str = match format {
        LogEntryFormat::TDW03 => "did:tdw:0.3",
        LogEntryFormat::WebVH10 => "did:webvh:1.0",
    };

    let parameters = match format {
        LogEntryFormat::TDW03 => LogParameters::new_tdw(
            Some(method_str.into()),
            Some("{SCID}".into()),
            Some(vec![authorized_multikey.into()]),
            None,        // prerotation
            None,        // next_key_hashes
            Some(false), // portable (DID Toolbox includes this explicitly)
            None,        // deactivated
            None,        // ttl
            None,        // witness
        ),
        LogEntryFormat::WebVH10 => LogParameters::new_webvh(
            Some(method_str.into()),
            Some("{SCID}".into()),
            Some(vec![authorized_multikey.into()]),
            None, // prerotation
            None, // next_key_hashes
            None, // portable
            None, // deactivated
            None, // ttl
            None, // witness
            None, // watchers (did:webvh only)
        ),
    };

    let genesis_doc = build_initial_did_doc(did_placeholder, authentication_xy, assertion_xy);
    let state = DIDDocState::Value(genesis_doc);

    match format {
        LogEntryFormat::TDW03 => {
            DIDLogEntry::new_tdw("{SCID}".into(), now.into(), parameters, state, vec![])
        }
        LogEntryFormat::WebVH10 => {
            DIDLogEntry::new_webvh("{SCID}".into(), now.into(), parameters, state, vec![])
        }
    }
}

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

    fn fixture_xy() -> ([u8; 32], [u8; 32]) {
        ([1u8; 32], [2u8; 32])
    }

    #[test]
    fn build_initial_entry_tdw_carries_scid_placeholder() {
        let entry = build_initial_entry(
            &LogEntryFormat::TDW03,
            "z6Mk-authorized",
            "did:tdw:example.com:{SCID}",
            &fixture_xy(),
            &fixture_xy(),
            "2026-05-03T12:00:00Z",
        );
        let value = entry.to_json();
        assert_eq!(value[0], "{SCID}");
        assert_eq!(value[1], "2026-05-03T12:00:00Z");
    }

    #[test]
    fn build_initial_entry_webvh_carries_scid_placeholder() {
        let entry = build_initial_entry(
            &LogEntryFormat::WebVH10,
            "z6Mk-authorized",
            "did:webvh:example.com:{SCID}",
            &fixture_xy(),
            &fixture_xy(),
            "2026-05-03T12:00:00Z",
        );
        let value = entry.to_json();
        assert_eq!(value["versionId"], "{SCID}");
        assert_eq!(value["versionTime"], "2026-05-03T12:00:00Z");
    }

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
