//! Input and state-data shapes for `CreateIssuer` tasks.
//!
//! `CreateIssuerInput` is what the BA submits at `POST /api/v1/issuers`
//! and what the worker reads back from `task.input` after a crash.
//! `CreateIssuerStateData` is the merged accumulation of step
//! outputs; the worker reads it on resume to skip steps whose side
//! effects have already happened. Both round-trip through the
//! `serde_json::Value` columns on `operation_tasks`.

use serde::{Deserialize, Serialize};

use crate::domain::KeyPairId;

/// BA-supplied portion of a `CreateIssuer` task.
///
/// The DID, the key triple, and the lifecycle state are produced by
/// the worker — the BA does not pick them. Multi-tenant routing is
/// resolved from the API token by `TenantContext`, never from the
/// body.
///
/// `did_method` is intentionally absent: v1 hard-codes `did:tdw` 0.3
/// inside the worker because `did:webvh` 1.0 is not testable
/// end-to-end. The field will return as an optional enum once
/// `did:webvh` lands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateIssuerInput {
    pub description: String,
    pub display_name: String,
}

/// Accumulated step outputs for a `CreateIssuer` task.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CreateIssuerStateData {
    /// Registry-published DIDLog URL (e.g.
    /// `https://identifier-reg.swiyu.admin.ch/api/v1/did/<UUID>/did.jsonl`).
    /// Set by `allocate_did`; when present that step is skipped on resume.
    /// The host/path component of the DID is derived from this URL; the
    /// final DID with SCID is computed during `build_initial_didlog` and not
    /// stored separately, since it is deterministic from this URL plus the
    /// key triple.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigned_did_url: Option<String>,

    /// Registry-assigned UUID extracted from the allocation URL.
    /// Set by `allocate_did` alongside `assigned_did_url`. Required by
    /// `publish_log_entry`, which addresses the entry by
    /// (`partner_id`, `identifier`) rather than by DID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigned_identifier: Option<String>,

    /// Set by `generate_keys`; when present that step is skipped on resume.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_ids: Option<KeyTriple>,

    /// Set to `true` once `publish_didlog` has succeeded; when `true` that step
    /// is skipped on resume. The registry's PUT endpoint returns no body, so
    /// the worker records a boolean rather than a server-supplied identifier.
    #[serde(default, skip_serializing_if = "crate::worker::is_false")]
    pub didlog_published: bool,

    /// Registry-side status-list entry UUID returned by
    /// `create_status_list_entry`. When present the registry call is skipped
    /// on resume and only the DB-side provisioning runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_list_registry_entry_id: Option<String>,

    /// `statusRegistryUrl` returned alongside
    /// `status_list_registry_entry_id`. Stored on the issuer's
    /// `status_lists` row by `provision_status_list` and embedded as
    /// `status.status_list.uri` on every issued credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_list_registry_url: Option<String>,
}

/// The three `KeyPairId`s an issuer holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyTriple {
    /// Ed25519 key used for DID-log signing.
    pub authorized: KeyPairId,
    /// ECDSA P-256 key embedded in the DID document as the authentication verification method.
    pub authentication: KeyPairId,
    /// ECDSA P-256 key embedded in the DID document as the assertion verification method.
    pub assertion: KeyPairId,
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::{Value, json};
    use uuid::Uuid;

    fn fixture_key_triple() -> KeyTriple {
        KeyTriple {
            authorized: KeyPairId::from(
                Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap(),
            ),
            authentication: KeyPairId::from(
                Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap(),
            ),
            assertion: KeyPairId::from(
                Uuid::parse_str("33333333-3333-4333-8333-333333333333").unwrap(),
            ),
        }
    }

    #[test]
    fn create_issuer_input_round_trips_through_json() {
        let input = CreateIssuerInput {
            description: "Cantonal driver-licence issuer".into(),
            display_name: "Canton Bern Verkehrsamt".into(),
        };
        let value = serde_json::to_value(&input).unwrap();
        let parsed: CreateIssuerInput = serde_json::from_value(value).unwrap();
        assert_eq!(parsed, input);
    }

    #[test]
    fn create_issuer_input_rejects_unknown_fields() {
        let value = json!({
            "description": "x",
            "display_name": "X",
            "did_method": "tdw:0.3",
        });
        let err = serde_json::from_value::<CreateIssuerInput>(value).unwrap_err();
        assert!(
            err.to_string().contains("did_method"),
            "expected error to mention the unknown field, got: {err}",
        );
    }

    #[test]
    fn create_issuer_input_requires_both_fields() {
        let value = json!({"description": "x"});
        assert!(serde_json::from_value::<CreateIssuerInput>(value).is_err());

        let value = json!({"display_name": "X"});
        assert!(serde_json::from_value::<CreateIssuerInput>(value).is_err());
    }

    #[test]
    fn state_data_default_is_all_none() {
        let state = CreateIssuerStateData::default();
        assert!(state.assigned_did_url.is_none());
        assert!(state.assigned_identifier.is_none());
        assert!(state.key_ids.is_none());
        assert!(!state.didlog_published);
        assert!(state.status_list_registry_entry_id.is_none());
        assert!(state.status_list_registry_url.is_none());
    }

    #[test]
    fn state_data_deserialises_from_empty_object() {
        let state: CreateIssuerStateData = serde_json::from_value(json!({})).unwrap();
        assert_eq!(state, CreateIssuerStateData::default());
    }

    #[test]
    fn state_data_deserialises_partial_progress() {
        let value = json!({
            "assigned_did_url": "https://reg.example/api/v1/did/abc/did.jsonl",
            "assigned_identifier": "abc",
        });
        let state: CreateIssuerStateData = serde_json::from_value(value).unwrap();
        assert_eq!(
            state.assigned_did_url.as_deref(),
            Some("https://reg.example/api/v1/did/abc/did.jsonl"),
        );
        assert_eq!(state.assigned_identifier.as_deref(), Some("abc"));
        assert!(state.key_ids.is_none());
        assert!(!state.didlog_published);
    }

    #[test]
    fn state_data_round_trips_full_state() {
        let original = CreateIssuerStateData {
            assigned_did_url: Some("https://reg.example/api/v1/did/abc/did.jsonl".into()),
            assigned_identifier: Some("abc".into()),
            key_ids: Some(fixture_key_triple()),
            didlog_published: true,
            status_list_registry_entry_id: Some("11111111-2222-3333-4444-555555555555".into()),
            status_list_registry_url: Some("https://status-reg.example.com/lists/abc.jwt".into()),
        };
        let value = serde_json::to_value(&original).unwrap();
        let parsed: CreateIssuerStateData = serde_json::from_value(value).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn state_data_skips_default_fields_when_serialising() {
        let state = CreateIssuerStateData::default();
        let value = serde_json::to_value(&state).unwrap();
        assert_eq!(value, json!({}));
    }

    #[test]
    fn key_triple_serialises_as_uuid_strings() {
        let triple = fixture_key_triple();
        let value = serde_json::to_value(triple).unwrap();
        let Value::Object(obj) = value else {
            panic!("expected object");
        };
        assert_eq!(obj["authorized"], "11111111-1111-4111-8111-111111111111");
        assert_eq!(
            obj["authentication"],
            "22222222-2222-4222-8222-222222222222"
        );
        assert_eq!(obj["assertion"], "33333333-3333-4333-8333-333333333333");
    }
}
