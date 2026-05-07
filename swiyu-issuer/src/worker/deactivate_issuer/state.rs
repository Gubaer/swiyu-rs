//! Input and state-data shapes for `DeactivateIssuer` tasks.
//!
//! `DeactivateIssuerInput` is the BA-supplied portion of the task —
//! deliberately empty in v1 because the target issuer is already
//! identified by `task.result_issuer_id` (set by the endpoint at
//! submit time) and the operation has no further parameters. The
//! struct exists so future fields (e.g. a deactivation reason) can be
//! added without churning callers, and so the wire shape mirrors
//! `CreateIssuerInput`'s `deny_unknown_fields` discipline.
//!
//! `DeactivateIssuerStateData` accumulates step outputs across
//! retries and crashes. It currently records only whether
//! `publish_log` has succeeded; the deactivation entry itself is not
//! stored, since each step that needs it re-derives it deterministically
//! from the current registry tail and the issuer's current
//! `Authorized` key.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeactivateIssuerInput {}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeactivateIssuerStateData {
    /// Set to `true` once `publish_log` has succeeded against the
    /// SWIYU Identifier Registry. The registry's PUT endpoint returns
    /// no body, so the worker records a boolean rather than a
    /// server-supplied identifier — same pattern as `CreateIssuer`.
    #[serde(default, skip_serializing_if = "crate::worker::is_false")]
    pub log_published: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::{Value, json};

    #[test]
    fn input_round_trips_through_empty_object() {
        let input = DeactivateIssuerInput::default();
        let value = serde_json::to_value(&input).unwrap();
        assert_eq!(value, json!({}));
        let parsed: DeactivateIssuerInput = serde_json::from_value(value).unwrap();
        assert_eq!(parsed, input);
    }

    #[test]
    fn input_rejects_unknown_fields() {
        let value = json!({"reason": "compromised"});
        let err = serde_json::from_value::<DeactivateIssuerInput>(value).unwrap_err();
        assert!(
            err.to_string().contains("reason"),
            "expected error to mention the unknown field, got: {err}",
        );
    }

    #[test]
    fn state_data_default_has_log_unpublished() {
        let state = DeactivateIssuerStateData::default();
        assert!(!state.log_published);
    }

    #[test]
    fn state_data_deserialises_from_empty_object() {
        let state: DeactivateIssuerStateData = serde_json::from_value(json!({})).unwrap();
        assert_eq!(state, DeactivateIssuerStateData::default());
    }

    #[test]
    fn state_data_round_trips_when_published() {
        let original = DeactivateIssuerStateData {
            log_published: true,
        };
        let value = serde_json::to_value(&original).unwrap();
        let parsed: DeactivateIssuerStateData = serde_json::from_value(value).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn state_data_skips_default_field_when_serialising() {
        let state = DeactivateIssuerStateData::default();
        let value = serde_json::to_value(&state).unwrap();
        assert_eq!(value, json!({}));
    }

    #[test]
    fn state_data_serialises_log_published_true() {
        let state = DeactivateIssuerStateData {
            log_published: true,
        };
        let value = serde_json::to_value(&state).unwrap();
        let Value::Object(obj) = value else {
            panic!("expected object");
        };
        assert_eq!(obj["log_published"], true);
    }
}
