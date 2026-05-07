//! Input and state-data shapes for `RotateKeys` tasks.
//!
//! `RotateKeysInput` is the BA-supplied portion of the task. The
//! wire format carries the role names as lowercase snake-case
//! strings plus an `"all"` sentinel that expands server-side into
//! the full three-role set; worker code only ever sees the concrete
//! `KeyRole` enum.
//!
//! `RotateKeysStateData` accumulates step outputs across retries
//! and crashes. `new_key_triple` records the key ids the saga has
//! decided on (rotated → new ids freshly minted by the
//! SigningEngine, non-rotated → the issuer's existing ids), so a
//! crash between `generate_new_keys` and `build_rotation_log` does
//! not strand the freshly generated keys: the resume sees the
//! populated triple and skips engine traffic.

use serde::{Deserialize, Serialize};

use crate::domain::KeyRole;
use crate::worker::create_issuer::KeyTriple;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotateKeysInput {
    #[serde(with = "wire_roles")]
    pub roles: Vec<KeyRole>,
}

/// Wire-format adapter for the `roles` array.
///
/// Deserialise: accept lowercase snake-case role names, plus the
/// sentinel `"all"`. Empty arrays are rejected. `"all"` must appear
/// alone; mixing it with concrete role names is a client bug and
/// surfaces as an error. Duplicates are tolerated and de-duplicated,
/// preserving first-occurrence order.
///
/// Serialise: emit each `KeyRole` as its snake_case wire name.
/// `"all"` is *not* re-emitted on round-trip — the deserialiser
/// expands it into the concrete set, so the round-tripped value is
/// always the explicit list.
mod wire_roles {
    use super::KeyRole;
    use serde::de::{self, Deserializer, SeqAccess, Visitor};
    use serde::ser::{SerializeSeq, Serializer};
    use std::collections::HashSet;
    use std::fmt;

    pub fn serialize<S>(roles: &[KeyRole], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(roles.len()))?;
        for role in roles {
            seq.serialize_element(role_name(*role))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<KeyRole>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Vec<KeyRole>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a non-empty array of role names or [\"all\"]")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Vec<KeyRole>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut raw: Vec<String> = Vec::new();
                while let Some(s) = seq.next_element::<String>()? {
                    raw.push(s);
                }
                if raw.is_empty() {
                    return Err(de::Error::custom("roles must be non-empty"));
                }

                let saw_all = raw.iter().any(|s| s == "all");
                if saw_all {
                    if raw.len() > 1 {
                        return Err(de::Error::custom(
                            "\"all\" must appear alone in roles, not mixed with concrete role names",
                        ));
                    }
                    return Ok(vec![
                        KeyRole::Authorized,
                        KeyRole::Authentication,
                        KeyRole::Assertion,
                    ]);
                }

                let mut seen = HashSet::new();
                let mut out = Vec::new();
                for s in raw {
                    let role = match s.as_str() {
                        "authorized" => KeyRole::Authorized,
                        "authentication" => KeyRole::Authentication,
                        "assertion" => KeyRole::Assertion,
                        other => {
                            return Err(de::Error::custom(format!("unknown role name: {other}")));
                        }
                    };
                    if seen.insert(role) {
                        out.push(role);
                    }
                }
                Ok(out)
            }
        }

        deserializer.deserialize_seq(V)
    }

    fn role_name(role: KeyRole) -> &'static str {
        match role {
            KeyRole::Authorized => "authorized",
            KeyRole::Authentication => "authentication",
            KeyRole::Assertion => "assertion",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotateKeysStateData {
    /// The key triple the saga has decided to install: rotated
    /// roles point at freshly generated ids, non-rotated roles
    /// carry the issuer's existing ids forward unchanged. `None`
    /// while `generate_new_keys` has not yet run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_key_triple: Option<KeyTriple>,

    /// Set to `true` once `publish_log` has succeeded. The registry's
    /// PUT endpoint returns no body, so the worker records a boolean
    /// rather than a server-supplied identifier — same pattern as
    /// `CreateIssuer` and `DeactivateIssuer`.
    #[serde(default, skip_serializing_if = "crate::worker::is_false")]
    pub log_published: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::json;

    #[test]
    fn input_parses_single_role() {
        let v = json!({"roles": ["authorized"]});
        let parsed: RotateKeysInput = serde_json::from_value(v).unwrap();
        assert_eq!(parsed.roles, vec![KeyRole::Authorized]);
    }

    #[test]
    fn input_parses_multiple_roles_in_order() {
        let v = json!({"roles": ["authentication", "assertion"]});
        let parsed: RotateKeysInput = serde_json::from_value(v).unwrap();
        assert_eq!(
            parsed.roles,
            vec![KeyRole::Authentication, KeyRole::Assertion],
        );
    }

    #[test]
    fn input_dedupes_repeated_roles_keeping_first_occurrence() {
        let v = json!({"roles": ["assertion", "authorized", "assertion"]});
        let parsed: RotateKeysInput = serde_json::from_value(v).unwrap();
        assert_eq!(parsed.roles, vec![KeyRole::Assertion, KeyRole::Authorized]);
    }

    #[test]
    fn input_expands_all_sentinel_to_full_set() {
        let v = json!({"roles": ["all"]});
        let parsed: RotateKeysInput = serde_json::from_value(v).unwrap();
        assert_eq!(
            parsed.roles,
            vec![
                KeyRole::Authorized,
                KeyRole::Authentication,
                KeyRole::Assertion,
            ],
        );
    }

    #[test]
    fn input_rejects_all_mixed_with_concrete_role() {
        let v = json!({"roles": ["all", "authorized"]});
        let err = serde_json::from_value::<RotateKeysInput>(v).unwrap_err();
        assert!(
            err.to_string().contains("\"all\" must appear alone"),
            "expected \"all\" mixing message, got: {err}",
        );
    }

    #[test]
    fn input_rejects_empty_roles() {
        let v = json!({"roles": []});
        let err = serde_json::from_value::<RotateKeysInput>(v).unwrap_err();
        assert!(
            err.to_string().contains("non-empty"),
            "expected non-empty message, got: {err}",
        );
    }

    #[test]
    fn input_rejects_unknown_role_name() {
        let v = json!({"roles": ["administrator"]});
        let err = serde_json::from_value::<RotateKeysInput>(v).unwrap_err();
        assert!(
            err.to_string().contains("unknown role name"),
            "expected unknown-role message, got: {err}",
        );
    }

    #[test]
    fn input_rejects_unknown_top_level_field() {
        let v = json!({"roles": ["authorized"], "reason": "compromised"});
        let err = serde_json::from_value::<RotateKeysInput>(v).unwrap_err();
        assert!(
            err.to_string().contains("reason"),
            "expected unknown-field message, got: {err}",
        );
    }

    #[test]
    fn input_serialises_with_snake_case_role_names() {
        let input = RotateKeysInput {
            roles: vec![KeyRole::Authorized, KeyRole::Assertion],
        };
        let value = serde_json::to_value(&input).unwrap();
        assert_eq!(value, json!({"roles": ["authorized", "assertion"]}));
    }

    #[test]
    fn input_round_trips_through_json() {
        let original = RotateKeysInput {
            roles: vec![KeyRole::Authentication],
        };
        let value = serde_json::to_value(&original).unwrap();
        let parsed: RotateKeysInput = serde_json::from_value(value).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn state_data_default_is_empty() {
        let s = RotateKeysStateData::default();
        assert!(s.new_key_triple.is_none());
        assert!(!s.log_published);
    }

    #[test]
    fn state_data_round_trips_through_empty_object() {
        let s: RotateKeysStateData = serde_json::from_value(json!({})).unwrap();
        assert_eq!(s, RotateKeysStateData::default());
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v, json!({}));
    }

    #[test]
    fn state_data_round_trips_when_log_published() {
        let original = RotateKeysStateData {
            new_key_triple: None,
            log_published: true,
        };
        let v = serde_json::to_value(&original).unwrap();
        let parsed: RotateKeysStateData = serde_json::from_value(v).unwrap();
        assert_eq!(parsed, original);
    }
}
