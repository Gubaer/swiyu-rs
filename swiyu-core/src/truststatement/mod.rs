//! SWIYU trust statement (`TrustStatementIdentityV1`) and its SD-JWT VC decoder.
//!
//! A SWIYU trust statement is the SD-JWT VC the SWIYU trust authority issues to
//! vouch for the business entity that owns a DID. This module decodes the
//! wire-format JWT into a typed [`TrustStatement`] holding both the disclosed
//! claims (legal name, state-actor flag) and the JWS bits needed to verify the
//! statement's signature.
//!
//! Pure: no I/O, no async, no signature verification. Fetching from the trust
//! registry and verifying signatures live in the consuming application.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::str::FromStr;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;

use crate::sd_jwt::{Disclosure, DisclosureError};
use crate::statuslist::{StatusListError, StatusListPointer};

#[derive(Debug)]
pub enum TrustStatementError {
    /// JWT does not have the expected three dot-separated segments.
    JwtShape { got: usize },
    /// A JWT segment failed base64url decoding.
    Base64 {
        segment: &'static str,
        reason: String,
    },
    /// A JWT segment is not valid JSON.
    Json {
        segment: &'static str,
        reason: String,
    },
    /// A disclosure decoded as JSON but is not an array.
    DisclosureNotArray,
    /// Required header field is missing.
    MissingHeaderField { name: &'static str },
    /// Required payload field is missing or has the wrong type.
    MissingPayloadField { name: &'static str },
    /// `payload.status.status_list` is malformed.
    StatusListPointer(StatusListError),
}

impl fmt::Display for TrustStatementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::JwtShape { got } => write!(f, "expected 3 dot-separated parts, got {got}"),
            Self::Base64 { segment, reason } => write!(f, "{segment} not base64url: {reason}"),
            Self::Json { segment, reason } => write!(f, "{segment} not JSON: {reason}"),
            Self::DisclosureNotArray => write!(f, "disclosure is not a JSON array"),
            Self::MissingHeaderField { name } => write!(f, "missing '{name}' in header"),
            Self::MissingPayloadField { name } => write!(f, "missing or non-numeric '{name}'"),
            Self::StatusListPointer(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for TrustStatementError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::StatusListPointer(e) => Some(e),
            _ => None,
        }
    }
}

impl From<StatusListError> for TrustStatementError {
    fn from(e: StatusListError) -> Self {
        Self::StatusListPointer(e)
    }
}

/// A SWIYU trust statement, decoded from its SD-JWT VC wire form.
///
/// Holds both the high-level claims used for display and the lower-level JWS
/// bits used for signature verification. Constructed via
/// [`TrustStatement::try_from_jwt`]; consumed read-only by callers.
///
/// Disclosure-hash-vs-`_sd` integrity is enforced during decoding: any disclosure
/// whose SHA-256 doesn't appear in the JWT's `_sd` array is silently dropped. The
/// fields below only ever reflect *authorised* disclosures.
#[derive(Debug)]
pub struct TrustStatement {
    /// Verifiable Credential Type from `payload.vct` — for example
    /// `TrustStatementIdentityV1`. Identifies which schema the disclosed claims
    /// conform to.
    pub vct: String,
    /// Issuer DID from `payload.iss`. For SWIYU trust statements this is the
    /// trust authority's `did:tdw`. Verifiers cross-check this against the
    /// expected SWIYU trust issuer.
    pub iss: String,
    /// Issued-at, Unix seconds (`payload.iat`). Used to sort statements
    /// newest-first for display.
    pub iat: u64,
    /// Optional not-before timestamp, Unix seconds (`payload.nbf`). When
    /// present, freshness checks require `now >= nbf`.
    pub nbf: Option<u64>,
    /// Optional expiration, Unix seconds (`payload.exp`). When present,
    /// freshness checks require `now < exp`.
    pub exp: Option<u64>,
    /// Language-keyed legal names from the disclosed `entityName` claim, e.g.
    /// `{"de-CH": "kacon GmbH", "fr-CH": "kacon Sàrl"}`. A `BTreeMap` so
    /// iteration is in stable, alphabetical order.
    pub entity_name: BTreeMap<String, String>,
    /// Disclosed `isStateActor` claim. `None` if the issuer chose not to
    /// disclose it.
    pub is_state_actor: Option<bool>,
    /// Status-list pointer from `payload.status.status_list`. `None` if the
    /// statement has no revocation mechanism.
    pub status: Option<StatusListPointer>,
    /// JWT header `kid` — the verification method id used to sign the
    /// statement.
    pub kid: String,
    /// JWT header `alg`. SWIYU uses `ES256` exclusively.
    pub alg: String,
    /// `<header_b64>.<payload_b64>` as ASCII bytes — the exact byte sequence
    /// the issuer signed. Stored verbatim so re-encoding can't drift the
    /// signature input.
    pub signing_input: String,
    /// Raw signature bytes from the third JWT segment. For `ES256` this is the
    /// JOSE 64-byte `r || s` form (not DER).
    pub signature: Vec<u8>,
}

impl TrustStatement {
    /// Decodes an SD-JWT VC wire-form trust statement.
    pub fn try_from_jwt(jwt_text: &str) -> Result<Self, TrustStatementError> {
        let trimmed = jwt_text.trim_end_matches('~');
        let parts: Vec<&str> = trimmed.split('~').collect();
        let jwt = parts[0];
        let disclosure_strs = &parts[1..];

        let segs: Vec<&str> = jwt.split('.').collect();
        if segs.len() != 3 {
            return Err(TrustStatementError::JwtShape { got: segs.len() });
        }

        let header_bytes =
            URL_SAFE_NO_PAD
                .decode(segs[0])
                .map_err(|e| TrustStatementError::Base64 {
                    segment: "header",
                    reason: e.to_string(),
                })?;
        let header: Value =
            serde_json::from_slice(&header_bytes).map_err(|e| TrustStatementError::Json {
                segment: "header",
                reason: e.to_string(),
            })?;
        let payload_bytes =
            URL_SAFE_NO_PAD
                .decode(segs[1])
                .map_err(|e| TrustStatementError::Base64 {
                    segment: "payload",
                    reason: e.to_string(),
                })?;
        let payload: Value =
            serde_json::from_slice(&payload_bytes).map_err(|e| TrustStatementError::Json {
                segment: "payload",
                reason: e.to_string(),
            })?;
        let signature =
            URL_SAFE_NO_PAD
                .decode(segs[2])
                .map_err(|e| TrustStatementError::Base64 {
                    segment: "signature",
                    reason: e.to_string(),
                })?;

        let kid = header
            .get("kid")
            .and_then(Value::as_str)
            .ok_or(TrustStatementError::MissingHeaderField { name: "kid" })?
            .to_string();
        let alg = header
            .get("alg")
            .and_then(Value::as_str)
            .ok_or(TrustStatementError::MissingHeaderField { name: "alg" })?
            .to_string();

        let sd_set: HashSet<String> = payload
            .get("_sd")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();

        let mut entity_name: BTreeMap<String, String> = BTreeMap::new();
        let mut is_state_actor: Option<bool> = None;

        for d in disclosure_strs {
            let disclosure = match Disclosure::from_str(d) {
                Ok(disclosure) => disclosure,
                // Malformed encoding, JSON, or a non-array disclosure fails the
                // whole statement — the behaviour before extraction moved into
                // `Disclosure`.
                Err(DisclosureError::Base64(reason)) => {
                    return Err(TrustStatementError::Base64 {
                        segment: "disclosure",
                        reason,
                    });
                }
                Err(DisclosureError::Json(reason)) => {
                    return Err(TrustStatementError::Json {
                        segment: "disclosure",
                        reason,
                    });
                }
                Err(DisclosureError::NotArray) => {
                    return Err(TrustStatementError::DisclosureNotArray);
                }
                // Off-profile shapes — the two-element array-element form, any
                // other arity, or a non-string salt/name — are skipped:
                // TrustStatementIdentityV1 only uses object-property disclosures.
                Err(
                    DisclosureError::WrongLength { .. }
                    | DisclosureError::SaltNotString
                    | DisclosureError::NameNotString,
                ) => continue,
            };

            // Only disclosures the signed `_sd` array commits to are authorised.
            if !sd_set.contains(&disclosure.digest()) {
                continue;
            }

            match disclosure.name() {
                "entityName" => {
                    if let Some(map) = disclosure.value().as_object() {
                        for (lang, val) in map {
                            if let Some(s) = val.as_str() {
                                entity_name.insert(lang.clone(), s.to_string());
                            }
                        }
                    }
                }
                "isStateActor" => {
                    if let Some(b) = disclosure.value().as_bool() {
                        is_state_actor = Some(b);
                    }
                }
                _ => {}
            }
        }

        let vct = payload
            .get("vct")
            .and_then(Value::as_str)
            .unwrap_or("(unknown)")
            .to_string();
        let iss = payload
            .get("iss")
            .and_then(Value::as_str)
            .unwrap_or("(unknown)")
            .to_string();
        let iat = payload
            .get("iat")
            .and_then(Value::as_u64)
            .ok_or(TrustStatementError::MissingPayloadField { name: "iat" })?;
        let nbf = payload.get("nbf").and_then(Value::as_u64);
        let exp = payload.get("exp").and_then(Value::as_u64);

        let status = payload
            .get("status")
            .and_then(|s| s.get("status_list"))
            .map(StatusListPointer::try_from)
            .transpose()?;

        let signing_input = format!("{}.{}", segs[0], segs[1]);

        Ok(TrustStatement {
            vct,
            iss,
            iat,
            nbf,
            exp,
            entity_name,
            is_state_actor,
            status,
            kid,
            alg,
            signing_input,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn build_jwt(payload_extra: Value, disclosures: Vec<Disclosure>) -> String {
        let mut sd_hashes: Vec<String> = Vec::new();
        let mut encoded_disclosures: Vec<String> = Vec::new();
        for d in &disclosures {
            sd_hashes.push(d.digest());
            encoded_disclosures.push(d.to_string());
        }

        let mut payload = json!({
            "_sd": sd_hashes,
            "_sd_alg": "sha-256",
            "vct": "TrustStatementIdentityV1",
            "iss": "did:tdw:Q123:trust-reg.example.com:api:v1:did:abc",
            "iat": 1776683538u64,
            "exp": 1798761600u64,
            "nbf": 1767225600u64,
            "status": {
                "status_list": {
                    "type": "SwissTokenStatusList-1.0",
                    "idx": 643,
                    "uri": "https://status-reg.example.com/api/v1/statuslist/abc.jwt",
                }
            }
        });
        let payload_obj = payload.as_object_mut().unwrap();
        if let Some(extra_obj) = payload_extra.as_object() {
            for (k, v) in extra_obj {
                payload_obj.insert(k.clone(), v.clone());
            }
        }

        let header = json!({
            "alg": "ES256",
            "kid": "did:tdw:Q123:...:abc#assert-key-02",
            "typ": "vc+sd-jwt"
        });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let sig_b64 = URL_SAFE_NO_PAD.encode(b"junk-signature-not-verified");
        let mut out = format!("{header_b64}.{payload_b64}.{sig_b64}");
        for d in encoded_disclosures {
            out.push('~');
            out.push_str(&d);
        }
        out.push('~');
        out
    }

    fn entity_name_disclosure(map: Value) -> Disclosure {
        Disclosure::new("UmcUADYUuaTR5Icmlod4hw", "entityName", map)
    }

    fn is_state_actor_disclosure(b: bool) -> Disclosure {
        Disclosure::new("rIPBffSxmopF09SQ2-gjaQ", "isStateActor", json!(b))
    }

    #[test]
    fn try_from_jwt_extracts_entity_name_and_state_actor() {
        let jwt = build_jwt(
            json!({}),
            vec![
                entity_name_disclosure(json!({ "de-CH": "kacon GmbH" })),
                is_state_actor_disclosure(false),
            ],
        );
        let s = TrustStatement::try_from_jwt(&jwt).unwrap();
        assert_eq!(s.vct, "TrustStatementIdentityV1");
        assert_eq!(s.iat, 1776683538);
        assert_eq!(s.entity_name.get("de-CH"), Some(&"kacon GmbH".to_string()));
        assert_eq!(s.is_state_actor, Some(false));
        assert_eq!(s.status.as_ref().unwrap().idx(), 643);
        assert_eq!(s.alg, "ES256");
        assert!(s.kid.starts_with("did:tdw:"));
        assert!(!s.signing_input.is_empty());
        assert!(!s.signature.is_empty());
    }

    #[test]
    fn try_from_jwt_accepts_multiple_locales() {
        let jwt = build_jwt(
            json!({}),
            vec![entity_name_disclosure(json!({
                "de-CH": "kacon GmbH",
                "fr-CH": "kacon Sàrl",
                "it-CH": "kacon Sagl",
            }))],
        );
        let s = TrustStatement::try_from_jwt(&jwt).unwrap();
        assert_eq!(s.entity_name.len(), 3);
        assert_eq!(s.entity_name.get("fr-CH"), Some(&"kacon Sàrl".to_string()));
        let keys: Vec<&String> = s.entity_name.keys().collect();
        assert_eq!(keys, vec!["de-CH", "fr-CH", "it-CH"]);
    }

    #[test]
    fn try_from_jwt_drops_disclosures_with_mismatched_hash() {
        let mut jwt = build_jwt(json!({}), vec![is_state_actor_disclosure(false)]);
        let bogus = Disclosure::new("salt", "secretClaim", json!("should-be-ignored"));
        jwt = format!("{jwt}{bogus}~");
        let s = TrustStatement::try_from_jwt(&jwt).unwrap();
        assert!(s.entity_name.is_empty());
        assert_eq!(s.is_state_actor, Some(false));
    }

    #[test]
    fn try_from_jwt_rejects_malformed_jwt() {
        let err = TrustStatement::try_from_jwt("only.two").unwrap_err();
        assert!(matches!(err, TrustStatementError::JwtShape { got: 2 }));
    }
}
