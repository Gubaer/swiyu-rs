pub mod lookup;
pub mod verify_trust;

use std::collections::{BTreeMap, HashSet};
use std::io::Read;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use sha2::{Digest, Sha256};

use swiyu_core::did::{DID, DIDError};
use swiyu_core::diddoc::DIDDocError;

use crate::cmd::ResolveError;
use crate::cmd::http::{DEFAULT_MAX_BYTES, ENV_MAX_BYTES, FETCH_BODY_SNIPPET};
use crate::cmd::log::LogError;
use crate::keystore::KeyStoreError;

#[derive(Debug, thiserror::Error)]
pub enum BusinessEntityError {
    #[error("--trust-registry-url or SWIYU_TRUST_REGISTRY_URL is required")]
    TrustRegistryUrlMissing,
    #[error("--trust-issuer or SWIYU_TRUST_ISSUER_DID is required")]
    TrustIssuerMissing,
    #[error("cannot fetch '{url}': {source}")]
    Http {
        url: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("'{url}' returned {status}: {body}")]
    HttpStatus {
        url: String,
        status: u16,
        body: String,
    },
    #[error("response from '{url}' exceeds {max_bytes} bytes")]
    ResponseTooLarge { url: String, max_bytes: usize },
    #[error("response is not valid UTF-8")]
    NonUtf8,
    #[error("trust registry response is not a JSON array of JWT strings")]
    ResponseShape,
    #[error("trust statement #{n} is malformed: {reason}")]
    Statement { n: usize, reason: String },
    #[error("cannot resolve issuer DID log for '{iss}': {reason}")]
    IssuerResolution { iss: String, reason: String },
    #[error("status list at '{url}' is malformed: {reason}")]
    StatusListMalformed { url: String, reason: String },
    #[error("status list signature verification failed")]
    StatusListSignatureInvalid,
    #[error("status list at '{url}' bitstring decompression failed: {reason}")]
    StatusListDecompression { url: String, reason: String },
    #[error("status list idx {idx} exceeds bitstring length")]
    StatusListIdxOutOfRange { idx: u64 },
    #[error(transparent)]
    Resolve(#[from] ResolveError),
    #[error(transparent)]
    Did(#[from] DIDError),
    #[error(transparent)]
    DidDoc(#[from] DIDDocError),
    #[error(transparent)]
    KeyStore(#[from] KeyStoreError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Log(#[from] LogError),
}

/// A SWIYU trust statement, decoded from its SD-JWT VC wire form.
///
/// Holds both the high-level claims used by `lookup` (for display) and the lower-level
/// JWS bits used by `verify-trust` (for signature verification). Constructed by
/// [`decode_statement`]; consumed read-only by both subcommands.
///
/// Disclosure-hash-vs-`_sd` integrity is enforced during decoding: any disclosure whose
/// SHA-256 doesn't appear in the JWT's `_sd` array is silently dropped. The fields below
/// only ever reflect *authorised* disclosures.
#[derive(Debug)]
pub(crate) struct DecodedStatement {
    /// Verifiable Credential Type from `payload.vct` — for example `TrustStatementIdentityV1`.
    /// Identifies which schema the disclosed claims conform to.
    pub vct: String,
    /// Issuer DID from `payload.iss`. For SWIYU trust statements this is the trust
    /// authority's `did:tdw`. `verify-trust` cross-checks this against `--trust-issuer`.
    pub iss: String,
    /// Issued-at, Unix seconds (`payload.iat`). Used by `lookup` to sort statements
    /// newest-first; `verify-trust` reports it for context but does not enforce it.
    pub iat: u64,
    /// Optional not-before timestamp, Unix seconds (`payload.nbf`). When present,
    /// `verify-trust` requires `now >= nbf` for the statement to be fresh.
    pub nbf: Option<u64>,
    /// Optional expiration, Unix seconds (`payload.exp`). When present, `verify-trust`
    /// requires `now < exp` for the statement to be fresh.
    pub exp: Option<u64>,
    /// Language-keyed legal names from the disclosed `entityName` claim, e.g.
    /// `{"de-CH": "kacon GmbH", "fr-CH": "kacon Sàrl"}`. A `BTreeMap` so iteration is
    /// in stable, alphabetical order — display formatting depends on this.
    pub entity_name: BTreeMap<String, String>,
    /// Disclosed `isStateActor` claim. `None` if the issuer chose not to disclose it.
    pub is_state_actor: Option<bool>,
    /// Status-list pointer from `payload.status.status_list`. `None` if the statement
    /// has no revocation mechanism (uncommon, but allowed by the SD-JWT VC spec).
    pub status: Option<StatusInfo>,
    /// JWT header `kid` — the verification method id used to sign the statement.
    /// SWIYU's trust authority signs with the `#assert-key-02` fragment of its DID.
    pub kid: String,
    /// JWT header `alg`. SWIYU uses `ES256` exclusively; `verify-trust` rejects
    /// anything else.
    pub alg: String,
    /// `<header_b64>.<payload_b64>` as ASCII bytes — the exact byte sequence the issuer
    /// signed. Stored verbatim so re-encoding can't drift the signature input.
    pub signing_input: String,
    /// Raw signature bytes from the third JWT segment. For `ES256` this is the JOSE
    /// 64-byte `r || s` form (not DER); decoded directly into `p256::ecdsa::Signature`.
    pub signature: Vec<u8>,
}

/// Pointer to a single entry in an external status list (the IETF Token Status List
/// shape). Lives at `payload.status.status_list` of a SWIYU trust statement and tells a
/// verifier *where* to look up the statement's current revocation status — the bitstring
/// itself is fetched from `uri` and the slot is read at `idx`.
#[derive(Debug)]
pub(crate) struct StatusInfo {
    /// Status-list type tag from the issuer (e.g. `SwissTokenStatusList-1.0`). Stored
    /// verbatim and surfaced in the `lookup` display; not interpreted by `verify-trust`,
    /// which works off the `bits` value in the fetched status list itself.
    pub type_: String,
    /// 0-based index of this statement's slot in the bitstring. For 2-bit lists the
    /// slot is 2 bits wide; for 1-bit lists, 1 bit. Out-of-range indices are an error.
    pub idx: u64,
    /// HTTPS URL of the status-list JWT. `verify-trust` fetches it once per invocation
    /// (cached by URL), verifies its signature, and reads the slot at `idx`.
    pub uri: String,
}

pub(crate) enum FetchOutcome {
    Ok(String),
    NotFound,
}

pub(crate) fn build_endpoint(base_url: &str, did: &DID) -> String {
    let trimmed = base_url.trim_end_matches('/');
    format!(
        "{trimmed}/api/v1/truststatements/identity/{}",
        did.url_path_segment()
    )
}

pub(crate) fn fetch_text(url: &str) -> Result<FetchOutcome, BusinessEntityError> {
    let max_bytes = std::env::var(ENV_MAX_BYTES)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(DEFAULT_MAX_BYTES);

    let client = reqwest::blocking::Client::new();
    let response = client
        .get(url)
        .send()
        .map_err(|e| BusinessEntityError::Http {
            url: url.to_string(),
            source: e,
        })?;

    let status = response.status();
    if status.as_u16() == 404 {
        return Ok(FetchOutcome::NotFound);
    }
    if !status.is_success() {
        let body = response.text().unwrap_or_default();
        let snippet: String = body.chars().take(FETCH_BODY_SNIPPET).collect();
        return Err(BusinessEntityError::HttpStatus {
            url: url.to_string(),
            status: status.as_u16(),
            body: snippet,
        });
    }

    let mut buf = Vec::with_capacity(max_bytes.min(1024 * 64));
    response
        .take((max_bytes + 1) as u64)
        .read_to_end(&mut buf)?;

    if buf.len() > max_bytes {
        return Err(BusinessEntityError::ResponseTooLarge {
            url: url.to_string(),
            max_bytes,
        });
    }

    let text = String::from_utf8(buf).map_err(|_| BusinessEntityError::NonUtf8)?;
    Ok(FetchOutcome::Ok(text))
}

pub(crate) fn decode_statement(jwt_text: &str) -> Result<DecodedStatement, String> {
    let trimmed = jwt_text.trim_end_matches('~');
    let parts: Vec<&str> = trimmed.split('~').collect();
    let jwt = parts.first().ok_or("empty JWT")?;
    let disclosure_strs = &parts[1..];

    let segs: Vec<&str> = jwt.split('.').collect();
    if segs.len() != 3 {
        return Err(format!(
            "expected 3 dot-separated parts, got {}",
            segs.len()
        ));
    }
    let header_bytes = URL_SAFE_NO_PAD
        .decode(segs[0])
        .map_err(|e| format!("header not base64url: {e}"))?;
    let header: Value =
        serde_json::from_slice(&header_bytes).map_err(|e| format!("header not JSON: {e}"))?;
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(segs[1])
        .map_err(|e| format!("payload not base64url: {e}"))?;
    let payload: Value =
        serde_json::from_slice(&payload_bytes).map_err(|e| format!("payload not JSON: {e}"))?;
    let signature = URL_SAFE_NO_PAD
        .decode(segs[2])
        .map_err(|e| format!("signature not base64url: {e}"))?;

    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing 'kid' in header".to_string())?
        .to_string();
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing 'alg' in header".to_string())?
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
        let bytes = URL_SAFE_NO_PAD
            .decode(d)
            .map_err(|e| format!("disclosure not base64url: {e}"))?;
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|e| format!("disclosure not JSON: {e}"))?;
        let arr = value
            .as_array()
            .ok_or_else(|| "disclosure is not a JSON array".to_string())?;

        let hash_b64 = URL_SAFE_NO_PAD.encode(Sha256::digest(d.as_bytes()));
        if !sd_set.contains(&hash_b64) {
            continue;
        }

        // Object-property disclosure: [salt, name, value]. Array-element disclosures
        // ([salt, value], length 2) are intentionally ignored — TrustStatementIdentityV1
        // doesn't use them.
        if arr.len() != 3 {
            continue;
        }
        let name = match arr[1].as_str() {
            Some(s) => s,
            None => continue,
        };
        match name {
            "entityName" => {
                if let Some(map) = arr[2].as_object() {
                    for (lang, val) in map {
                        if let Some(s) = val.as_str() {
                            entity_name.insert(lang.clone(), s.to_string());
                        }
                    }
                }
            }
            "isStateActor" => {
                if let Some(b) = arr[2].as_bool() {
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
        .ok_or_else(|| "missing or non-numeric 'iat'".to_string())?;
    let nbf = payload.get("nbf").and_then(Value::as_u64);
    let exp = payload.get("exp").and_then(Value::as_u64);

    let status = payload
        .get("status")
        .and_then(|s| s.get("status_list"))
        .and_then(|sl| {
            Some(StatusInfo {
                type_: sl.get("type").and_then(Value::as_str)?.to_string(),
                idx: sl.get("idx").and_then(Value::as_u64)?,
                uri: sl.get("uri").and_then(Value::as_str)?.to_string(),
            })
        });

    let signing_input = format!("{}.{}", segs[0], segs[1]);

    Ok(DecodedStatement {
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

// ── Test fixtures (cfg(test) only, shared across submodules) ─────────────────

/// Builds a single SD-JWT VC string with the given disclosed claims.
/// The signature segment is junk — callers that need a valid signature must
/// build their own JWT.
#[cfg(test)]
pub(crate) fn build_jwt(payload_extra: Value, disclosures: Vec<serde_json::Value>) -> String {
    use serde_json::json;
    let mut sd_hashes: Vec<String> = Vec::new();
    let mut encoded_disclosures: Vec<String> = Vec::new();
    for d in &disclosures {
        let json = serde_json::to_string(d).unwrap();
        let enc = URL_SAFE_NO_PAD.encode(json.as_bytes());
        let hash = URL_SAFE_NO_PAD.encode(Sha256::digest(enc.as_bytes()));
        sd_hashes.push(hash);
        encoded_disclosures.push(enc);
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

    let header =
        json!({ "alg": "ES256", "kid": "did:tdw:Q123:...:abc#assert-key-02", "typ": "vc+sd-jwt" });
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

#[cfg(test)]
pub(crate) fn entity_name_disclosure(map: serde_json::Value) -> serde_json::Value {
    serde_json::json!(["UmcUADYUuaTR5Icmlod4hw", "entityName", map])
}

#[cfg(test)]
pub(crate) fn is_state_actor_disclosure(b: bool) -> serde_json::Value {
    serde_json::json!(["rIPBffSxmopF09SQ2-gjaQ", "isStateActor", b])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn decode_extracts_entity_name_and_state_actor() {
        let jwt = build_jwt(
            json!({}),
            vec![
                entity_name_disclosure(json!({ "de-CH": "kacon GmbH" })),
                is_state_actor_disclosure(false),
            ],
        );
        let s = decode_statement(&jwt).unwrap();
        assert_eq!(s.vct, "TrustStatementIdentityV1");
        assert_eq!(s.iat, 1776683538);
        assert_eq!(s.entity_name.get("de-CH"), Some(&"kacon GmbH".to_string()));
        assert_eq!(s.is_state_actor, Some(false));
        assert_eq!(s.status.as_ref().unwrap().idx, 643);
        assert_eq!(s.alg, "ES256");
        assert!(s.kid.starts_with("did:tdw:"));
        assert!(!s.signing_input.is_empty());
        assert!(!s.signature.is_empty());
    }

    #[test]
    fn decode_accepts_multiple_locales() {
        let jwt = build_jwt(
            json!({}),
            vec![entity_name_disclosure(json!({
                "de-CH": "kacon GmbH",
                "fr-CH": "kacon Sàrl",
                "it-CH": "kacon Sagl",
            }))],
        );
        let s = decode_statement(&jwt).unwrap();
        assert_eq!(s.entity_name.len(), 3);
        assert_eq!(s.entity_name.get("fr-CH"), Some(&"kacon Sàrl".to_string()));
        let keys: Vec<&String> = s.entity_name.keys().collect();
        assert_eq!(keys, vec!["de-CH", "fr-CH", "it-CH"]);
    }

    #[test]
    fn decode_drops_disclosures_with_mismatched_hash() {
        let mut jwt = build_jwt(json!({}), vec![is_state_actor_disclosure(false)]);
        let bogus = json!(["salt", "secretClaim", "should-be-ignored"]);
        let bogus_enc = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&bogus).unwrap());
        jwt = format!("{jwt}{bogus_enc}~");
        let s = decode_statement(&jwt).unwrap();
        assert!(s.entity_name.is_empty());
        assert_eq!(s.is_state_actor, Some(false));
    }

    #[test]
    fn decode_rejects_malformed_jwt() {
        let err = decode_statement("only.two").unwrap_err();
        assert!(err.contains("3 dot-separated parts"));
    }

    #[test]
    fn build_endpoint_percent_encodes_did() {
        let did: DID = "did:tdw:Q123:host.example.com:api:v1:did:abc"
            .parse()
            .unwrap();
        let url = build_endpoint("https://trust-reg.example.com/", &did);
        assert_eq!(
            url,
            "https://trust-reg.example.com/api/v1/truststatements/identity/did%3Atdw%3AQ123%3Ahost.example.com%3Aapi%3Av1%3Adid%3Aabc"
        );
    }

    #[test]
    fn build_endpoint_handles_trailing_slash() {
        let did: DID = "did:tdw:abc:example.com".parse().unwrap();
        let with_slash = build_endpoint("https://x/", &did);
        let without = build_endpoint("https://x", &did);
        assert_eq!(with_slash, without);
    }
}
