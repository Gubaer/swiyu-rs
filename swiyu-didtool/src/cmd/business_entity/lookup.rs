use std::collections::{BTreeMap, HashSet};
use std::io::Read;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tracing::debug;

use swiyu_core::did::{DID, DIDError};

use crate::cmd::iso8601;
use crate::keystore::{KeyStore, KeyStoreError};

const FETCH_BODY_SNIPPET: usize = 200;
const DEFAULT_MAX_BYTES: usize = 50 * 1024 * 1024;
const ENV_MAX_BYTES: &str = "DIDTOOL_LOG_MAX_BYTES";

pub struct LookupArgs {
    pub did: String,
    pub trust_registry_url: Option<String>,
    pub raw: bool,
}

#[derive(Debug)]
pub enum LookupOutcome {
    Found,
    NoStatements,
}

#[derive(Debug, thiserror::Error)]
pub enum LookupError {
    #[error("--trust-registry-url or SWIYU_TRUST_REGISTRY_URL is required")]
    TrustRegistryUrlMissing,
    #[error("no entry found for '{0}'")]
    NotFound(String),
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
    #[error(transparent)]
    Did(#[from] DIDError),
    #[error(transparent)]
    KeyStore(#[from] KeyStoreError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub fn cmd_lookup(store: &KeyStore, args: LookupArgs) -> Result<LookupOutcome, LookupError> {
    let base_url = args
        .trust_registry_url
        .ok_or(LookupError::TrustRegistryUrlMissing)?;
    let did = resolve_did(store, &args.did)?;
    let did_str = did.to_string();
    let endpoint = build_endpoint(&base_url, &did_str);
    debug!("GET {endpoint}");

    let body = match fetch(&endpoint)? {
        FetchResult::NotFound => {
            eprintln!("no trust statements found for {did_str}");
            return Ok(LookupOutcome::NoStatements);
        }
        FetchResult::Ok(body) => body,
    };

    process_body(&did_str, &body, args.raw)
}

fn process_body(did: &str, body: &str, raw: bool) -> Result<LookupOutcome, LookupError> {
    let array: Vec<String> = serde_json::from_str(body).map_err(|_| LookupError::ResponseShape)?;

    if array.is_empty() {
        eprintln!("no trust statements found for {did}");
        return Ok(LookupOutcome::NoStatements);
    }

    if raw {
        let pretty =
            serde_json::to_string_pretty(&array).expect("array of strings is serialisable");
        println!("{pretty}");
        return Ok(LookupOutcome::Found);
    }

    let mut statements = Vec::with_capacity(array.len());
    for (i, jwt) in array.iter().enumerate() {
        let s =
            decode_statement(jwt).map_err(|reason| LookupError::Statement { n: i + 1, reason })?;
        statements.push(s);
    }
    statements.sort_by(|a, b| b.iat.cmp(&a.iat));

    println!("Trust statements for {did}");
    for (i, s) in statements.iter().enumerate() {
        println!();
        print_statement(i + 1, s);
    }

    Ok(LookupOutcome::Found)
}

fn resolve_did(store: &KeyStore, target: &str) -> Result<DID, LookupError> {
    if target.len() == 12 && target.chars().all(|c| c.is_ascii_hexdigit()) {
        debug!("resolving '{target}' as BLAKE3 hash via key store");
        let entry = store
            .lookup_by_hash(target)?
            .ok_or_else(|| LookupError::NotFound(target.to_string()))?;
        Ok(DID::parse(entry.did())?)
    } else {
        Ok(DID::parse(target)?)
    }
}

fn build_endpoint(base_url: &str, did: &str) -> String {
    let trimmed = base_url.trim_end_matches('/');
    let encoded = percent_encode_did(did);
    format!("{trimmed}/api/v1/truststatements/identity/{encoded}")
}

fn percent_encode_did(s: &str) -> String {
    // DIDs in this ecosystem only need ':' percent-encoded for use as a path segment.
    // Encode the conservative reserved set anyway so unexpected characters don't get
    // misinterpreted by the server.
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            ':' => out.push_str("%3A"),
            '/' => out.push_str("%2F"),
            '?' => out.push_str("%3F"),
            '#' => out.push_str("%23"),
            '%' => out.push_str("%25"),
            ' ' => out.push_str("%20"),
            _ => out.push(c),
        }
    }
    out
}

enum FetchResult {
    Ok(String),
    NotFound,
}

fn fetch(url: &str) -> Result<FetchResult, LookupError> {
    let max_bytes = std::env::var(ENV_MAX_BYTES)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(DEFAULT_MAX_BYTES);

    let client = reqwest::blocking::Client::new();
    let response = client.get(url).send().map_err(|e| LookupError::Http {
        url: url.to_string(),
        source: e,
    })?;

    let status = response.status();
    if status.as_u16() == 404 {
        return Ok(FetchResult::NotFound);
    }
    if !status.is_success() {
        let body = response.text().unwrap_or_default();
        let snippet: String = body.chars().take(FETCH_BODY_SNIPPET).collect();
        return Err(LookupError::HttpStatus {
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
        return Err(LookupError::ResponseTooLarge {
            url: url.to_string(),
            max_bytes,
        });
    }

    let text = String::from_utf8(buf).map_err(|_| LookupError::NonUtf8)?;
    Ok(FetchResult::Ok(text))
}

#[derive(Debug)]
struct DecodedStatement {
    vct: String,
    iss: String,
    iat: u64,
    nbf: Option<u64>,
    exp: Option<u64>,
    entity_name: BTreeMap<String, String>,
    is_state_actor: Option<bool>,
    status: Option<StatusInfo>,
}

#[derive(Debug)]
struct StatusInfo {
    type_: String,
    idx: u64,
    uri: String,
}

fn decode_statement(jwt_text: &str) -> Result<DecodedStatement, String> {
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
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(segs[1])
        .map_err(|e| format!("payload not base64url: {e}"))?;
    let payload: Value =
        serde_json::from_slice(&payload_bytes).map_err(|e| format!("payload not JSON: {e}"))?;

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

    Ok(DecodedStatement {
        vct,
        iss,
        iat,
        nbf,
        exp,
        entity_name,
        is_state_actor,
        status,
    })
}

fn print_statement(n: usize, s: &DecodedStatement) {
    println!("#{n}  {}", s.vct);
    println!("  issuer:       {}", s.iss);
    println!("  iat:          {}", iso8601(s.iat));
    if let Some(t) = s.nbf {
        println!("  nbf:          {}", iso8601(t));
    }
    if let Some(t) = s.exp {
        println!("  exp:          {}", iso8601(t));
    }
    if s.entity_name.is_empty() {
        println!("  entity name:  (none)");
    } else {
        let mut first = true;
        for (lang, name) in &s.entity_name {
            if first {
                println!("  entity name:  {lang}: {name}");
                first = false;
            } else {
                println!("                {lang}: {name}");
            }
        }
    }
    println!(
        "  state actor:  {}",
        match s.is_state_actor {
            Some(true) => "yes",
            Some(false) => "no",
            None => "(undisclosed)",
        }
    );
    if let Some(st) = &s.status {
        println!("  status:       {} idx={}", st.type_, st.idx);
        println!("                {}", st.uri);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Build a single SD-JWT VC string with the given disclosed claims.
    /// The signature segment is junk — these tests don't verify signatures.
    fn build_jwt(payload_extra: Value, disclosures: Vec<Value>) -> String {
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

        let header = json!({ "alg": "ES256", "typ": "vc+sd-jwt" });
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

    fn entity_name_disclosure(map: Value) -> Value {
        json!(["UmcUADYUuaTR5Icmlod4hw", "entityName", map])
    }

    fn is_state_actor_disclosure(b: bool) -> Value {
        json!(["rIPBffSxmopF09SQ2-gjaQ", "isStateActor", b])
    }

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
        // BTreeMap iterates in sorted key order — verify the output order is stable.
        let keys: Vec<&String> = s.entity_name.keys().collect();
        assert_eq!(keys, vec!["de-CH", "fr-CH", "it-CH"]);
    }

    #[test]
    fn decode_drops_disclosures_with_mismatched_hash() {
        // Build a JWT, then append an extra disclosure that's not in _sd.
        let mut jwt = build_jwt(json!({}), vec![is_state_actor_disclosure(false)]);
        let bogus = json!(["salt", "secretClaim", "should-be-ignored"]);
        let bogus_enc = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&bogus).unwrap());
        // Strip trailing ~, append bogus disclosure, restore trailing ~.
        jwt = format!("{}{bogus_enc}~", jwt);
        let s = decode_statement(&jwt).unwrap();
        // bogus disclosure must not surface as entityName (which would be the
        // closest-matching field). It's silently dropped.
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
        let url = build_endpoint(
            "https://trust-reg.example.com/",
            "did:tdw:Q123:host.example.com:api:v1:did:abc",
        );
        assert_eq!(
            url,
            "https://trust-reg.example.com/api/v1/truststatements/identity/did%3Atdw%3AQ123%3Ahost.example.com%3Aapi%3Av1%3Adid%3Aabc"
        );
    }

    #[test]
    fn build_endpoint_handles_trailing_slash() {
        let with_slash = build_endpoint("https://x/", "did:foo");
        let without = build_endpoint("https://x", "did:foo");
        assert_eq!(with_slash, without);
    }

    #[test]
    fn process_body_empty_array_returns_no_statements() {
        let outcome = process_body("did:tdw:abc", "[]", false).unwrap();
        assert!(matches!(outcome, LookupOutcome::NoStatements));
    }

    #[test]
    fn process_body_non_array_is_response_shape_error() {
        let err = process_body("did:tdw:abc", "{}", false).unwrap_err();
        assert!(matches!(err, LookupError::ResponseShape));
    }

    #[test]
    fn process_body_one_statement_returns_found() {
        let jwt = build_jwt(json!({}), vec![is_state_actor_disclosure(true)]);
        let body = serde_json::to_string(&vec![jwt]).unwrap();
        let outcome = process_body("did:tdw:abc", &body, false).unwrap();
        assert!(matches!(outcome, LookupOutcome::Found));
    }
}
