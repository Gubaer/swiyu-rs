use std::path::PathBuf;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek::Verifier as _;
use serde_json::Value;
use tracing::debug;

use swiyu_core::did::{DID, DIDError};
use swiyu_core::diddoc::{DIDDoc, DIDDocError, PublicKey, PublicKeyJWK, PublicKeyMultibase};
use swiyu_core::didlog::{DIDDocState, DIDLog};

use crate::cmd::iso8601;
use crate::cmd::log::{LogError, current_did, load_log};
use crate::keystore::{KeyRole, KeyStore, KeyStoreError};

const IAT_SKEW_SECS: u64 = 60;

pub struct VerifyPopArgs {
    pub jwt: Option<String>,
    pub jwt_file: Option<PathBuf>,
    pub did: Option<String>,
    pub input: Option<PathBuf>,
    pub nonce: Option<String>,
    pub allow_expired: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyPopError {
    #[error("--jwt and --jwt-file are mutually exclusive")]
    AmbiguousJwt,
    #[error("provide one of --jwt or --jwt-file")]
    NoJwt,
    #[error("JWT is malformed: {0}")]
    JwtMalformed(String),
    #[error("kid '{0}' is malformed")]
    KidMalformed(String),
    #[error("cannot decode did:key multikey: {0}")]
    Multikey(String),
    #[error("unsupported alg '{0}'; expected EdDSA or ES256")]
    UnsupportedAlg(String),
    #[error("alg '{alg}' does not match key type {key_type}")]
    AlgKeyMismatch { alg: String, key_type: String },
    #[error("signature verification failed")]
    SignatureInvalid,
    #[error("payload.iss '{iss}' does not match expected '{expected}'")]
    IssMismatch { expected: String, iss: String },
    #[error(
        "did:key multikey is not present in the latest entry's parameters.updateKeys of '{source_did}'"
    )]
    MultikeyNotInUpdateKeys { source_did: String },
    #[error("JWT expired at {exp_iso} ({delta} ago)")]
    Expired { exp_iso: String, delta: String },
    #[error("JWT has iat in the future ({delta} ahead)")]
    NotYetIssued { delta: String },
    #[error("payload.nonce '{actual}' does not match expected '{expected}'")]
    NonceMismatch { expected: String, actual: String },
    #[error("no verification method with id '{0}' in DID document")]
    VerificationMethodMissing(String),
    #[error("DID '{source_did}' does not match kid's DID '{kid_did}'")]
    DidMismatch { kid_did: String, source_did: String },
    #[error("no entry found for '{0}'")]
    NotFound(String),
    #[error("DID document state is a JSON Patch; verify-pop only supports full snapshots")]
    PreviousStateIsPatch,
    #[error("verification-method publicKey is not a JWK; only publicKeyJwk is supported")]
    UnsupportedKeyMaterial,
    #[error("DID log is empty")]
    EmptyLog,
    #[error("cannot read JWT from '{}': {source}", path.display())]
    ReadJwt {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    Did(#[from] DIDError),
    #[error(transparent)]
    DidDoc(#[from] DIDDocError),
    #[error(transparent)]
    KeyStore(#[from] KeyStoreError),
    #[error(transparent)]
    Log(#[from] LogError),
}

pub fn cmd_verify_pop(store: &KeyStore, args: VerifyPopArgs) -> Result<(), VerifyPopError> {
    if args.jwt.is_some() && args.jwt_file.is_some() {
        return Err(VerifyPopError::AmbiguousJwt);
    }

    let jwt_text = match (&args.jwt, &args.jwt_file) {
        (Some(s), _) => s.trim().to_string(),
        (_, Some(p)) => std::fs::read_to_string(p)
            .map_err(|source| VerifyPopError::ReadJwt {
                path: p.clone(),
                source,
            })?
            .trim()
            .to_string(),
        (None, None) => return Err(VerifyPopError::NoJwt),
    };

    let parts: Vec<&str> = jwt_text.split('.').collect();
    if parts.len() != 3 {
        return Err(VerifyPopError::JwtMalformed(format!(
            "expected 3 dot-separated parts, got {}",
            parts.len()
        )));
    }

    let header: Value = decode_part_json(parts[0], "header")?;
    let payload: Value = decode_part_json(parts[1], "payload")?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| VerifyPopError::JwtMalformed(format!("signature is not base64url: {e}")))?;

    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| VerifyPopError::JwtMalformed("missing 'alg' in header".into()))?;
    if alg != "EdDSA" && alg != "ES256" {
        return Err(VerifyPopError::UnsupportedAlg(alg.to_string()));
    }

    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .ok_or_else(|| VerifyPopError::JwtMalformed("missing 'kid' in header".into()))?
        .to_string();

    let kid_shape = parse_kid(&kid)?;
    let context = resolve_context(store, &kid, &kid_shape, &args)?;

    if alg != context.key.alg() {
        return Err(VerifyPopError::AlgKeyMismatch {
            alg: alg.to_string(),
            key_type: context.key.alg().to_string(),
        });
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    context
        .key
        .verify(signing_input.as_bytes(), &signature_bytes)?;

    let iss = payload
        .get("iss")
        .and_then(Value::as_str)
        .ok_or_else(|| VerifyPopError::JwtMalformed("missing 'iss' in payload".into()))?;

    if let Some(expected) = &context.iss_constraint
        && iss != expected
    {
        return Err(VerifyPopError::IssMismatch {
            expected: expected.clone(),
            iss: iss.to_string(),
        });
    }

    let iat = payload
        .get("iat")
        .and_then(Value::as_u64)
        .ok_or_else(|| VerifyPopError::JwtMalformed("missing or non-numeric 'iat'".into()))?;
    let exp = payload
        .get("exp")
        .and_then(Value::as_u64)
        .ok_or_else(|| VerifyPopError::JwtMalformed("missing or non-numeric 'exp'".into()))?;
    let now = current_unix_seconds();

    if iat > now + IAT_SKEW_SECS {
        return Err(VerifyPopError::NotYetIssued {
            delta: human_duration(iat - now),
        });
    }

    let expired = now >= exp;
    if expired && !args.allow_expired {
        return Err(VerifyPopError::Expired {
            exp_iso: iso8601(exp),
            delta: human_duration(now - exp),
        });
    }

    let nonce = payload
        .get("nonce")
        .and_then(Value::as_str)
        .ok_or_else(|| VerifyPopError::JwtMalformed("missing 'nonce' in payload".into()))?;
    if let Some(expected) = &args.nonce
        && expected != nonce
    {
        return Err(VerifyPopError::NonceMismatch {
            expected: expected.clone(),
            actual: nonce.to_string(),
        });
    }

    print_summary(&Summary {
        alg,
        kid: &kid,
        iss,
        iat,
        exp,
        nonce,
        expired,
        now,
    });
    Ok(())
}

struct Summary<'a> {
    alg: &'a str,
    kid: &'a str,
    iss: &'a str,
    iat: u64,
    exp: u64,
    nonce: &'a str,
    expired: bool,
    now: u64,
}

fn decode_part_json(part: &str, label: &str) -> Result<Value, VerifyPopError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|e| VerifyPopError::JwtMalformed(format!("{label} is not base64url: {e}")))?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|e| VerifyPopError::JwtMalformed(format!("{label} is not JSON: {e}")))?;
    if !value.is_object() {
        return Err(VerifyPopError::JwtMalformed(format!(
            "{label} is not a JSON object"
        )));
    }
    Ok(value)
}

enum KidShape {
    DidKey { multikey: String },
    Fragment { kid_did: String },
}

fn parse_kid(kid: &str) -> Result<KidShape, VerifyPopError> {
    if let Some(rest) = kid.strip_prefix("did:key:") {
        let (multikey, frag) = rest
            .split_once('#')
            .ok_or_else(|| VerifyPopError::KidMalformed(kid.to_string()))?;
        if multikey != frag {
            return Err(VerifyPopError::KidMalformed(kid.to_string()));
        }
        Ok(KidShape::DidKey {
            multikey: multikey.to_string(),
        })
    } else {
        let (kid_did, _) = kid
            .split_once('#')
            .ok_or_else(|| VerifyPopError::KidMalformed(kid.to_string()))?;
        Ok(KidShape::Fragment {
            kid_did: kid_did.to_string(),
        })
    }
}

enum VerifyingKey {
    Eddsa(ed25519_dalek::VerifyingKey),
    Ecdsa(p256::ecdsa::VerifyingKey),
}

impl VerifyingKey {
    fn alg(&self) -> &'static str {
        match self {
            Self::Eddsa(_) => "EdDSA",
            Self::Ecdsa(_) => "ES256",
        }
    }

    fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<(), VerifyPopError> {
        match self {
            Self::Eddsa(k) => {
                let sig_arr: [u8; 64] = sig
                    .try_into()
                    .map_err(|_| VerifyPopError::SignatureInvalid)?;
                let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
                k.verify(msg, &signature)
                    .map_err(|_| VerifyPopError::SignatureInvalid)
            }
            Self::Ecdsa(k) => {
                use p256::ecdsa::signature::Verifier;
                let signature = p256::ecdsa::Signature::from_slice(sig)
                    .map_err(|_| VerifyPopError::SignatureInvalid)?;
                k.verify(msg, &signature)
                    .map_err(|_| VerifyPopError::SignatureInvalid)
            }
        }
    }
}

struct Context {
    key: VerifyingKey,
    /// Some(did) → `payload.iss` must equal this; None → iss is informational.
    iss_constraint: Option<String>,
}

fn resolve_context(
    store: &KeyStore,
    kid: &str,
    shape: &KidShape,
    args: &VerifyPopArgs,
) -> Result<Context, VerifyPopError> {
    let log_flag = args.did.is_some() || args.input.is_some();
    match shape {
        KidShape::DidKey { multikey } if log_flag => {
            let key = decode_multikey(multikey)?;
            let loaded = load_log(store, args.did.clone(), args.input.clone())?;
            let log_did = current_did(&loaded.log).ok_or(VerifyPopError::EmptyLog)?;
            let update_keys = latest_update_keys(&loaded.log);
            if !update_keys.iter().any(|k| k == multikey) {
                return Err(VerifyPopError::MultikeyNotInUpdateKeys {
                    source_did: log_did,
                });
            }
            Ok(Context {
                key,
                iss_constraint: Some(log_did),
            })
        }
        KidShape::DidKey { multikey } => {
            let key = decode_multikey(multikey)?;
            Ok(Context {
                key,
                iss_constraint: None,
            })
        }
        KidShape::Fragment { kid_did } if log_flag => {
            let loaded = load_log(store, args.did.clone(), args.input.clone())?;
            let log_did = current_did(&loaded.log).ok_or(VerifyPopError::EmptyLog)?;
            if &log_did != kid_did {
                return Err(VerifyPopError::DidMismatch {
                    kid_did: kid_did.clone(),
                    source_did: log_did,
                });
            }
            let key = find_vm_key_in_log(&loaded.log, kid)?;
            Ok(Context {
                key,
                iss_constraint: Some(kid_did.clone()),
            })
        }
        KidShape::Fragment { kid_did } => {
            let key = resolve_via_keystore(store, kid_did, kid)?;
            Ok(Context {
                key,
                iss_constraint: Some(kid_did.clone()),
            })
        }
    }
}

fn decode_multikey(s: &str) -> Result<VerifyingKey, VerifyPopError> {
    let mb = PublicKeyMultibase::try_from_string(s)
        .map_err(|e| VerifyPopError::Multikey(e.to_string()))?;
    let bytes = mb.raw_key();
    if bytes.len() < 2 {
        return Err(VerifyPopError::Multikey("payload too short".into()));
    }
    match (bytes[0], bytes[1]) {
        (0xed, 0x01) => {
            if bytes.len() != 34 {
                return Err(VerifyPopError::Multikey(format!(
                    "Ed25519 multikey must be 34 bytes, got {}",
                    bytes.len()
                )));
            }
            let key_bytes: [u8; 32] = bytes[2..].try_into().expect("checked length above");
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
                .map_err(|e| VerifyPopError::Multikey(format!("invalid Ed25519 key: {e}")))?;
            Ok(VerifyingKey::Eddsa(vk))
        }
        _ => Err(VerifyPopError::UnsupportedAlg(format!(
            "did:key multicodec {:#04x}{:02x}",
            bytes[0], bytes[1]
        ))),
    }
}

fn latest_update_keys(log: &DIDLog) -> Vec<String> {
    // did:tdw 0.3 / did:webvh 1.0: parameters.updateKeys carries forward unless rotated.
    // Find the latest entry that explicitly sets it.
    log.entries()
        .iter()
        .rev()
        .find_map(|e| e.parameters().update_keys().map(<[String]>::to_vec))
        .unwrap_or_default()
}

fn find_vm_key_in_log(log: &DIDLog, kid: &str) -> Result<VerifyingKey, VerifyPopError> {
    let last = log.entries().last().ok_or(VerifyPopError::EmptyLog)?;
    let doc_value = match last.did_doc_state() {
        DIDDocState::Value(v) => v,
        DIDDocState::Patch(_) => return Err(VerifyPopError::PreviousStateIsPatch),
    };
    let doc = DIDDoc::try_from_jsonld(doc_value)?;
    let vm = doc
        .verification_method()
        .iter()
        .find(|vm| vm.id() == kid)
        .ok_or_else(|| VerifyPopError::VerificationMethodMissing(kid.to_string()))?;
    match vm.public_key() {
        PublicKey::Jwk(jwk) => jwk_to_verifying_key(jwk),
        PublicKey::Multibase(_) => Err(VerifyPopError::UnsupportedKeyMaterial),
    }
}

fn resolve_via_keystore(
    store: &KeyStore,
    kid_did: &str,
    kid: &str,
) -> Result<VerifyingKey, VerifyPopError> {
    let did = DID::parse(kid_did)?;
    let entry = store
        .lookup(&did)?
        .ok_or_else(|| VerifyPopError::NotFound(kid_did.to_string()))?;

    let frag = kid.split_once('#').map(|(_, f)| f).unwrap_or("");
    let role = match frag {
        "authentication-key-01" => KeyRole::Authentication,
        "assertion-key-01" => KeyRole::Assertion,
        _ => return Err(VerifyPopError::VerificationMethodMissing(kid.to_string())),
    };
    debug!("resolving kid via keystore role {:?}", role);
    let signing_key = entry.load_ecdsa(role, None)?;
    Ok(VerifyingKey::Ecdsa(*signing_key.verifying_key()))
}

fn jwk_to_verifying_key(jwk: &PublicKeyJWK) -> Result<VerifyingKey, VerifyPopError> {
    match jwk {
        PublicKeyJWK::OKP(k) if k.crv() == "Ed25519" => {
            let x_bytes = URL_SAFE_NO_PAD
                .decode(k.x())
                .map_err(|e| VerifyPopError::JwtMalformed(format!("JWK 'x' not base64url: {e}")))?;
            let arr: [u8; 32] = x_bytes.try_into().map_err(|v: Vec<u8>| {
                VerifyPopError::JwtMalformed(format!(
                    "Ed25519 'x' must be 32 bytes, got {}",
                    v.len()
                ))
            })?;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&arr).map_err(|e| {
                VerifyPopError::JwtMalformed(format!("invalid Ed25519 public key: {e}"))
            })?;
            Ok(VerifyingKey::Eddsa(vk))
        }
        PublicKeyJWK::EC(k) if k.crv() == "P-256" => {
            let x_bytes = URL_SAFE_NO_PAD
                .decode(k.x())
                .map_err(|e| VerifyPopError::JwtMalformed(format!("JWK 'x' not base64url: {e}")))?;
            let y_bytes = URL_SAFE_NO_PAD
                .decode(k.y())
                .map_err(|e| VerifyPopError::JwtMalformed(format!("JWK 'y' not base64url: {e}")))?;
            let mut sec1 = Vec::with_capacity(1 + x_bytes.len() + y_bytes.len());
            sec1.push(0x04); // uncompressed point prefix
            sec1.extend_from_slice(&x_bytes);
            sec1.extend_from_slice(&y_bytes);
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).map_err(|e| {
                VerifyPopError::JwtMalformed(format!("invalid P-256 public key: {e}"))
            })?;
            Ok(VerifyingKey::Ecdsa(vk))
        }
        other => Err(VerifyPopError::UnsupportedAlg(format!(
            "{}/{}",
            other.kty(),
            other.crv().unwrap_or("?")
        ))),
    }
}

fn current_unix_seconds() -> u64 {
    Utc::now().timestamp().max(0) as u64
}

fn human_duration(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

fn print_summary(s: &Summary<'_>) {
    let _ = (|| -> std::io::Result<()> {
        use std::io::Write;
        let mut out = std::io::stdout().lock();
        writeln!(out, "PoP is valid")?;
        writeln!(out, "  alg:    {}", s.alg)?;
        writeln!(out, "  kid:    {}", s.kid)?;
        writeln!(out, "  iss:    {}", s.iss)?;
        writeln!(out, "  iat:    {}", iso8601(s.iat))?;
        let exp_iso = iso8601(s.exp);
        if s.expired {
            writeln!(
                out,
                "  exp:    {exp_iso} (expired {} ago)",
                human_duration(s.now - s.exp)
            )?;
        } else {
            writeln!(
                out,
                "  exp:    {exp_iso} (in {})",
                human_duration(s.exp - s.now)
            )?;
        }
        writeln!(out, "  nonce:  {}", s.nonce)?;
        Ok(())
    })();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::create::{CreateArgs, cmd_create};
    use crate::cmd::create_pop::{CreatePopArgs, cmd_create_pop};
    use crate::keystore::KeyStoreEntry;
    use ed25519_dalek::Signer as _;
    use serde_json::json;
    use swiyu_core::didlog::LogEntryFormat;

    fn test_did() -> DID {
        DID::parse("did:webvh:abc123:example.com").unwrap()
    }

    fn make_store() -> (tempfile::TempDir, KeyStore, KeyStoreEntry) {
        let dir = tempfile::tempdir().unwrap();
        let store = KeyStore::open_or_create(dir.path()).unwrap();
        let entry = store
            .commit(KeyStore::generate().unwrap(), &test_did())
            .unwrap();
        (dir, store, entry)
    }

    /// Build a real `did:tdw` DID (keystore + log file) via `cmd_create`.
    /// Returns (tempdir, keystore, log_path, entry).
    fn make_real_did() -> (tempfile::TempDir, KeyStore, PathBuf, KeyStoreEntry) {
        let dir = tempfile::tempdir().unwrap();
        let store = KeyStore::open_or_create(&dir.path().join("ks")).unwrap();
        let log_path = dir.path().join("did.jsonl");
        cmd_create(
            &store,
            CreateArgs {
                url: Some("https://example.com/dids/test".into()),
                swiyu: false,
                partner_id: None,
                registry_url: None,
                no_publish: false,
                format: LogEntryFormat::TDW03,
                out: log_path.clone(),
                authorized_key: None,
                authentication_key: None,
                assertion_key: None,
            },
        )
        .unwrap();
        let entry = store.list().unwrap().into_iter().next().unwrap();
        let entry = store.lookup_by_hash(&entry.hash).unwrap().unwrap();
        (dir, store, log_path, entry)
    }

    fn produce_jwt(
        store: &KeyStore,
        entry: &KeyStoreEntry,
        role: KeyRole,
        nonce: &str,
        ttl: u64,
    ) -> String {
        let outdir = tempfile::tempdir().unwrap();
        let path = outdir.path().join("pop.jwt");
        cmd_create_pop(
            store,
            CreatePopArgs {
                did: entry.hash().to_string(),
                role,
                nonce: Some(nonce.into()),
                ttl,
                version: None,
                out: Some(path.clone()),
                force: false,
            },
        )
        .unwrap();
        std::fs::read_to_string(&path).unwrap()
    }

    fn args(jwt: &str) -> VerifyPopArgs {
        VerifyPopArgs {
            jwt: Some(jwt.to_string()),
            jwt_file: None,
            did: None,
            input: None,
            nonce: None,
            allow_expired: false,
        }
    }

    fn forge_jwt_ecdsa(
        signing_key: &p256::ecdsa::SigningKey,
        kid: &str,
        payload: &Value,
    ) -> String {
        let header = json!({ "alg": "ES256", "kid": kid });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).unwrap());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }

    fn forge_jwt_eddsa(
        signing_key: &ed25519_dalek::SigningKey,
        kid: &str,
        payload: &Value,
    ) -> String {
        let header = json!({ "alg": "EdDSA", "kid": kid });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).unwrap());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig = signing_key.sign(signing_input.as_bytes()).to_bytes();
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig))
    }

    #[test]
    fn ed25519_did_key_self_contained() {
        // Without --did/--input, did:key kids are self-contained: signature only,
        // iss is informational.
        let (_dir, store, entry) = make_store();
        let jwt = produce_jwt(&store, &entry, KeyRole::Authorized, "nonce-1", 3600);
        cmd_verify_pop(&store, args(&jwt)).expect("must verify");
    }

    #[test]
    fn ed25519_did_key_with_input_validates_update_keys() {
        // With --input pointing to the DID's log, verify-pop additionally checks
        // that the multikey is in parameters.updateKeys.
        let (_dir, store, log_path, entry) = make_real_did();
        let jwt = produce_jwt(&store, &entry, KeyRole::Authorized, "n", 3600);
        let mut a = args(&jwt);
        a.input = Some(log_path);
        cmd_verify_pop(&store, a).expect("multikey is in updateKeys");
    }

    #[test]
    fn ed25519_did_key_with_input_iss_must_match_log_did() {
        let (_dir, store, log_path, entry) = make_real_did();
        let signing_key = entry.load_eddsa(KeyRole::Authorized, None).unwrap();
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let multikey =
            swiyu_core::diddoc::public_keys::ed25519_verifying_key_to_multikey(&pub_bytes);
        let kid = format!("did:key:{multikey}#{multikey}");
        let now = current_unix_seconds();
        let payload = json!({
            "iss": "did:tdw:OTHER:example.com",   // not the log's DID
            "iat": now,
            "exp": now + 3600,
            "nonce": "n",
        });
        let jwt = forge_jwt_eddsa(&signing_key, &kid, &payload);
        let mut a = args(&jwt);
        a.input = Some(log_path);
        let err = cmd_verify_pop(&store, a).unwrap_err();
        assert!(matches!(err, VerifyPopError::IssMismatch { .. }));
    }

    #[test]
    fn ed25519_did_key_with_input_unknown_multikey_rejected() {
        // Use one DID's log but sign with a *different* key whose multikey
        // is not in the log's updateKeys. Verify must reject.
        let (_dir_a, _store_a, log_path, _entry_a) = make_real_did();

        // Generate an unrelated keypair, sign manually, present a kid built from
        // the unrelated multikey.
        let mut rng = rand::rngs::OsRng;
        use rand::RngCore;
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let other_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let pub_bytes = other_key.verifying_key().to_bytes();
        let multikey =
            swiyu_core::diddoc::public_keys::ed25519_verifying_key_to_multikey(&pub_bytes);
        let kid = format!("did:key:{multikey}#{multikey}");

        // We need a separate keystore for the verifier: it must not see the
        // log's DID via keystore (but log_path provides it). The store is unused
        // for did:key resolution.
        let dir = tempfile::tempdir().unwrap();
        let store = KeyStore::open_or_create(dir.path()).unwrap();

        let now = current_unix_seconds();
        let payload = json!({
            "iss": "did:tdw:irrelevant",
            "iat": now,
            "exp": now + 3600,
            "nonce": "n",
        });
        let jwt = forge_jwt_eddsa(&other_key, &kid, &payload);
        let mut a = args(&jwt);
        a.input = Some(log_path);
        let err = cmd_verify_pop(&store, a).unwrap_err();
        assert!(matches!(
            err,
            VerifyPopError::MultikeyNotInUpdateKeys { .. }
        ));
    }

    #[test]
    fn p256_roundtrip_assertion_role() {
        let (_dir, store, entry) = make_store();
        let jwt = produce_jwt(&store, &entry, KeyRole::Assertion, "nonce-2", 3600);
        cmd_verify_pop(&store, args(&jwt)).expect("must verify");
    }

    #[test]
    fn p256_roundtrip_authentication_role() {
        let (_dir, store, entry) = make_store();
        let jwt = produce_jwt(&store, &entry, KeyRole::Authentication, "nonce-3", 3600);
        cmd_verify_pop(&store, args(&jwt)).expect("must verify");
    }

    #[test]
    fn nonce_match_is_enforced_when_provided() {
        let (_dir, store, entry) = make_store();
        let jwt = produce_jwt(&store, &entry, KeyRole::Assertion, "the-nonce", 3600);
        let mut a = args(&jwt);
        a.nonce = Some("the-nonce".into());
        cmd_verify_pop(&store, a).expect("must verify");
    }

    #[test]
    fn nonce_mismatch_is_rejected() {
        let (_dir, store, entry) = make_store();
        let jwt = produce_jwt(&store, &entry, KeyRole::Assertion, "real-nonce", 3600);
        let mut a = args(&jwt);
        a.nonce = Some("wrong-nonce".into());
        let err = cmd_verify_pop(&store, a).unwrap_err();
        assert!(matches!(err, VerifyPopError::NonceMismatch { .. }));
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let (_dir, store, entry) = make_store();
        let jwt = produce_jwt(&store, &entry, KeyRole::Assertion, "n", 3600);
        let mut parts: Vec<String> = jwt.split('.').map(String::from).collect();
        let mut sig = URL_SAFE_NO_PAD.decode(&parts[2]).unwrap();
        sig[0] ^= 0xff;
        parts[2] = URL_SAFE_NO_PAD.encode(&sig);
        let tampered = parts.join(".");
        let err = cmd_verify_pop(&store, args(&tampered)).unwrap_err();
        assert!(matches!(err, VerifyPopError::SignatureInvalid));
    }

    #[test]
    fn alg_none_is_rejected() {
        let (_dir, store, entry) = make_store();
        let jwt = produce_jwt(&store, &entry, KeyRole::Assertion, "n", 3600);
        let parts: Vec<&str> = jwt.split('.').collect();
        let header = json!({ "alg": "none", "kid": "did:tdw:xx#assertion-key-01" });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let forged = format!("{}.{}.{}", header_b64, parts[1], parts[2]);
        let err = cmd_verify_pop(&store, args(&forged)).unwrap_err();
        assert!(matches!(err, VerifyPopError::UnsupportedAlg(s) if s == "none"));
    }

    #[test]
    fn iss_mismatch_for_fragment_kid_rejected() {
        let (_dir, store, entry) = make_store();
        let signing_key = entry.load_ecdsa(KeyRole::Assertion, None).unwrap();
        let kid = format!("{}#assertion-key-01", entry.did());
        let now = current_unix_seconds();
        let payload = json!({
            "iss": "did:tdw:OTHER:example.com",
            "iat": now,
            "exp": now + 3600,
            "nonce": "n",
        });
        let jwt = forge_jwt_ecdsa(&signing_key, &kid, &payload);
        let err = cmd_verify_pop(&store, args(&jwt)).unwrap_err();
        assert!(matches!(err, VerifyPopError::IssMismatch { .. }));
    }

    #[test]
    fn expired_jwt_is_rejected_by_default() {
        let (_dir, store, entry) = make_store();
        let signing_key = entry.load_ecdsa(KeyRole::Assertion, None).unwrap();
        let kid = format!("{}#assertion-key-01", entry.did());
        let now = current_unix_seconds();
        let payload = json!({
            "iss": entry.did(),
            "iat": now - 7200,
            "exp": now - 3600,
            "nonce": "n",
        });
        let jwt = forge_jwt_ecdsa(&signing_key, &kid, &payload);
        let err = cmd_verify_pop(&store, args(&jwt)).unwrap_err();
        assert!(matches!(err, VerifyPopError::Expired { .. }));
    }

    #[test]
    fn allow_expired_accepts_expired() {
        let (_dir, store, entry) = make_store();
        let signing_key = entry.load_ecdsa(KeyRole::Assertion, None).unwrap();
        let kid = format!("{}#assertion-key-01", entry.did());
        let now = current_unix_seconds();
        let payload = json!({
            "iss": entry.did(),
            "iat": now - 7200,
            "exp": now - 3600,
            "nonce": "n",
        });
        let jwt = forge_jwt_ecdsa(&signing_key, &kid, &payload);
        let mut a = args(&jwt);
        a.allow_expired = true;
        cmd_verify_pop(&store, a).expect("--allow-expired makes this pass");
    }

    #[test]
    fn iat_in_future_is_rejected() {
        let (_dir, store, entry) = make_store();
        let signing_key = entry.load_ecdsa(KeyRole::Assertion, None).unwrap();
        let kid = format!("{}#assertion-key-01", entry.did());
        let now = current_unix_seconds();
        let payload = json!({
            "iss": entry.did(),
            "iat": now + 3600,
            "exp": now + 7200,
            "nonce": "n",
        });
        let jwt = forge_jwt_ecdsa(&signing_key, &kid, &payload);
        let err = cmd_verify_pop(&store, args(&jwt)).unwrap_err();
        assert!(matches!(err, VerifyPopError::NotYetIssued { .. }));
    }

    #[test]
    fn ambiguous_jwt_inputs_rejected() {
        let (_dir, store, _entry) = make_store();
        let mut a = args("a.b.c");
        a.jwt_file = Some(PathBuf::from("/nope"));
        let err = cmd_verify_pop(&store, a).unwrap_err();
        assert!(matches!(err, VerifyPopError::AmbiguousJwt));
    }

    #[test]
    fn no_jwt_input_rejected() {
        let (_dir, store, _entry) = make_store();
        let err = cmd_verify_pop(
            &store,
            VerifyPopArgs {
                jwt: None,
                jwt_file: None,
                did: None,
                input: None,
                nonce: None,
                allow_expired: false,
            },
        )
        .unwrap_err();
        assert!(matches!(err, VerifyPopError::NoJwt));
    }

    #[test]
    fn malformed_jwt_two_parts_rejected() {
        let (_dir, store, _entry) = make_store();
        let err = cmd_verify_pop(&store, args("only.two")).unwrap_err();
        assert!(matches!(err, VerifyPopError::JwtMalformed(_)));
    }

    #[test]
    fn jwt_file_input_works() {
        let (_dir, store, entry) = make_store();
        let jwt = produce_jwt(&store, &entry, KeyRole::Assertion, "n", 3600);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pop.jwt");
        std::fs::write(&path, &jwt).unwrap();
        cmd_verify_pop(
            &store,
            VerifyPopArgs {
                jwt: None,
                jwt_file: Some(path),
                did: None,
                input: None,
                nonce: None,
                allow_expired: false,
            },
        )
        .expect("must verify from file");
    }

    #[test]
    fn alg_eddsa_with_es256_key_mismatch_is_rejected() {
        let (_dir, store, entry) = make_store();
        let signing_key = entry.load_ecdsa(KeyRole::Assertion, None).unwrap();
        let kid = format!("{}#assertion-key-01", entry.did());
        let now = current_unix_seconds();
        let header = json!({ "alg": "EdDSA", "kid": kid });
        let payload = json!({
            "iss": entry.did(),
            "iat": now,
            "exp": now + 3600,
            "nonce": "n",
        });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
        let forged = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()));
        let err = cmd_verify_pop(&store, args(&forged)).unwrap_err();
        assert!(matches!(err, VerifyPopError::AlgKeyMismatch { .. }));
    }
}
