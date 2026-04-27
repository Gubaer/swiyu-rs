use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::EncodedPoint;
use serde_json::{Value, json};
use tracing::debug;

use swiyu_core::did::DID;
use swiyu_core::diddoc::public_keys::ed25519_verifying_key_to_multikey;
use swiyu_core::didlog::scid::derive_from_genesis_entry;
use swiyu_core::didlog::{
    DIDDocState, DIDLogEntry, LogEntryFormat, LogParameters, eddsa_jcs_2022_hash,
};

use crate::crypto::{CryptoError, generate_ecdsa_key_pair, generate_eddsa_key_pair};
use crate::keystore::{KeyStore, KeyStoreError, StagedKeys};

pub struct CreateArgs {
    pub url: Option<String>,
    pub swiyu: bool,
    pub partner_id: Option<String>,
    pub registry_url: Option<String>,
    pub format: LogEntryFormat,
    pub out: PathBuf,
    pub authorized_key: Option<PathBuf>,
    pub authentication_key: Option<PathBuf>,
    pub assertion_key: Option<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
pub enum CreateError {
    #[error("{0}")]
    Url(String),
    #[error("--authorized-key: {0}")]
    AuthorizedKey(CryptoError),
    #[error("--authentication-key: {0}")]
    AuthenticationKey(CryptoError),
    #[error("--assertion-key: {0}")]
    AssertionKey(CryptoError),
    #[error("--authentication-key and --assertion-key must differ")]
    IdenticalKeys,
    #[error("provide a <url> or --swiyu")]
    NoUrlSource,
    #[error("<url> and --swiyu are mutually exclusive")]
    AmbiguousUrlSource,
    #[error("provide --partner-id or set SWIYU_PARTNER_ID")]
    PartnerIdMissing,
    #[error("provide --registry-url or set SWIYU_IDENTIFIER_REGISTRY_URL")]
    RegistryUrlMissing,
    #[error("cannot write '{0}': {1}")]
    WriteLog(PathBuf, std::io::Error),
    #[error(transparent)]
    KeyStore(#[from] KeyStoreError),
    #[error(transparent)]
    Did(#[from] swiyu_core::did::DIDError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Swiyu(#[from] crate::swiyu::SwiyuError),
}

pub fn cmd_create(store: &KeyStore, args: CreateArgs) -> Result<(), CreateError> {
    // --- resolve URL ---
    let url = match (&args.url, args.swiyu) {
        (Some(_), true) => return Err(CreateError::AmbiguousUrlSource),
        (None, false) => return Err(CreateError::NoUrlSource),
        (None, true) => {
            let partner_id = args
                .partner_id
                .clone()
                .ok_or(CreateError::PartnerIdMissing)?;
            let registry_url = args
                .registry_url
                .clone()
                .ok_or(CreateError::RegistryUrlMissing)?;
            debug!("allocating DID space via SWIYU identifier registry");
            let url = crate::swiyu::allocate_did_url(partner_id, registry_url)?;
            debug!("registry returned identifierRegistryUrl: {}", url);
            url
        }
        (Some(u), false) => u.clone(),
    };

    let (domain, path) = url_to_did_components(&url)?;
    debug!("parsed URL: domain='{}', path={:?}", domain, path);

    // --- assemble key pairs ---
    let staged = prepare_keys(&args)?;
    let authorized_multikey =
        ed25519_verifying_key_to_multikey(staged.authorized_verifying_key().as_bytes());
    debug!("authorized multikey: {}", authorized_multikey);

    // --- placeholder DID (scid = None → displays as {SCID}) ---
    let did_placeholder = build_did(&args.format, None, &domain, path.as_deref())?;
    let did_placeholder_str = did_placeholder.to_string();
    debug!("DID placeholder: {}", did_placeholder_str);

    // --- genesis log entry (with {SCID} everywhere, empty proof) ---
    let now = now_iso8601();
    let entry_template = build_genesis_entry(
        &args.format,
        &authorized_multikey,
        &did_placeholder_str,
        &staged,
        &now,
    );
    let template_json = serde_json::to_string(&entry_template.to_json())?;

    // --- derive SCID ---
    let scid = derive_from_genesis_entry(&template_json);
    debug!("derived SCID: {}", scid);

    // --- replace placeholders ---
    let entry_str = template_json.replace("{SCID}", &scid);
    let mut entry_value: Value = serde_json::from_str(&entry_str)?;

    // --- real DID ---
    let real_did = build_did(&args.format, Some(scid), &domain, path.as_deref())?;
    let real_did_str = real_did.to_string();
    debug!("DID: {}", real_did_str);

    // --- data integrity proof ---
    let proof = build_proof(&staged, &entry_value, &real_did_str, &now);
    add_proof(&mut entry_value, proof, &args.format);

    // --- write DID log ---
    let line = serde_json::to_string(&entry_value)? + "\n";
    std::fs::write(&args.out, &line).map_err(|e| CreateError::WriteLog(args.out.clone(), e))?;
    debug!("wrote DID log to {}", args.out.display());

    // --- commit keys to key store ---
    let entry = store.commit(staged, &real_did)?;
    debug!("committed keys to key store (hash: {})", entry.hash());

    // --- report ---
    println!("Generated DID: {real_did_str}");
    println!("Saved DID log entry: {}", args.out.display());
    println!("Keystore hash: {}", entry.hash());

    Ok(())
}

// --- helpers ---

fn url_to_did_components(url: &str) -> Result<(String, Option<String>), CreateError> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| CreateError::Url(format!("URL must use https:// scheme: {url}")))?;

    let (host, path_str) = match rest.find('/') {
        Some(pos) => (&rest[..pos], &rest[pos + 1..]),
        None => (rest, ""),
    };

    if host.is_empty() {
        return Err(CreateError::Url("URL is missing a host".into()));
    }

    // Percent-encode port separator so it survives the DID colon-separator syntax.
    let did_host = match host.find(':') {
        Some(pos) => format!("{}%3A{}", &host[..pos], &host[pos + 1..]),
        None => host.to_string(),
    };

    let mut segments: Vec<&str> = path_str.split('/').filter(|s| !s.is_empty()).collect();

    // did.jsonl is the filename, not a path segment in the DID.
    if segments.last() == Some(&"did.jsonl") {
        segments.pop();
    }

    // /.well-known/ is the implicit root path — no path component in the DID.
    let did_path = if segments.is_empty() || segments == [".well-known"] {
        None
    } else {
        Some(segments.join(":"))
    };

    Ok((did_host, did_path))
}

fn build_did(
    format: &LogEntryFormat,
    scid: Option<String>,
    domain: &str,
    path: Option<&str>,
) -> Result<DID, swiyu_core::did::DIDError> {
    match format {
        LogEntryFormat::TDW03 => {
            DID::try_new_tdw(scid, domain.to_string(), path.map(str::to_string))
        }
        LogEntryFormat::WebVH10 => {
            DID::try_new_webvh(scid, domain.to_string(), path.map(str::to_string))
        }
    }
}

fn prepare_keys(args: &CreateArgs) -> Result<StagedKeys, CreateError> {
    // Authorized key (Ed25519)
    let authorized_signing = match &args.authorized_key {
        Some(path) => {
            debug!("importing authorized Ed25519 key from {}", path.display());
            let key =
                crate::crypto::read_private_key_eddsa(path).map_err(CreateError::AuthorizedKey)?;
            debug!("derived authorized public key");
            key
        }
        None => {
            debug!("generating authorized Ed25519 key pair");
            generate_eddsa_key_pair().0
        }
    };

    // Authentication key (P-256)
    let authentication_signing = match &args.authentication_key {
        Some(path) => {
            debug!("importing authentication P-256 key from {}", path.display());
            let key = crate::crypto::read_private_key_ecdsa(path)
                .map_err(CreateError::AuthenticationKey)?;
            debug!("derived authentication public key");
            key
        }
        None => {
            debug!("generating authentication P-256 key pair");
            generate_ecdsa_key_pair().0
        }
    };

    // Assertion key (P-256)
    let assertion_signing = match &args.assertion_key {
        Some(path) => {
            debug!("importing assertion P-256 key from {}", path.display());
            let key =
                crate::crypto::read_private_key_ecdsa(path).map_err(CreateError::AssertionKey)?;
            debug!("derived assertion public key");
            key
        }
        None => {
            debug!("generating assertion P-256 key pair");
            generate_ecdsa_key_pair().0
        }
    };

    // authentication and assertion must be different keys
    if args.authentication_key.is_some()
        && args.assertion_key.is_some()
        && authentication_signing.verifying_key() == assertion_signing.verifying_key()
    {
        return Err(CreateError::IdenticalKeys);
    }

    Ok(StagedKeys::from_parts(
        authorized_signing,
        authentication_signing,
        assertion_signing,
    ))
}

fn build_genesis_entry(
    format: &LogEntryFormat,
    authorized_multikey: &str,
    did_placeholder_str: &str,
    staged: &StagedKeys,
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
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        LogEntryFormat::WebVH10 => LogParameters::new_webvh(
            Some(method_str.into()),
            Some("{SCID}".into()),
            Some(vec![authorized_multikey.into()]),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ),
    };

    let genesis_doc = build_genesis_doc(did_placeholder_str, staged);
    let state = DIDDocState::Value(genesis_doc);

    match format {
        LogEntryFormat::TDW03 => {
            DIDLogEntry::new_tdw("1-{SCID}".into(), now.into(), parameters, state, vec![])
        }
        LogEntryFormat::WebVH10 => {
            DIDLogEntry::new_webvh("1-{SCID}".into(), now.into(), parameters, state, vec![])
        }
    }
}

fn build_genesis_doc(did: &str, staged: &StagedKeys) -> Value {
    let authorized_vm_id = format!("{did}#authorized-key-01");
    let auth_vm_id = format!("{did}#authentication-key-01");
    let assert_vm_id = format!("{did}#assertion-key-01");

    let authorized_jwk = okp_jwk_for_ed25519(staged.authorized_verifying_key().as_bytes());
    let auth_jwk = ec_jwk_for_p256(
        staged
            .authentication_verifying_key()
            .to_encoded_point(false),
    );
    let assert_jwk = ec_jwk_for_p256(staged.assertion_verifying_key().to_encoded_point(false));

    json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1"
        ],
        "id": did,
        "verificationMethod": [
            {
                "id": authorized_vm_id,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": authorized_jwk
            },
            {
                "id": auth_vm_id,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": auth_jwk
            },
            {
                "id": assert_vm_id,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": assert_jwk
            }
        ],
        "authentication": [auth_vm_id],
        "assertionMethod": [assert_vm_id],
        "capabilityInvocation": [authorized_vm_id]
    })
}

fn okp_jwk_for_ed25519(key_bytes: &[u8; 32]) -> Value {
    json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": URL_SAFE_NO_PAD.encode(key_bytes)
    })
}

fn ec_jwk_for_p256(point: EncodedPoint) -> Value {
    json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(point.x().expect("uncompressed point has x")),
        "y": URL_SAFE_NO_PAD.encode(point.y().expect("uncompressed point has y"))
    })
}

fn build_proof(staged: &StagedKeys, entry: &Value, did_str: &str, now: &str) -> Value {
    let vm_id = format!("{did_str}#authorized-key-01");
    let proof_config = json!({
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": vm_id,
        "proofPurpose": "assertionMethod",
        "created": now
    });

    let hash_data = eddsa_jcs_2022_hash(entry, &proof_config);
    let sig_bytes = staged.sign_with_authorized(&hash_data);
    let proof_value = format!("z{}", bs58::encode(sig_bytes).into_string());

    let mut proof = proof_config.as_object().unwrap().clone();
    proof.insert("proofValue".into(), json!(proof_value));
    Value::Object(proof)
}

fn add_proof(entry: &mut Value, proof: Value, format: &LogEntryFormat) {
    match format {
        LogEntryFormat::TDW03 => {
            if let Some(arr) = entry.as_array_mut()
                && arr.len() == 5
            {
                arr[4] = json!([proof]);
            }
        }
        LogEntryFormat::WebVH10 => {
            if let Some(obj) = entry.as_object_mut() {
                obj.insert("proof".into(), json!([proof]));
            }
        }
    }
}

fn now_iso8601() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
