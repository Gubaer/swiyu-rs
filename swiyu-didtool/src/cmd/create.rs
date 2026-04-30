use std::path::PathBuf;

use serde_json::{Value, json};
use tracing::debug;

use swiyu_core::did::DID;
use swiyu_core::diddoc::public_keys::ed25519_verifying_key_to_multikey;
use swiyu_core::didlog::scid::{derive_entry_hash, derive_scid};
use swiyu_core::didlog::{DIDDocState, DIDLogEntry, LogEntryFormat, LogParameters};

use crate::crypto::{CryptoError, generate_ecdsa_key_pair, generate_eddsa_key_pair};
use crate::keystore::{KeyStore, KeyStoreError, StagedKeys};

pub struct CreateArgs {
    pub url: Option<String>,
    pub swiyu: bool,
    pub partner_id: Option<String>,
    pub registry_url: Option<String>,
    pub no_publish: bool,
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
    #[error("neither URL nor SWIYU mode set")]
    NoUrlSource,
    #[error("URL and SWIYU mode are mutually exclusive")]
    AmbiguousUrlSource,
    #[error(transparent)]
    RegistryArgs(#[from] crate::cmd::RegistryArgsError),
    #[error("--no-publish requires SWIYU mode")]
    NoPublishWithoutSwiyu,
    #[error(
        "DID created and saved locally, but registry upload failed: {source} — retry manually with the file at {path}"
    )]
    PublishFailed {
        #[source]
        source: crate::swiyu::SwiyuError,
        path: PathBuf,
    },
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
    if args.no_publish && !args.swiyu {
        return Err(CreateError::NoPublishWithoutSwiyu);
    }

    // --- resolve URL (and, in SWIYU mode, the registry-assigned identifier) ---
    let (url, allocation) = match (&args.url, args.swiyu) {
        (Some(_), true) => return Err(CreateError::AmbiguousUrlSource),
        (None, false) => return Err(CreateError::NoUrlSource),
        (None, true) => {
            let (partner_id, registry_url) = crate::cmd::require_registry_credentials(
                args.partner_id.clone(),
                args.registry_url.clone(),
                "",
            )?;
            debug!("allocating DID space via SWIYU identifier registry");
            let allocation = crate::swiyu::allocate_did_url(partner_id, registry_url)?;
            debug!(
                "registry returned identifierRegistryUrl: {}",
                allocation.url
            );
            (allocation.url.clone(), Some(allocation))
        }
        (Some(u), false) => (u.clone(), None),
    };

    let (domain, path) = url_to_did_components(&url)?;
    debug!("parsed URL: domain='{}', path={:?}", domain, path);

    // --- assemble key pairs ---
    let staged = prepare_keys(&args)?;
    let authorized_multikey = ed25519_verifying_key_to_multikey(staged.authorized_key_bytes());
    debug!("authorized multikey: {}", authorized_multikey);

    // --- placeholder DID (scid = None → displays as {SCID}) ---
    let did_placeholder = build_did(&args.format, None, &domain, path.as_deref())?;
    let did_placeholder_str = did_placeholder.to_string();
    debug!("DID placeholder: {}", did_placeholder_str);

    // --- genesis log entry (with {SCID} placeholders, no proof slot yet) ---
    let now = now_iso8601();
    let entry_template = build_genesis_entry(
        &args.format,
        &authorized_multikey,
        &did_placeholder_str,
        &staged,
        &now,
    );

    // Strip the proof slot before hashing; the SCID and entryHash are computed
    // over the 4-element preliminary entry per did:tdw 0.3.
    let mut prelim = entry_template.to_json();
    strip_proof_slot(&mut prelim, &args.format);

    // --- derive SCID ---
    let scid = derive_scid(&prelim);
    debug!("derived SCID: {}", scid);

    // Substitute {SCID} → scid throughout. After this the versionId field is the
    // bare SCID (no "1-" prefix), which is exactly the input shape the spec wants
    // for the genesis entryHash.
    let prelim_str = serde_json::to_string(&prelim)?;
    let with_scid_str = prelim_str.replace("{SCID}", &scid);
    let mut entry_value: Value = serde_json::from_str(&with_scid_str)?;

    // --- derive entryHash, build final versionId ---
    let entry_hash = derive_entry_hash(&entry_value);
    debug!("derived entryHash: {}", entry_hash);
    let version_id = format!("1-{entry_hash}");
    set_version_id(&mut entry_value, &version_id, &args.format);

    // --- real DID ---
    let real_did = build_did(&args.format, Some(scid.clone()), &domain, path.as_deref())?;
    let real_did_str = real_did.to_string();
    debug!("DID: {}", real_did_str);

    // --- data integrity proof ---
    // The DID Toolbox (Java) hashes only the DID document content — i.e.
    // entry[3]["value"] for did:tdw, entry["state"]["value"] for did:webvh —
    // not the entire log entry. We mirror that to match its signature bytes.
    let document_for_hash = match args.format {
        LogEntryFormat::TDW03 => entry_value[3]["value"].clone(),
        LogEntryFormat::WebVH10 => entry_value["state"]["value"].clone(),
    };
    let proof_purpose = match args.format {
        LogEntryFormat::TDW03 => "authentication",
        LogEntryFormat::WebVH10 => "assertionMethod",
    };
    let proof = super::proof::build_proof(
        staged.authorized_signing(),
        &document_for_hash,
        &authorized_multikey,
        &version_id,
        proof_purpose,
        &now,
    );
    append_proof(&mut entry_value, proof, &args.format);

    // --- write DID log ---
    let line = serde_json::to_string(&entry_value)? + "\n";
    std::fs::write(&args.out, &line).map_err(|e| CreateError::WriteLog(args.out.clone(), e))?;
    debug!("wrote DID log to {}", args.out.display());

    // --- commit keys to key store ---
    let entry = store.commit(staged, &real_did)?;
    debug!("committed keys to key store (hash: {})", entry.hash());

    // --- publish to registry (SWIYU mode only, unless --no-publish) ---
    let published_url = if let Some(allocation) = &allocation
        && !args.no_publish
    {
        let partner_id = args
            .partner_id
            .as_deref()
            .expect("partner-id checked above");
        let registry_url = args
            .registry_url
            .as_deref()
            .expect("registry-url checked above");
        debug!("publishing DID log entry to registry");
        crate::swiyu::publish_entry(
            registry_url,
            partner_id,
            &allocation.identifier,
            line.trim_end(),
        )
        .map_err(|source| CreateError::PublishFailed {
            source,
            path: args.out.clone(),
        })?;
        debug!("published to {}", allocation.url);
        Some(allocation.url.as_str())
    } else {
        None
    };

    // --- report ---
    println!("Generated DID: {real_did_str}");
    println!("Saved DID log entry: {}", args.out.display());
    println!("Keystore hash: {}", entry.hash());
    if let Some(url) = published_url {
        println!("Published to registry: {url}");
    }

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

    let genesis_doc = super::diddoc::build_did_doc(did_placeholder_str, staged);
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

fn strip_proof_slot(entry: &mut Value, format: &LogEntryFormat) {
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

fn set_version_id(entry: &mut Value, version_id: &str, format: &LogEntryFormat) {
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

fn append_proof(entry: &mut Value, proof: Value, format: &LogEntryFormat) {
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

fn now_iso8601() -> String {
    // Backdate by a few seconds so a small client/server clock skew doesn't push
    // versionTime past the registry's "now" (the SWIYU registry rejects entries
    // whose versionTime is not strictly in the past).
    (chrono::Utc::now() - chrono::Duration::seconds(5))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
