use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use tracing::debug;

use swiyu_core::did::{DID, DIDError};
use swiyu_core::didlog::scid::derive_entry_hash;
use swiyu_core::didlog::{DIDDocState, LogEntryFormat};

use crate::cmd::log::{LogError, current_did, load_log};
use crate::cmd::update::{
    build_proof, build_updated_log, compute_version_time, extract_registry_identifier, write_atomic,
};
use crate::keystore::{KeyRole, KeyStore, KeyStoreError};

pub struct DeactivateArgs {
    pub did: Option<String>,
    pub input: Option<PathBuf>,
    pub out: Option<PathBuf>,
    pub force: bool,
    pub no_publish: bool,
    pub partner_id: Option<String>,
    pub registry_url: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum DeactivateError {
    #[error("DID is already deactivated (latest entry's parameters.deactivated == true)")]
    AlreadyDeactivated,
    #[error("DID log is empty — nothing to deactivate")]
    EmptyLog,
    #[error("could not extract a DID from the log (no entry has a Value state)")]
    DidNotInLog,
    #[error("DID log uses an unsupported format for deactivate (only did:tdw 0.3 is supported)")]
    UnsupportedFormat,
    #[error("latest entry's state is a Patch — full DID document required for deactivate")]
    PreviousStateIsPatch,
    #[error("invalid DID '{0}': {1}")]
    Did(String, DIDError),
    #[error("no key store entry for DID '{0}' — cannot sign deactivate entry")]
    KeyStoreMiss(String),
    #[error("--did/HTTPS source: --out is required (cannot append in place)")]
    OutRequiredForRemote,
    #[error("file '{}' already exists; pass --force to overwrite", path.display())]
    FileExists { path: PathBuf },
    #[error("cannot write '{}': {source}", path.display())]
    WriteOutput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("provide --partner-id or set SWIYU_PARTNER_ID (or use --no-publish)")]
    PartnerIdMissing,
    #[error("provide --registry-url or set SWIYU_IDENTIFIER_REGISTRY_URL (or use --no-publish)")]
    RegistryUrlMissing,
    #[error("cannot extract registry identifier (UUID) from DID '{0}'")]
    IdentifierExtraction(String),
    #[error(
        "DID log deactivated and saved locally, but registry upload failed: {source} — retry manually with the file at {}", path.display()
    )]
    PublishFailed {
        #[source]
        source: crate::swiyu::SwiyuError,
        path: PathBuf,
    },
    #[error(transparent)]
    KeyStore(#[from] KeyStoreError),
    #[error(transparent)]
    Load(#[from] LogError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub fn cmd_deactivate(store: &KeyStore, args: DeactivateArgs) -> Result<(), DeactivateError> {
    // --- load existing log ---
    let loaded = load_log(store, args.did.clone(), args.input.clone())?;
    if loaded.log.entries().is_empty() {
        return Err(DeactivateError::EmptyLog);
    }
    let last = loaded.log.entries().last().unwrap();
    if !matches!(last.format(), LogEntryFormat::TDW03) {
        return Err(DeactivateError::UnsupportedFormat);
    }
    if last.parameters().deactivated() == Some(true) {
        return Err(DeactivateError::AlreadyDeactivated);
    }
    let prev_version_id = last.version_id().to_string();
    let prev_version_time = last.version_time().to_string();

    // --- previous DID document (used unchanged in the deactivation entry) ---
    let prev_doc = match last.did_doc_state() {
        DIDDocState::Value(v) => v.clone(),
        DIDDocState::Patch(_) => return Err(DeactivateError::PreviousStateIsPatch),
    };

    // --- resolve DID + previous key store entry ---
    let did_str = current_did(&loaded.log).ok_or(DeactivateError::DidNotInLog)?;
    let did = DID::parse(&did_str).map_err(|e| DeactivateError::Did(did_str.clone(), e))?;
    let entry = store
        .lookup(&did)?
        .ok_or_else(|| DeactivateError::KeyStoreMiss(did_str.clone()))?;
    let prev_version = entry.latest_version()?;
    let prev_authorized = entry.load_eddsa(KeyRole::Authorized, Some(prev_version))?;
    let prev_authorized_multikey =
        swiyu_core::diddoc::public_keys::ed25519_verifying_key_to_multikey(
            prev_authorized.verifying_key().as_bytes(),
        );

    // --- new versionTime ---
    let new_version_time = compute_version_time(&prev_version_time);

    // --- build the 4-element entry for hashing ---
    let parameters = json!({
        "deactivated": true,
        "updateKeys": [],
    });
    let mut entry_value = json!([
        prev_version_id,
        new_version_time.clone(),
        parameters,
        json!({ "value": prev_doc }),
    ]);

    let entry_hash = derive_entry_hash(&entry_value);
    let next_seq = loaded.log.entries().len() as u32 + 1;
    let new_version_id = format!("{next_seq}-{entry_hash}");
    debug!("derived entryHash: {}", entry_hash);
    debug!("new versionId: {}", new_version_id);
    entry_value[0] = json!(new_version_id);

    // --- proof: signed by the current authorized key ---
    let proof = build_proof(
        &prev_authorized,
        &entry_value[3]["value"],
        &prev_authorized_multikey,
        &new_version_id,
        "authentication",
        &new_version_time,
    );
    if let Value::Array(arr) = &mut entry_value {
        arr.push(json!([proof]));
    }

    // --- write log ---
    let new_line = serde_json::to_string(&entry_value)?;
    let updated_log = build_updated_log(&loaded, &new_line);
    let written_to = write_log(&updated_log, &loaded.source_path, &args)?;
    debug!("wrote deactivation log to {}", written_to.display());

    // --- publish (unless --no-publish) ---
    let mut published_url: Option<String> = None;
    if !args.no_publish {
        let partner_id = args.partner_id.ok_or(DeactivateError::PartnerIdMissing)?;
        let registry_url = args
            .registry_url
            .ok_or(DeactivateError::RegistryUrlMissing)?;
        let identifier = extract_registry_identifier(&did)
            .ok_or_else(|| DeactivateError::IdentifierExtraction(did_str.clone()))?;
        debug!("publishing deactivation to registry");
        crate::swiyu::publish_entry(
            &registry_url,
            &partner_id,
            &identifier,
            updated_log.trim_end(),
        )
        .map_err(|source| DeactivateError::PublishFailed {
            source,
            path: written_to.clone(),
        })?;
        published_url = Some(did.log_url());
    }

    println!("Deactivated DID: {did_str}");
    println!("New versionId: {new_version_id}");
    println!("Saved DID log: {}", written_to.display());
    if let Some(url) = published_url {
        println!("Published to registry: {url}");
    }

    Ok(())
}

fn write_log(
    content: &str,
    source_path: &Option<PathBuf>,
    args: &DeactivateArgs,
) -> Result<PathBuf, DeactivateError> {
    if let Some(path) = &args.out {
        if path.exists() && !args.force {
            return Err(DeactivateError::FileExists { path: path.clone() });
        }
        fs::write(path, content).map_err(|source| DeactivateError::WriteOutput {
            path: path.clone(),
            source,
        })?;
        return Ok(path.clone());
    }
    let source: PathBuf = source_path
        .clone()
        .ok_or(DeactivateError::OutRequiredForRemote)?;
    write_atomic(Path::new(&source), content).map_err(|source_err| {
        DeactivateError::WriteOutput {
            path: source.clone(),
            source: source_err,
        }
    })?;
    Ok(source)
}
