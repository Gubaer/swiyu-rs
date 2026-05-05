use std::path::PathBuf;

use serde_json::{Value, json};
use tracing::debug;

use swiyu_core::did::{DID, DIDError};
use swiyu_core::didlog::scid::derive_entry_hash;
use swiyu_core::didlog::{DIDDocState, LogEntryFormat};

use crate::cmd::log::{LogError, current_did, load_log};
use crate::cmd::update::{build_updated_log, compute_version_time, extract_registry_identifier};
use crate::keystore::{KeyRole, KeyStore, KeyStoreError};
use swiyu_core::proof::{Cryptosuite, DataIntegrityProof, ProofConfig, ProofPurpose};

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
    #[error(transparent)]
    WriteLog(#[from] crate::cmd::file::WriteLogError),
    #[error(transparent)]
    RegistryArgs(#[from] crate::cmd::RegistryArgsError),
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
    #[error(
        "registry upload of deactivation entry failed: {source} — entry saved to fallback file {}; retry manually with this file", path.display()
    )]
    PublishFailedPending {
        #[source]
        source: crate::swiyu::SwiyuError,
        path: PathBuf,
    },
    #[error(
        "--did used without --out and --no-publish set: the deactivation entry would have nowhere to go (use --out to save it locally, or drop --no-publish to publish to the registry)"
    )]
    NoTarget,
    #[error(transparent)]
    KeyStore(#[from] KeyStoreError),
    #[error(transparent)]
    Load(#[from] LogError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub fn cmd_deactivate(store: &KeyStore, args: DeactivateArgs) -> Result<(), DeactivateError> {
    // With --did, the log is fetched over HTTPS and there is no local file to
    // append to. Combined with --no-publish and no --out, the deactivation
    // entry would be discarded — reject early.
    if args.did.is_some() && args.out.is_none() && args.no_publish {
        return Err(DeactivateError::NoTarget);
    }

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
    let proof_config = ProofConfig {
        cryptosuite: Cryptosuite::EddsaJcs2022,
        verification_method: format!(
            "did:key:{prev_authorized_multikey}#{prev_authorized_multikey}"
        ),
        proof_purpose: ProofPurpose::Authentication,
        challenge: new_version_id.clone(),
        created: new_version_time.clone(),
    };
    let proof = Value::from(DataIntegrityProof::sign(
        &prev_authorized,
        &entry_value[3]["value"],
        proof_config,
    ));
    if let Value::Array(arr) = &mut entry_value {
        arr.push(json!([proof]));
    }

    // --- write log (atomic-rename, --out, or skip for --did without --out) ---
    let new_line = serde_json::to_string(&entry_value)?;
    let updated_log = build_updated_log(&loaded, &new_line);
    let written_to = crate::cmd::file::write_log(
        &updated_log,
        loaded.source_path.as_deref(),
        args.out.as_deref(),
        args.force,
    )?;
    if let Some(path) = &written_to {
        debug!("wrote deactivation log to {}", path.display());
    } else {
        debug!("no local log file written; persistence relies on registry publish");
    }

    // --- publish (unless --no-publish) ---
    let mut published_url: Option<String> = None;
    if !args.no_publish {
        let (partner_id, registry_url) = crate::cmd::require_registry_credentials(
            args.partner_id,
            args.registry_url,
            " (or use --no-publish)",
        )?;
        let identifier = extract_registry_identifier(&did)
            .ok_or_else(|| DeactivateError::IdentifierExtraction(did_str.clone()))?;
        debug!("publishing deactivation to registry");
        if let Err(source) = crate::swiyu::publish_entry(
            &registry_url,
            &partner_id,
            &identifier,
            updated_log.trim_end(),
        ) {
            return Err(match &written_to {
                Some(path) => DeactivateError::PublishFailed {
                    source,
                    path: path.clone(),
                },
                None => {
                    let pending = crate::cmd::file::write_pending_log(&updated_log)?;
                    DeactivateError::PublishFailedPending {
                        source,
                        path: pending,
                    }
                }
            });
        }
        published_url = Some(did.log_url());
    }

    println!("Deactivated DID: {did_str}");
    println!("New versionId: {new_version_id}");
    if let Some(path) = &written_to {
        println!("Saved DID log: {}", path.display());
    }
    if let Some(url) = published_url {
        println!("Published to registry: {url}");
    }

    Ok(())
}
