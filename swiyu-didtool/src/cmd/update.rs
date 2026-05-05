use std::path::PathBuf;

use serde_json::{Value, json};
use tracing::debug;

use swiyu_core::did::{DID, DIDError};
use swiyu_core::diddoc::DIDDoc;
use swiyu_core::diddoc::public_keys::ed25519_verifying_key_to_multikey;
use swiyu_core::didlog::scid::derive_entry_hash;
use swiyu_core::proof::{Cryptosuite, DataIntegrityProof, ProofConfig, ProofPurpose};

use crate::cmd::log::{LoadedLog, LogError, current_did, load_log};
use crate::crypto::{
    CryptoError, generate_ecdsa_key_pair, generate_eddsa_key_pair, read_private_key_ecdsa,
    read_private_key_eddsa,
};
use crate::keystore::{KeyRole, KeyStore, KeyStoreEntry, KeyStoreError, StagedKeys};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RotateRole {
    Authorized,
    Authentication,
    Assertion,
    All,
}

pub struct UpdateArgs {
    pub did: Option<String>,
    pub input: Option<PathBuf>,
    pub rotate: Vec<RotateRole>,
    pub authorized_key: Option<PathBuf>,
    pub authentication_key: Option<PathBuf>,
    pub assertion_key: Option<PathBuf>,
    pub out: Option<PathBuf>,
    pub force: bool,
    pub no_publish: bool,
    pub partner_id: Option<String>,
    pub registry_url: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("nothing to update — pass at least one --rotate <role> or --<role>-key flag")]
    NoChange,
    #[error("--rotate {role} and --{role}-key are mutually exclusive")]
    ConflictingRotation { role: &'static str },
    #[error(transparent)]
    WriteLog(#[from] crate::cmd::file::WriteLogError),
    #[error("DID log is empty — nothing to update against")]
    EmptyLog,
    #[error("could not extract a DID from the log (no entry has a Value state)")]
    DidNotInLog,
    #[error("DID log uses an unsupported format for update (only did:tdw 0.3 is supported)")]
    UnsupportedFormat,
    #[error("invalid DID '{0}': {1}")]
    Did(String, DIDError),
    #[error("no key store entry for DID '{0}' — cannot sign update")]
    KeyStoreMiss(String),
    #[error("--{role}-key: {source}")]
    KeyImport {
        role: &'static str,
        #[source]
        source: CryptoError,
    },
    #[error(transparent)]
    RegistryArgs(#[from] crate::cmd::RegistryArgsError),
    #[error("cannot extract registry identifier (UUID) from DID '{0}'")]
    IdentifierExtraction(String),
    #[error(
        "DID log updated and saved locally, but registry upload failed: {source} — retry manually with the file at {}", path.display()
    )]
    PublishFailed {
        #[source]
        source: crate::swiyu::SwiyuError,
        path: PathBuf,
    },
    #[error(
        "registry upload of new DID log failed: {source} — new entry saved to fallback file {}; retry manually with this file", path.display()
    )]
    PublishFailedPending {
        #[source]
        source: crate::swiyu::SwiyuError,
        path: PathBuf,
    },
    #[error(
        "--did used without --out and --no-publish set: the new log entry would have nowhere to go (use --out to save it locally, or drop --no-publish to publish to the registry)"
    )]
    NoTarget,
    #[error(transparent)]
    KeyStore(#[from] KeyStoreError),
    #[error(transparent)]
    Load(#[from] LogError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub fn cmd_update(store: &KeyStore, args: UpdateArgs) -> Result<(), UpdateError> {
    let plan = plan_rotation(&args)?;

    // With --did, the log is fetched over HTTPS and there is no local file to
    // append to. Combined with --no-publish and no --out, the new entry would
    // be discarded — reject early.
    if args.did.is_some() && args.out.is_none() && args.no_publish {
        return Err(UpdateError::NoTarget);
    }

    // --- load existing log ---
    let loaded = load_log(store, args.did.clone(), args.input.clone())?;
    if loaded.log.entries().is_empty() {
        return Err(UpdateError::EmptyLog);
    }
    let last = loaded.log.entries().last().unwrap();
    if !matches!(last.format(), swiyu_core::didlog::LogEntryFormat::TDW03) {
        return Err(UpdateError::UnsupportedFormat);
    }
    let prev_version_id = last.version_id().to_string();
    let prev_version_time = last.version_time().to_string();

    // --- resolve DID + previous key store entry ---
    let did_str = current_did(&loaded.log).ok_or(UpdateError::DidNotInLog)?;
    let did = DID::parse(&did_str).map_err(|e| UpdateError::Did(did_str.clone(), e))?;
    let entry = store
        .lookup(&did)?
        .ok_or_else(|| UpdateError::KeyStoreMiss(did_str.clone()))?;
    let prev_version = entry.latest_version()?;
    debug!(
        "key store entry hash {} at version {}",
        entry.hash(),
        prev_version
    );

    // --- previous authorized key (used to sign the new entry) ---
    let prev_authorized = entry.load_eddsa(KeyRole::Authorized, Some(prev_version))?;
    let prev_authorized_multikey =
        ed25519_verifying_key_to_multikey(prev_authorized.verifying_key().as_bytes());

    // --- stage new key set ---
    let staged = stage_keys(&entry, prev_version, &plan)?;
    let new_authorized_multikey = ed25519_verifying_key_to_multikey(staged.authorized_key_bytes());
    let authorized_rotated = prev_authorized_multikey != new_authorized_multikey;
    debug!("authorized rotated: {}", authorized_rotated);

    // --- new DID document ---
    let new_doc = DIDDoc::new_genesis(
        &did_str,
        &staged.authentication_key_coords(),
        &staged.assertion_key_coords(),
    );

    // --- parameters: only changed fields ---
    let mut params = serde_json::Map::new();
    if authorized_rotated {
        params.insert("updateKeys".into(), json!([new_authorized_multikey]));
    }
    let parameters = Value::Object(params);

    // --- versionTime: max(now − 5s, prev + 1s), ISO-8601 UTC ---
    let new_version_time = compute_version_time(&prev_version_time);
    debug!("new versionTime: {}", new_version_time);

    // --- build the 4-element entry for hashing (proof slot excluded) ---
    let mut entry_value = json!([
        prev_version_id,
        new_version_time.clone(),
        parameters,
        json!({ "value": Value::from(new_doc) }),
    ]);

    let entry_hash = derive_entry_hash(&entry_value);
    let next_seq = loaded.log.entries().len() as u32 + 1;
    let new_version_id = format!("{next_seq}-{entry_hash}");
    debug!("derived entryHash: {}", entry_hash);
    debug!("new versionId: {}", new_version_id);
    entry_value[0] = json!(new_version_id);

    // --- proof: signed by previous authorized key, hashes only the DID document ---
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
        debug!("wrote updated DID log to {}", path.display());
    } else {
        debug!("no local log file written; persistence relies on registry publish");
    }

    // --- commit new keys to key store ---
    let new_version = entry.add_version(staged)?;
    debug!("committed key store version {}", new_version);

    // --- publish to registry (unless --no-publish) ---
    let mut published_url: Option<String> = None;
    if !args.no_publish {
        let (partner_id, registry_url) = crate::cmd::require_registry_credentials(
            args.partner_id,
            args.registry_url,
            " (or use --no-publish)",
        )?;
        let identifier = extract_registry_identifier(&did)
            .ok_or_else(|| UpdateError::IdentifierExtraction(did_str.clone()))?;
        debug!("publishing updated DID log to registry");
        if let Err(source) = crate::swiyu::publish_entry(
            &registry_url,
            &partner_id,
            &identifier,
            updated_log.trim_end(),
        ) {
            return Err(match &written_to {
                Some(path) => UpdateError::PublishFailed {
                    source,
                    path: path.clone(),
                },
                None => {
                    let pending = crate::cmd::file::write_pending_log(&updated_log)?;
                    UpdateError::PublishFailedPending {
                        source,
                        path: pending,
                    }
                }
            });
        }
        published_url = Some(did.log_url());
        debug!("published to {}", published_url.as_deref().unwrap_or(""));
    }

    println!("Updated DID: {did_str}");
    println!("New versionId: {new_version_id}");
    if let Some(path) = &written_to {
        println!("Saved DID log: {}", path.display());
    }
    println!("Keystore hash: {}", entry.hash());
    println!("Keystore version: {new_version}");
    if let Some(url) = published_url {
        println!("Published to registry: {url}");
    }

    Ok(())
}

/// Extracts the trailing path segment of a DID (the SWIYU registry's `<uuid>`).
pub(super) fn extract_registry_identifier(did: &DID) -> Option<String> {
    did.path()
        .and_then(|p| p.rsplit(':').next())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

// ---------------------------------------------------------------------------
// Rotation planning

#[derive(Debug, Clone, PartialEq)]
enum Action {
    Keep,
    Generate,
    Import(PathBuf),
}

#[derive(Debug)]
struct Plan {
    authorized: Action,
    authentication: Action,
    assertion: Action,
}

fn plan_rotation(args: &UpdateArgs) -> Result<Plan, UpdateError> {
    let mut auth = Action::Keep;
    let mut authn = Action::Keep;
    let mut assert = Action::Keep;

    for role in &args.rotate {
        match role {
            RotateRole::Authorized => auth = Action::Generate,
            RotateRole::Authentication => authn = Action::Generate,
            RotateRole::Assertion => assert = Action::Generate,
            RotateRole::All => {
                auth = Action::Generate;
                authn = Action::Generate;
                assert = Action::Generate;
            }
        }
    }

    if let Some(path) = &args.authorized_key {
        if matches!(auth, Action::Generate) {
            return Err(UpdateError::ConflictingRotation { role: "authorized" });
        }
        auth = Action::Import(path.clone());
    }
    if let Some(path) = &args.authentication_key {
        if matches!(authn, Action::Generate) {
            return Err(UpdateError::ConflictingRotation {
                role: "authentication",
            });
        }
        authn = Action::Import(path.clone());
    }
    if let Some(path) = &args.assertion_key {
        if matches!(assert, Action::Generate) {
            return Err(UpdateError::ConflictingRotation { role: "assertion" });
        }
        assert = Action::Import(path.clone());
    }

    if matches!(auth, Action::Keep)
        && matches!(authn, Action::Keep)
        && matches!(assert, Action::Keep)
    {
        return Err(UpdateError::NoChange);
    }

    Ok(Plan {
        authorized: auth,
        authentication: authn,
        assertion: assert,
    })
}

fn stage_keys(entry: &KeyStoreEntry, version: u32, plan: &Plan) -> Result<StagedKeys, UpdateError> {
    let authorized = match &plan.authorized {
        Action::Keep => entry.load_eddsa(KeyRole::Authorized, Some(version))?,
        Action::Generate => {
            debug!("generating new authorized Ed25519 key pair");
            generate_eddsa_key_pair().0
        }
        Action::Import(p) => {
            debug!("importing authorized Ed25519 key from {}", p.display());
            read_private_key_eddsa(p).map_err(|source| UpdateError::KeyImport {
                role: "authorized",
                source,
            })?
        }
    };
    let authentication = match &plan.authentication {
        Action::Keep => entry.load_ecdsa(KeyRole::Authentication, Some(version))?,
        Action::Generate => {
            debug!("generating new authentication P-256 key pair");
            generate_ecdsa_key_pair().0
        }
        Action::Import(p) => {
            debug!("importing authentication P-256 key from {}", p.display());
            read_private_key_ecdsa(p).map_err(|source| UpdateError::KeyImport {
                role: "authentication",
                source,
            })?
        }
    };
    let assertion = match &plan.assertion {
        Action::Keep => entry.load_ecdsa(KeyRole::Assertion, Some(version))?,
        Action::Generate => {
            debug!("generating new assertion P-256 key pair");
            generate_ecdsa_key_pair().0
        }
        Action::Import(p) => {
            debug!("importing assertion P-256 key from {}", p.display());
            read_private_key_ecdsa(p).map_err(|source| UpdateError::KeyImport {
                role: "assertion",
                source,
            })?
        }
    };
    Ok(StagedKeys::from_parts(
        authorized,
        authentication,
        assertion,
    ))
}

pub(super) fn compute_version_time(prev_version_time: &str) -> String {
    // Backdate by 5 s to absorb client clock skew, but never earlier than (prev + 1 s).
    let now = chrono::Utc::now() - chrono::Duration::seconds(5);
    let prev = chrono::DateTime::parse_from_rfc3339(prev_version_time)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc));
    let candidate = match prev {
        Some(p) => {
            let bumped = p + chrono::Duration::seconds(1);
            if bumped > now { bumped } else { now }
        }
        None => now,
    };
    candidate.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

// ---------------------------------------------------------------------------
// Writing

pub(super) fn build_updated_log(loaded: &LoadedLog, new_line: &str) -> String {
    let mut updated = String::new();
    for line in &loaded.raw_lines {
        updated.push_str(line);
        updated.push('\n');
    }
    updated.push_str(new_line);
    if !new_line.ends_with('\n') {
        updated.push('\n');
    }
    updated
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args_with_rotate(roles: Vec<RotateRole>) -> UpdateArgs {
        UpdateArgs {
            did: None,
            input: None,
            rotate: roles,
            authorized_key: None,
            authentication_key: None,
            assertion_key: None,
            out: None,
            force: false,
            no_publish: true,
            partner_id: None,
            registry_url: None,
        }
    }

    #[test]
    fn plan_rejects_nothing_to_do() {
        let args = args_with_rotate(vec![]);
        assert!(matches!(plan_rotation(&args), Err(UpdateError::NoChange)));
    }

    #[test]
    fn plan_rotate_all_sets_all_three_to_generate() {
        let args = args_with_rotate(vec![RotateRole::All]);
        let plan = plan_rotation(&args).unwrap();
        assert_eq!(plan.authorized, Action::Generate);
        assert_eq!(plan.authentication, Action::Generate);
        assert_eq!(plan.assertion, Action::Generate);
    }

    #[test]
    fn plan_rotate_individual_roles() {
        let args = args_with_rotate(vec![RotateRole::Authentication, RotateRole::Assertion]);
        let plan = plan_rotation(&args).unwrap();
        assert_eq!(plan.authorized, Action::Keep);
        assert_eq!(plan.authentication, Action::Generate);
        assert_eq!(plan.assertion, Action::Generate);
    }

    #[test]
    fn plan_rejects_rotate_and_import_for_same_role() {
        let mut args = args_with_rotate(vec![RotateRole::Authorized]);
        args.authorized_key = Some(PathBuf::from("/dev/null"));
        assert!(matches!(
            plan_rotation(&args),
            Err(UpdateError::ConflictingRotation { role: "authorized" })
        ));
    }

    #[test]
    fn plan_imports_when_only_role_key_supplied() {
        let mut args = args_with_rotate(vec![]);
        args.authentication_key = Some(PathBuf::from("/some/path.pem"));
        let plan = plan_rotation(&args).unwrap();
        assert_eq!(plan.authorized, Action::Keep);
        match plan.authentication {
            Action::Import(p) => assert_eq!(p, PathBuf::from("/some/path.pem")),
            other => panic!("expected Import, got {other:?}"),
        }
    }

    #[test]
    fn compute_version_time_clamps_to_after_previous() {
        // "2099-01-01T00:00:00Z" is comfortably in the future, so the clamp must take effect.
        let prev = "2099-01-01T00:00:00Z";
        let new = compute_version_time(prev);
        let new_dt = chrono::DateTime::parse_from_rfc3339(&new).unwrap();
        let prev_dt = chrono::DateTime::parse_from_rfc3339(prev).unwrap();
        assert!(new_dt > prev_dt);
    }
}
