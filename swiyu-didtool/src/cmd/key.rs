use std::path::PathBuf;

use tracing::debug;

use crate::keystore::{KeyRole, KeyStore, key_role_file_stem};

pub fn cmd_list(store: &KeyStore) -> Result<(), Box<dyn std::error::Error>> {
    let entries = store.list()?;
    debug!("found {} entries in key store", entries.len());
    for entry in entries {
        println!("{}  {}", entry.hash, entry.did);
    }
    Ok(())
}

pub fn cmd_versions(store: &KeyStore, target: &str) -> Result<(), Box<dyn std::error::Error>> {
    let entry = crate::cmd::resolve_entry(store, target)?;
    let versions = entry.all_versions()?;
    debug!(
        "entry {} has {} version(s) on disk",
        entry.hash(),
        versions.len()
    );
    let roles = [
        ("authorized", KeyRole::Authorized),
        ("authentication", KeyRole::Authentication),
        ("assertion", KeyRole::Assertion),
    ];
    let mut prev: Option<[String; 3]> = None;
    for v in versions {
        let pems = [
            entry.public_key_pem(roles[0].1, Some(v))?,
            entry.public_key_pem(roles[1].1, Some(v))?,
            entry.public_key_pem(roles[2].1, Some(v))?,
        ];
        let tag = match &prev {
            None => "initial".to_string(),
            Some(prev_pems) => {
                let mut changed: Vec<&str> = Vec::with_capacity(3);
                for (i, (label, _)) in roles.iter().enumerate() {
                    if prev_pems[i] != pems[i] {
                        changed.push(label);
                    }
                }
                if changed.is_empty() {
                    "(unchanged)".to_string()
                } else {
                    changed.join(" ")
                }
            }
        };
        println!("{v}  {tag}");
        prev = Some(pems);
    }
    Ok(())
}

pub fn cmd_show(
    store: &KeyStore,
    target: &str,
    role: Option<KeyRole>,
    version: Option<u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    let entry = crate::cmd::resolve_entry(store, target)?;
    match role {
        Some(key_role) => {
            debug!(
                "showing {} public key (version: {})",
                key_role_file_stem(key_role),
                version.map_or("latest".to_string(), |v| v.to_string())
            );
            let pem = entry.public_key_pem(key_role, version)?;
            println!("{}", pem.trim());
        }
        None => {
            debug!(
                "showing all public keys (version: {})",
                version.map_or("latest".to_string(), |v| v.to_string())
            );
            for (label, key_role) in [
                ("authorized", KeyRole::Authorized),
                ("authentication", KeyRole::Authentication),
                ("assertion", KeyRole::Assertion),
            ] {
                let pem = entry.public_key_pem(key_role, version)?;
                println!("# {label}");
                println!("{}", pem.trim());
                println!();
            }
        }
    }
    Ok(())
}

pub fn cmd_export(
    store: &KeyStore,
    target: &str,
    role: KeyRole,
    out: PathBuf,
    private: bool,
    version: Option<u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    let entry = crate::cmd::resolve_entry(store, target)?;
    let visibility = if private { "private" } else { "public" };
    debug!(
        "exporting {} {} key to {}",
        key_role_file_stem(role),
        visibility,
        out.display()
    );
    if private {
        entry.export_private_key(role, version, &out)?;
    } else {
        entry.export_public_key(role, version, &out)?;
    }
    debug!("exported to {}", out.display());
    Ok(())
}
