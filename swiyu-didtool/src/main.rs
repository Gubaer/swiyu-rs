// crypto functions are called from keystore; rustc doesn't trace through test-only call chains
#[allow(dead_code)]
mod crypto;
// keystore items used only in tests (generate, commit, …) are intentionally kept for future commands
#[allow(dead_code)]
mod keystore;

use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand, ValueEnum};
use swiyu_core::did::DID;

use keystore::{KeyRole, KeyStore, KeyStoreEntry};

#[derive(Parser)]
#[command(name = "didtool", about = "Manage did:tdw and did:webvh identities")]
struct Cli {
    /// Path to the key store root directory (overrides DIDTOOL_KEYSTORE and the default).
    #[arg(long, env = "DIDTOOL_KEYSTORE", global = true)]
    keystore: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage the key store.
    Keystore {
        #[command(subcommand)]
        command: KeystoreCommand,
    },
}

#[derive(Subcommand)]
enum KeystoreCommand {
    /// List all entries in the key store.
    List,
    /// Display public key(s) for an entry.
    Show {
        /// 12-character BLAKE3 hash or full DID string.
        target: String,
        /// Show only the key for this role; omit to show all three.
        #[arg(long)]
        role: Option<Role>,
        /// Snapshot version (defaults to latest).
        #[arg(long)]
        version: Option<u32>,
    },
    /// Export a key to a file in PEM format.
    Export {
        /// 12-character BLAKE3 hash or full DID string.
        target: String,
        /// The key role to export.
        #[arg(long, required = true)]
        role: Role,
        /// Output file path.
        #[arg(long, required = true)]
        out: PathBuf,
        /// Export the private key (default: exports the public key).
        #[arg(long)]
        private: bool,
        /// Snapshot version (defaults to latest).
        #[arg(long)]
        version: Option<u32>,
    },
}

/// A key role, for use as a CLI argument.
#[derive(Clone, ValueEnum)]
enum Role {
    Authorized,
    Authentication,
    Assertion,
}

impl From<Role> for KeyRole {
    fn from(r: Role) -> KeyRole {
        match r {
            Role::Authorized => KeyRole::Authorized,
            Role::Authentication => KeyRole::Authentication,
            Role::Assertion => KeyRole::Assertion,
        }
    }
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("error: {e}");
        process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let store = open_store(cli.keystore)?;
    match cli.command {
        Command::Keystore { command } => match command {
            KeystoreCommand::List => cmd_list(&store),
            KeystoreCommand::Show {
                target,
                role,
                version,
            } => cmd_show(&store, &target, role, version),
            KeystoreCommand::Export {
                target,
                role,
                out,
                private,
                version,
            } => cmd_export(&store, &target, role, out, private, version),
        },
    }
}

fn open_store(path: Option<PathBuf>) -> Result<KeyStore, Box<dyn std::error::Error>> {
    let store = match path {
        Some(p) => KeyStore::open_or_create(&p)?,
        None => KeyStore::open_default()?,
    };
    Ok(store)
}

/// Resolves a `<hash|did>` target string to a [`KeyStoreEntry`].
///
/// A 12-character all-hex string is treated as a BLAKE3 hash; anything else is parsed as a DID.
fn resolve_target(
    store: &KeyStore,
    target: &str,
) -> Result<KeyStoreEntry, Box<dyn std::error::Error>> {
    let entry = if target.len() == 12 && target.chars().all(|c| c.is_ascii_hexdigit()) {
        store.lookup_by_hash(target)?
    } else {
        let did = DID::parse(target)?;
        store.lookup(&did)?
    };
    entry.ok_or_else(|| format!("no entry found for '{target}'").into())
}

fn cmd_list(store: &KeyStore) -> Result<(), Box<dyn std::error::Error>> {
    for entry in store.list()? {
        println!("{}  {}", entry.hash, entry.did);
    }
    Ok(())
}

fn cmd_show(
    store: &KeyStore,
    target: &str,
    role: Option<Role>,
    version: Option<u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    let entry = resolve_target(store, target)?;
    match role {
        Some(role) => {
            let pem = entry.public_key_pem(role.into(), version)?;
            println!("{}", pem.trim());
        }
        None => {
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

fn cmd_export(
    store: &KeyStore,
    target: &str,
    role: Role,
    out: PathBuf,
    private: bool,
    version: Option<u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    let entry = resolve_target(store, target)?;
    let key_role: KeyRole = role.into();
    if private {
        entry.export_private_key(key_role, version, &out)?;
    } else {
        entry.export_public_key(key_role, version, &out)?;
    }
    Ok(())
}
