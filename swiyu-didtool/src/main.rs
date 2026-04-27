// crypto functions are called from keystore; rustc doesn't trace through test-only call chains
#[allow(dead_code)]
mod crypto;
// keystore items used only in tests (generate, commit, …) are intentionally kept for future commands
mod cmd;
#[allow(dead_code)]
mod keystore;
mod swiyu;

use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand, ValueEnum};
use swiyu_core::did::DID;
use swiyu_core::didlog::LogEntryFormat;
use tracing::debug;

use keystore::{KeyRole, KeyStore, KeyStoreEntry};

#[derive(Parser)]
#[command(name = "didtool", about = "Manage did:tdw and did:webvh identities")]
struct Cli {
    /// Path to the key store root directory (overrides DIDTOOL_KEYSTORE and the default).
    #[arg(long, env = "DIDTOOL_KEYSTORE", global = true)]
    keystore: Option<PathBuf>,

    /// Enable DEBUG-level log output to stderr.
    #[arg(long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new DID, generate key pairs, and write the initial DID log.
    Create {
        /// HTTPS URL where the DID log will be served (e.g. https://example.com/.well-known/did.jsonl).
        url: Option<String>,
        /// Allocate a DID space via the SWIYU identifier registry instead of supplying a URL.
        #[arg(long)]
        swiyu: bool,
        /// SWIYU business partner ID (overrides SWIYU_PARTNER_ID).
        #[arg(long, env = "SWIYU_PARTNER_ID", value_parser = parse_partner_id)]
        partner_id: Option<String>,
        /// SWIYU identifier registry base URL (overrides SWIYU_IDENTIFIER_REGISTRY_URL).
        #[arg(long, env = "SWIYU_IDENTIFIER_REGISTRY_URL", value_parser = parse_registry_url)]
        registry_url: Option<String>,
        /// DID method to use.
        #[arg(long, default_value = "webvh")]
        format: Format,
        /// Path to write the initial DID log (default: did.jsonl in the current directory).
        #[arg(long, default_value = "did.jsonl")]
        out: PathBuf,
        /// Existing Ed25519 private key to use for the authorized role (PEM). Generated if omitted.
        #[arg(long)]
        authorized_key: Option<PathBuf>,
        /// Existing P-256 private key to use for the authentication role (PEM). Generated if omitted.
        #[arg(long)]
        authentication_key: Option<PathBuf>,
        /// Existing P-256 private key to use for the assertion role (PEM). Generated if omitted.
        #[arg(long)]
        assertion_key: Option<PathBuf>,
    },
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

/// DID method format, for use as a CLI argument.
#[derive(Clone, ValueEnum)]
enum Format {
    /// did:tdw v0.3 (Trust DID Web).
    Tdw,
    /// did:webvh v1.0 (Web + Verifiable History).
    Webvh,
}

impl From<Format> for LogEntryFormat {
    fn from(f: Format) -> LogEntryFormat {
        match f {
            Format::Tdw => LogEntryFormat::TDW03,
            Format::Webvh => LogEntryFormat::WebVH10,
        }
    }
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

    if cli.verbose {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_target(false)
            .without_time()
            .init();
    }

    if let Err(e) = run(cli) {
        eprintln!("error: {e}");
        process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let store = open_store(cli.keystore)?;
    match cli.command {
        Command::Create {
            url,
            swiyu,
            partner_id,
            registry_url,
            format,
            out,
            authorized_key,
            authentication_key,
            assertion_key,
        } => cmd::create::cmd_create(
            &store,
            cmd::create::CreateArgs {
                url,
                swiyu,
                partner_id,
                registry_url,
                format: format.into(),
                out,
                authorized_key,
                authentication_key,
                assertion_key,
            },
        )
        .map_err(|e| e.into()),
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
        debug!("resolving target '{}' as BLAKE3 hash", target);
        store.lookup_by_hash(target)?
    } else {
        debug!("resolving target '{}' as DID", target);
        let did = DID::parse(target)?;
        store.lookup(&did)?
    };
    let entry = entry.ok_or_else(|| format!("no entry found for '{target}'").into());
    if let Ok(ref e) = entry {
        debug!("resolved to key store entry (hash: {})", e.hash());
    }
    entry
}

fn cmd_list(store: &KeyStore) -> Result<(), Box<dyn std::error::Error>> {
    let entries = store.list()?;
    debug!("found {} entries in key store", entries.len());
    for entry in entries {
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
            let key_role: KeyRole = role.into();
            debug!(
                "showing {} public key (version: {})",
                key_role.file_stem(),
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
    let visibility = if private { "private" } else { "public" };
    debug!(
        "exporting {} {} key to {}",
        key_role.file_stem(),
        visibility,
        out.display()
    );
    if private {
        entry.export_private_key(key_role, version, &out)?;
    } else {
        entry.export_public_key(key_role, version, &out)?;
    }
    debug!("exported to {}", out.display());
    Ok(())
}

fn parse_partner_id(s: &str) -> Result<String, String> {
    if is_uuid(s) {
        Ok(s.to_string())
    } else {
        Err(format!("not a valid UUID: '{s}'"))
    }
}

fn parse_registry_url(s: &str) -> Result<String, String> {
    if is_https_url(s) {
        Ok(s.to_string())
    } else {
        Err(format!(
            "must use https:// scheme and have a non-empty host: '{s}'"
        ))
    }
}

fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    let mut hex_positions = (0..36).filter(|&i| ![8, 13, 18, 23].contains(&i));
    let dash_positions = [8usize, 13, 18, 23];
    dash_positions.iter().all(|&i| b[i] == b'-') && hex_positions.all(|i| b[i].is_ascii_hexdigit())
}

fn is_https_url(s: &str) -> bool {
    s.strip_prefix("https://")
        .map(|rest| !rest.split('/').next().unwrap_or("").is_empty())
        .unwrap_or(false)
}
