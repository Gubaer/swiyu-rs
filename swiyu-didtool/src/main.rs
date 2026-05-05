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

use clap::{Args, Parser, Subcommand, ValueEnum};
use swiyu_core::didlog::LogEntryFormat;

use keystore::{KeyRole, KeyStore};

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
    /// Manage DID lifecycle: create, rotate, deactivate.
    Did {
        #[command(subcommand)]
        command: DidCommand,
    },
    /// Read a DID's log file (list, show, entry).
    Didlog {
        #[command(subcommand)]
        command: DidlogCommand,
    },
    /// Manage the key store.
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
    /// Generate or verify Proof-of-Possession (PoP) JWTs.
    Pop {
        #[command(subcommand)]
        command: PopCommand,
    },
    /// Inspect or verify the SWIYU trust granted to a DID.
    Trust {
        #[command(subcommand)]
        command: TrustCommand,
    },
}

#[derive(Subcommand)]
enum DidCommand {
    /// Create a new DID via the SWIYU identifier registry, generate key pairs, write the initial DID log, and (unless --no-publish) publish the log to the registry.
    Create {
        #[command(flatten)]
        registry: SwiyuRegistryArgs,
        /// DID method to use.
        #[arg(long, default_value = "tdw")]
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
    /// Append a new entry to an existing DID log, rotating one or more keys.
    Rotate {
        #[command(flatten)]
        source: DidOrInputArgs,
        /// Generate fresh keys for the named role(s). Repeatable. Values: authorized, authentication, assertion, all.
        #[arg(long, value_enum)]
        role: Vec<RotateRole>,
        /// Existing Ed25519 private key to install as the new authorized key (PEM).
        #[arg(long)]
        authorized_key: Option<PathBuf>,
        /// Existing P-256 private key to install as the new authentication key (PEM).
        #[arg(long)]
        authentication_key: Option<PathBuf>,
        /// Existing P-256 private key to install as the new assertion key (PEM).
        #[arg(long)]
        assertion_key: Option<PathBuf>,
        /// Write the full updated log to this file. With --input or the default `did.jsonl`, the source file is updated in place if --out is omitted; with --did the new log is not written locally unless --out is given (persistence is via registry publish).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Allow `--out` to overwrite an existing file.
        #[arg(long)]
        force: bool,
        #[command(flatten)]
        registry: SwiyuRegistryArgs,
    },
    /// Mark a DID as deactivated by appending a final entry to its log.
    Deactivate {
        #[command(flatten)]
        source: DidOrInputArgs,
        /// Write the full updated log to this file. With --input or the default `did.jsonl`, the source file is updated in place if --out is omitted; with --did the new log is not written locally unless --out is given (persistence is via registry publish).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Allow `--out` to overwrite an existing file.
        #[arg(long)]
        force: bool,
        #[command(flatten)]
        registry: SwiyuRegistryArgs,
    },
}

#[derive(Subcommand)]
enum PopCommand {
    /// Create a Proof of Possession (PoP) JWT signed with one of the DID's keys.
    Create {
        /// Full DID string or 12-character BLAKE3 hash.
        #[arg(long, required = true)]
        did: String,
        /// Which key to sign the PoP with.
        #[arg(long, value_enum, default_value = "assertion")]
        role: Role,
        /// Nonce embedded in the JWT. If omitted, a 128-bit random nonce is generated and printed to stderr.
        #[arg(long)]
        nonce: Option<String>,
        /// Validity in seconds from now. Must be positive.
        #[arg(long, default_value_t = 3600)]
        ttl: u64,
        /// Snapshot version (defaults to latest).
        #[arg(long)]
        version: Option<u32>,
        /// Write the JWT to this file instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Allow `--out` to overwrite an existing file.
        #[arg(long)]
        force: bool,
    },
    /// Verify a Proof of Possession (PoP) JWT against a DID's keys.
    Verify {
        /// The JWT to verify, passed inline.
        #[arg(long, conflicts_with = "jwt_file")]
        jwt: Option<String>,
        /// Path to a file containing the JWT.
        #[arg(long)]
        jwt_file: Option<PathBuf>,
        #[command(flatten)]
        source: DidOrInputArgs,
        /// Expected nonce; if given, payload.nonce must match exactly.
        #[arg(long)]
        nonce: Option<String>,
        /// Skip the `exp` freshness check.
        #[arg(long)]
        allow_expired: bool,
    },
}

/// Shared `--no-publish`, `--partner-id`, `--registry-url` options for the
/// subcommands that interact with the SWIYU identifier registry.
#[derive(Args)]
struct SwiyuRegistryArgs {
    /// Skip the registry update; produce only the local files.
    #[arg(long)]
    no_publish: bool,
    /// SWIYU business partner ID (overrides SWIYU_PARTNER_ID).
    #[arg(long, env = "SWIYU_PARTNER_ID", value_parser = parse_partner_id)]
    partner_id: Option<String>,
    /// SWIYU identifier registry base URL (overrides SWIYU_IDENTIFIER_REGISTRY_URL).
    #[arg(long, env = "SWIYU_IDENTIFIER_REGISTRY_URL", value_parser = parse_https_url)]
    registry_url: Option<String>,
}

/// Shared `--did` / `--input` mutex pair for subcommands that load a DID log,
/// either by resolving a DID over HTTPS or by reading a local JSONL file.
#[derive(Args)]
struct DidOrInputArgs {
    /// Full DID string or 12-character BLAKE3 hash; resolved to an HTTPS URL and fetched.
    #[arg(long, conflicts_with = "input")]
    did: Option<String>,
    /// Local DID log file (defaults to `did.jsonl`).
    #[arg(long)]
    input: Option<PathBuf>,
}

/// Role names for `didtool did rotate --role`.
#[derive(Clone, ValueEnum)]
enum RotateRole {
    /// EdDSA signing key for log-entry signatures.
    Authorized,
    /// P-256 key for DID authentication.
    Authentication,
    /// P-256 key for verifiable-credential signatures.
    Assertion,
    /// Shortcut for all three roles.
    All,
}

impl From<RotateRole> for cmd::did::RotateRole {
    fn from(r: RotateRole) -> cmd::did::RotateRole {
        match r {
            RotateRole::Authorized => cmd::did::RotateRole::Authorized,
            RotateRole::Authentication => cmd::did::RotateRole::Authentication,
            RotateRole::Assertion => cmd::did::RotateRole::Assertion,
            RotateRole::All => cmd::did::RotateRole::All,
        }
    }
}

#[derive(Subcommand)]
enum DidlogCommand {
    /// List every entry in the DID log, one row per entry.
    List {
        #[command(flatten)]
        source: DidOrInputArgs,
    },
    /// Output the full DID log.
    Show {
        #[command(flatten)]
        source: DidOrInputArgs,
        /// Write to this file instead of stdout. Default file format is raw JSONL.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Allow `--out` to overwrite an existing file.
        #[arg(long)]
        force: bool,
        /// Force raw JSONL output (default to a file).
        #[arg(long, conflicts_with = "pretty")]
        raw: bool,
        /// Force pretty-printed output (default to stdout).
        #[arg(long)]
        pretty: bool,
    },
    /// Output a single entry from the DID log.
    Entry {
        #[command(flatten)]
        source: DidOrInputArgs,
        /// Entry selector: `latest` (default) or a 1-based numeric index.
        #[arg(long)]
        at: Option<String>,
        /// Write to this file instead of stdout. Default file format is raw JSONL.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Allow `--out` to overwrite an existing file.
        #[arg(long)]
        force: bool,
        /// Force raw JSONL output (default to a file).
        #[arg(long, conflicts_with = "pretty")]
        raw: bool,
        /// Force pretty-printed output (default to stdout).
        #[arg(long)]
        pretty: bool,
    },
}

#[derive(Subcommand)]
enum TrustCommand {
    /// Look up the SWIYU trust statements for a DID and display them.
    Lookup {
        /// Subject DID — full DID string or 12-character BLAKE3 hash.
        #[arg(long, required = true)]
        did: String,
        /// Base URL of the SWIYU trust registry.
        #[arg(long, env = "SWIYU_TRUST_REGISTRY_URL", value_parser = parse_https_url)]
        trust_registry_url: Option<String>,
        /// Emit the registry response (JSON array) verbatim instead of a human-readable summary.
        #[arg(long)]
        raw: bool,
    },
    /// Verify the SWIYU trust statements for a DID.
    Verify {
        /// Subject DID — full DID string or 12-character BLAKE3 hash.
        #[arg(long, required = true)]
        did: String,
        /// Base URL of the SWIYU trust registry.
        #[arg(long, env = "SWIYU_TRUST_REGISTRY_URL", value_parser = parse_https_url)]
        trust_registry_url: Option<String>,
        /// The well-known SWIYU trust authority's DID. Allowlist for `payload.iss` and signer of the status list.
        #[arg(long, env = "SWIYU_TRUST_ISSUER_DID")]
        trust_issuer: Option<String>,
    },
}

#[derive(Subcommand)]
enum KeyCommand {
    /// List all entries in the key store.
    List,
    /// List the snapshot versions stored for one DID.
    Versions {
        /// Full DID string or 12-character BLAKE3 hash.
        #[arg(long, required = true)]
        did: String,
    },
    /// Display public key(s) for an entry.
    Show {
        /// Full DID string or 12-character BLAKE3 hash.
        #[arg(long, required = true)]
        did: String,
        /// Show only the key for this role; omit to show all three.
        #[arg(long)]
        role: Option<Role>,
        /// Snapshot version (defaults to latest).
        #[arg(long)]
        version: Option<u32>,
    },
    /// Export a key to a file in PEM format.
    Export {
        /// Full DID string or 12-character BLAKE3 hash.
        #[arg(long, required = true)]
        did: String,
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
        Command::Did { command } => match command {
            DidCommand::Create {
                registry:
                    SwiyuRegistryArgs {
                        no_publish,
                        partner_id,
                        registry_url,
                    },
                format,
                out,
                authorized_key,
                authentication_key,
                assertion_key,
            } => cmd::did::cmd_create(
                &store,
                cmd::did::CreateArgs {
                    url: None,
                    swiyu: true,
                    partner_id,
                    registry_url,
                    no_publish,
                    format: format.into(),
                    out,
                    authorized_key,
                    authentication_key,
                    assertion_key,
                },
            )
            .map_err(|e| e.into()),
            DidCommand::Rotate {
                source: DidOrInputArgs { did, input },
                role,
                authorized_key,
                authentication_key,
                assertion_key,
                out,
                force,
                registry:
                    SwiyuRegistryArgs {
                        no_publish,
                        partner_id,
                        registry_url,
                    },
            } => cmd::did::cmd_rotate(
                &store,
                cmd::did::RotateArgs {
                    did,
                    input,
                    rotate: role.into_iter().map(Into::into).collect(),
                    authorized_key,
                    authentication_key,
                    assertion_key,
                    out,
                    force,
                    no_publish,
                    partner_id,
                    registry_url,
                },
            )
            .map_err(|e| e.into()),
            DidCommand::Deactivate {
                source: DidOrInputArgs { did, input },
                out,
                force,
                registry:
                    SwiyuRegistryArgs {
                        no_publish,
                        partner_id,
                        registry_url,
                    },
            } => cmd::did::cmd_deactivate(
                &store,
                cmd::did::DeactivateArgs {
                    did,
                    input,
                    out,
                    force,
                    no_publish,
                    partner_id,
                    registry_url,
                },
            )
            .map_err(|e| e.into()),
        },
        Command::Didlog { command } => match command {
            DidlogCommand::List {
                source: DidOrInputArgs { did, input },
            } => cmd::didlog::cmd_list(&store, cmd::didlog::ListArgs { did, input })
                .map_err(|e| e.into()),
            DidlogCommand::Show {
                source: DidOrInputArgs { did, input },
                out,
                force,
                raw,
                pretty,
            } => cmd::didlog::cmd_show(
                &store,
                cmd::didlog::ShowArgs {
                    did,
                    input,
                    out,
                    force,
                    raw,
                    pretty,
                },
            )
            .map_err(|e| e.into()),
            DidlogCommand::Entry {
                source: DidOrInputArgs { did, input },
                at,
                out,
                force,
                raw,
                pretty,
            } => cmd::didlog::cmd_entry(
                &store,
                cmd::didlog::EntryArgs {
                    did,
                    input,
                    at,
                    out,
                    force,
                    raw,
                    pretty,
                },
            )
            .map_err(|e| e.into()),
        },
        Command::Key { command } => match command {
            KeyCommand::List => cmd::key::cmd_list(&store),
            KeyCommand::Versions { did } => cmd::key::cmd_versions(&store, &did),
            KeyCommand::Show { did, role, version } => {
                cmd::key::cmd_show(&store, &did, role.map(Into::into), version)
            }
            KeyCommand::Export {
                did,
                role,
                out,
                private,
                version,
            } => cmd::key::cmd_export(&store, &did, role.into(), out, private, version),
        },
        Command::Pop { command } => match command {
            PopCommand::Create {
                did,
                role,
                nonce,
                ttl,
                version,
                out,
                force,
            } => cmd::pop::cmd_create_pop(
                &store,
                cmd::pop::CreatePopArgs {
                    did,
                    role: role.into(),
                    nonce,
                    ttl,
                    version,
                    out,
                    force,
                },
            )
            .map_err(|e| e.into()),
            PopCommand::Verify {
                jwt,
                jwt_file,
                source: DidOrInputArgs { did, input },
                nonce,
                allow_expired,
            } => cmd::pop::cmd_verify_pop(
                &store,
                cmd::pop::VerifyPopArgs {
                    jwt,
                    jwt_file,
                    did,
                    input,
                    nonce,
                    allow_expired,
                },
            )
            .map_err(|e| e.into()),
        },
        Command::Trust { command } => match command {
            TrustCommand::Lookup {
                did,
                trust_registry_url,
                raw,
            } => match cmd::trust::lookup::cmd_lookup(
                &store,
                cmd::trust::lookup::LookupArgs {
                    did,
                    trust_registry_url,
                    raw,
                },
            ) {
                Ok(cmd::trust::lookup::LookupOutcome::Found) => Ok(()),
                Ok(cmd::trust::lookup::LookupOutcome::NoStatements) => process::exit(1),
                Err(e) => {
                    eprintln!("error: {e}");
                    process::exit(2);
                }
            },
            TrustCommand::Verify {
                did,
                trust_registry_url,
                trust_issuer,
            } => match cmd::trust::verify::cmd_verify(
                &store,
                cmd::trust::verify::VerifyArgs {
                    did,
                    trust_registry_url,
                    trust_issuer,
                },
            ) {
                Ok(cmd::trust::verify::VerifyOutcome::Trusted) => Ok(()),
                Ok(cmd::trust::verify::VerifyOutcome::Untrusted) => process::exit(1),
                Err(e) => {
                    eprintln!("error: {e}");
                    process::exit(2);
                }
            },
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

fn parse_partner_id(s: &str) -> Result<String, String> {
    if s.is_empty() {
        Err("required — provide --partner-id or set SWIYU_PARTNER_ID".to_string())
    } else if is_uuid(s) {
        Ok(s.to_string())
    } else {
        Err(format!("not a valid UUID: '{s}'"))
    }
}

fn parse_https_url(s: &str) -> Result<String, String> {
    if s.is_empty() {
        Err("required (value is empty)".to_string())
    } else if is_https_url(s) {
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
