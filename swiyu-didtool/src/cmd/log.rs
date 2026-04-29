use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde_json::Value;
use tracing::debug;

use swiyu_core::did::DID;
use swiyu_core::didlog::verify::{DIDLogVerifyError, verify_log};
use swiyu_core::didlog::{DIDDocState, DIDLog, DIDLogEntry, DIDLogError, LogEntryFormat};

use crate::cmd::ResolveError;
use crate::cmd::http::{FetchError, FetchOutcome};
use crate::keystore::{KeyStore, KeyStoreError};

const DEFAULT_INPUT: &str = "did.jsonl";

#[derive(Debug, thiserror::Error)]
pub enum LogError {
    #[error("--did and --input are mutually exclusive")]
    AmbiguousSource,
    #[error("--raw and --pretty are mutually exclusive")]
    AmbiguousFormat,
    #[error("--force is only meaningful with --out")]
    ForceWithoutOut,
    #[error("file '{}' already exists; pass --force to overwrite", path.display())]
    FileExists { path: PathBuf },
    #[error("cannot read '{}': {source}", path.display())]
    ReadInput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot write '{}': {source}", path.display())]
    WriteOutput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("write to stdout failed: {0}")]
    WriteStdout(#[source] std::io::Error),
    #[error(transparent)]
    Fetch(#[from] FetchError),
    #[error(transparent)]
    Resolve(#[from] ResolveError),
    #[error(transparent)]
    KeyStore(#[from] KeyStoreError),
    #[error("DID log parse error: {0}")]
    LogParse(#[from] DIDLogError),
    #[error("DID log failed verification: {0}")]
    Verification(#[from] DIDLogVerifyError),
    #[error("invalid --at selector '{0}': must be 'latest' or a positive integer")]
    BadSelector(String),
    #[error("no entry at index {index} (log has {total} entries)")]
    IndexOutOfRange { index: usize, total: usize },
}

pub struct ListArgs {
    pub did: Option<String>,
    pub input: Option<PathBuf>,
}

pub struct ShowArgs {
    pub did: Option<String>,
    pub input: Option<PathBuf>,
    pub out: Option<PathBuf>,
    pub force: bool,
    pub raw: bool,
    pub pretty: bool,
}

pub struct EntryArgs {
    pub did: Option<String>,
    pub input: Option<PathBuf>,
    pub at: Option<String>,
    pub out: Option<PathBuf>,
    pub force: bool,
    pub raw: bool,
    pub pretty: bool,
}

pub fn cmd_list(store: &KeyStore, args: ListArgs) -> Result<(), LogError> {
    let loaded = load_log(store, args.did, args.input)?;
    print_list(store, &loaded.log)
}

pub fn cmd_show(store: &KeyStore, args: ShowArgs) -> Result<(), LogError> {
    if args.raw && args.pretty {
        return Err(LogError::AmbiguousFormat);
    }
    if args.force && args.out.is_none() {
        return Err(LogError::ForceWithoutOut);
    }
    let loaded = load_log(store, args.did, args.input)?;
    let format = decide_format(args.out.is_some(), args.raw, args.pretty);
    write_show(&loaded, format, args.out.as_deref(), args.force)
}

pub fn cmd_entry(store: &KeyStore, args: EntryArgs) -> Result<(), LogError> {
    if args.raw && args.pretty {
        return Err(LogError::AmbiguousFormat);
    }
    if args.force && args.out.is_none() {
        return Err(LogError::ForceWithoutOut);
    }
    let selector = parse_selector(args.at.as_deref().unwrap_or("latest"))?;
    let loaded = load_log(store, args.did, args.input)?;
    let idx = resolve_selector(selector, &loaded.log)?;
    let format = decide_format(args.out.is_some(), args.raw, args.pretty);
    write_entry(&loaded, idx, format, args.out.as_deref(), args.force)
}

// ---------------------------------------------------------------------------
// Loading

pub(crate) struct LoadedLog {
    pub(crate) raw_lines: Vec<String>,
    pub(crate) log: DIDLog,
    /// Local source path, if the log was read from disk. `None` when fetched via HTTPS.
    pub(crate) source_path: Option<PathBuf>,
}

pub(crate) fn load_log(
    store: &KeyStore,
    did: Option<String>,
    input: Option<PathBuf>,
) -> Result<LoadedLog, LogError> {
    if did.is_some() && input.is_some() {
        return Err(LogError::AmbiguousSource);
    }
    let (text, source_path, target_did) = match did {
        Some(target) => {
            let resolved = crate::cmd::resolve_did(store, &target)?;
            let url = resolved.log_url();
            debug!("resolved DID to log URL: {}", url);
            (fetch_log(&url)?, None, Some(resolved))
        }
        None => {
            let path = input.unwrap_or_else(|| PathBuf::from(DEFAULT_INPUT));
            debug!("reading DID log from {}", path.display());
            let text = fs::read_to_string(&path).map_err(|source| LogError::ReadInput {
                path: path.clone(),
                source,
            })?;
            (text, Some(path), None)
        }
    };
    let raw_lines = collect_raw_lines(&text);
    let log = DIDLog::try_from_jsonl(&text)?;
    debug!("loaded {} log entries", log.entries().len());
    verify_loaded_log(&log, target_did.as_ref())?;
    Ok(LoadedLog {
        raw_lines,
        log,
        source_path,
    })
}

/// Verifies the loaded DID log against the chain integrity rules of did:tdw 0.3.
///
/// `target_did` is the DID the user explicitly asked to resolve (`--did`); when
/// present, the log MUST authenticate as that DID. When absent (a `--input`
/// load), the log is verified against the DID it announces in its own genesis
/// state — this catches accidental tampering but does not provide cryptographic
/// provenance against an adversary who can rewrite the local file.
///
/// did:webvh logs are skipped (verifier not yet implemented).
fn verify_loaded_log(log: &DIDLog, target_did: Option<&DID>) -> Result<(), LogError> {
    let is_tdw = log
        .entries()
        .first()
        .is_some_and(|e| matches!(e.format(), LogEntryFormat::TDW03));
    if !is_tdw {
        debug!("skipping log verification (not did:tdw 0.3)");
        return Ok(());
    }

    let did_for_verify = match target_did {
        Some(d) => d.clone(),
        None => match current_did(log).and_then(|s| DID::parse(&s).ok()) {
            Some(d) => d,
            None => {
                debug!("skipping log verification (no DID in genesis state)");
                return Ok(());
            }
        },
    };

    verify_log(log, &did_for_verify)?;
    debug!("DID log signature chain verified");
    Ok(())
}

fn collect_raw_lines(text: &str) -> Vec<String> {
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(str::to_string)
        .collect()
}

/// Fetches a DID log via HTTPS. A 404 response is *not* "absent" here — a
/// missing log is a hard error, so we map it to the same `HttpStatus` shape
/// the previous version produced.
fn fetch_log(url: &str) -> Result<String, LogError> {
    debug!("GET {url}");
    match crate::cmd::http::fetch_text(url)? {
        FetchOutcome::Ok(text) => Ok(text),
        FetchOutcome::NotFound => Err(LogError::Fetch(FetchError::HttpStatus {
            url: url.to_string(),
            status: 404,
            body: String::new(),
        })),
    }
}

// ---------------------------------------------------------------------------
// Selector

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Selector {
    Latest,
    Index(usize),
}

fn parse_selector(s: &str) -> Result<Selector, LogError> {
    if s == "latest" {
        return Ok(Selector::Latest);
    }
    match s.parse::<usize>() {
        Ok(n) if n >= 1 => Ok(Selector::Index(n)),
        _ => Err(LogError::BadSelector(s.to_string())),
    }
}

fn resolve_selector(selector: Selector, log: &DIDLog) -> Result<usize, LogError> {
    let total = log.entries().len();
    match selector {
        Selector::Latest => {
            if total == 0 {
                return Err(LogError::IndexOutOfRange { index: 1, total });
            }
            Ok(total - 1)
        }
        Selector::Index(n) => {
            if n > total {
                return Err(LogError::IndexOutOfRange { index: n, total });
            }
            Ok(n - 1)
        }
    }
}

// ---------------------------------------------------------------------------
// Output

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Raw,
    Pretty,
}

fn decide_format(to_file: bool, raw: bool, pretty: bool) -> Format {
    if raw {
        Format::Raw
    } else if pretty {
        Format::Pretty
    } else if to_file {
        Format::Raw
    } else {
        Format::Pretty
    }
}

fn print_list(store: &KeyStore, log: &DIDLog) -> Result<(), LogError> {
    let entries = log.entries();
    let version_id_width = entries
        .iter()
        .map(|e| e.version_id().len())
        .max()
        .unwrap_or(10)
        .max("VERSION-ID".len());

    let did_str = current_did(log);
    let keystore_hash = did_str.as_deref().and_then(|d| keystore_hash_for(store, d));

    let mut out = io::stdout().lock();
    writeln!(
        out,
        "DID:            {}",
        did_str.as_deref().unwrap_or("(unknown)"),
    )
    .map_err(LogError::WriteStdout)?;
    writeln!(
        out,
        "Keystore hash:  {}",
        keystore_hash.as_deref().unwrap_or("(not in keystore)"),
    )
    .map_err(LogError::WriteStdout)?;
    writeln!(out).map_err(LogError::WriteStdout)?;

    writeln!(
        out,
        "{vid:<vid_w$}  VERSION-TIME",
        vid = "VERSION-ID",
        vid_w = version_id_width,
    )
    .map_err(LogError::WriteStdout)?;
    for entry in entries {
        writeln!(
            out,
            "{vid:<vid_w$}  {vt}",
            vid = entry.version_id(),
            vid_w = version_id_width,
            vt = entry.version_time(),
        )
        .map_err(LogError::WriteStdout)?;
    }
    Ok(())
}

/// Returns the DID id from the most recent log entry whose state is a full document.
/// Skips `Patch` states, falling back to earlier entries (the genesis is always `Value`).
pub(crate) fn current_did(log: &DIDLog) -> Option<String> {
    for entry in log.entries().iter().rev() {
        if let DIDDocState::Value(doc) = entry.did_doc_state()
            && let Some(id) = doc.get("id").and_then(|v| v.as_str())
        {
            return Some(id.to_string());
        }
    }
    None
}

fn keystore_hash_for(store: &KeyStore, did: &str) -> Option<String> {
    let parsed = DID::parse(did).ok()?;
    store
        .lookup(&parsed)
        .ok()
        .flatten()
        .map(|e| e.hash().to_string())
}

fn write_show(
    loaded: &LoadedLog,
    format: Format,
    out: Option<&Path>,
    force: bool,
) -> Result<(), LogError> {
    let body = render_show(loaded, format);
    write_body(&body, out, force, format)
}

fn write_entry(
    loaded: &LoadedLog,
    index: usize,
    format: Format,
    out: Option<&Path>,
    force: bool,
) -> Result<(), LogError> {
    let body = render_entry(loaded, index, format);
    write_body(&body, out, force, format)
}

fn render_show(loaded: &LoadedLog, format: Format) -> String {
    match format {
        Format::Raw => {
            let mut s = loaded.raw_lines.join("\n");
            if !s.is_empty() {
                s.push('\n');
            }
            s
        }
        Format::Pretty => {
            let mut s = String::new();
            for (i, entry) in loaded.log.entries().iter().enumerate() {
                if i > 0 {
                    s.push('\n');
                }
                s.push_str(&format_pretty_header(i, entry));
                s.push('\n');
                s.push_str(&pretty_json(entry));
                s.push('\n');
            }
            s
        }
    }
}

fn render_entry(loaded: &LoadedLog, index: usize, format: Format) -> String {
    match format {
        Format::Raw => {
            let mut s = loaded.raw_lines[index].clone();
            s.push('\n');
            s
        }
        Format::Pretty => {
            let entry = &loaded.log.entries()[index];
            let mut s = format_pretty_header(index, entry);
            s.push('\n');
            s.push_str(&pretty_json(entry));
            s.push('\n');
            s
        }
    }
}

fn format_pretty_header(index: usize, entry: &DIDLogEntry) -> String {
    format!("# entry {} — {}", index + 1, entry.version_id())
}

fn pretty_json(entry: &DIDLogEntry) -> String {
    let value: Value = entry.to_json();
    serde_json::to_string_pretty(&value).expect("serializable JSON value")
}

fn write_body(
    body: &str,
    out: Option<&Path>,
    force: bool,
    _format: Format,
) -> Result<(), LogError> {
    match out {
        Some(path) => {
            if path.exists() && !force {
                return Err(LogError::FileExists {
                    path: path.to_path_buf(),
                });
            }
            fs::write(path, body).map_err(|source| LogError::WriteOutput {
                path: path.to_path_buf(),
                source,
            })
        }
        None => {
            let mut stdout = io::stdout().lock();
            stdout
                .write_all(body.as_bytes())
                .map_err(LogError::WriteStdout)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_selector_latest() {
        assert_eq!(parse_selector("latest").unwrap(), Selector::Latest);
    }

    #[test]
    fn parse_selector_numeric() {
        assert_eq!(parse_selector("3").unwrap(), Selector::Index(3));
    }

    #[test]
    fn parse_selector_rejects_zero() {
        assert!(matches!(parse_selector("0"), Err(LogError::BadSelector(_))));
    }

    #[test]
    fn parse_selector_rejects_non_numeric() {
        assert!(matches!(
            parse_selector("1-QmAbc"),
            Err(LogError::BadSelector(_))
        ));
    }

    #[test]
    fn decide_format_defaults() {
        assert_eq!(decide_format(false, false, false), Format::Pretty);
        assert_eq!(decide_format(true, false, false), Format::Raw);
    }

    #[test]
    fn decide_format_overrides() {
        assert_eq!(decide_format(false, true, false), Format::Raw);
        assert_eq!(decide_format(true, false, true), Format::Pretty);
    }

    #[test]
    fn collect_raw_lines_skips_blanks() {
        let text = "a\n\nb\n   \nc\n";
        assert_eq!(collect_raw_lines(text), vec!["a", "b", "c"]);
    }
}
