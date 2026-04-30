use std::fs;
use std::path::{Path, PathBuf};

const MAX_PENDING_INDEX: u32 = 9999;

#[derive(Debug, thiserror::Error)]
pub enum WriteLogError {
    #[error("file '{}' already exists; pass --force to overwrite", path.display())]
    FileExists { path: PathBuf },
    #[error("cannot write '{}': {source}", path.display())]
    WriteOutput {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "could not allocate a fallback file: did-pending-1.jsonl through did-pending-{max}.jsonl all exist; remove old pending files and retry"
    )]
    PendingExhausted { max: u32 },
}

/// Writes the DID log to either an explicit `out` path (with overwrite gated
/// by `force`) or atomically back to `source_path` when `out` is `None`.
/// Returns the written path, or `None` if neither destination was provided
/// (i.e. the log was loaded over HTTPS via `--did` and the caller did not
/// pass `--out`). In that case the caller is expected to publish the log to
/// the registry; persistence relies on the publish step.
pub(crate) fn write_log(
    content: &str,
    source_path: Option<&Path>,
    out: Option<&Path>,
    force: bool,
) -> Result<Option<PathBuf>, WriteLogError> {
    if let Some(path) = out {
        if path.exists() && !force {
            return Err(WriteLogError::FileExists {
                path: path.to_path_buf(),
            });
        }
        fs::write(path, content).map_err(|source| WriteLogError::WriteOutput {
            path: path.to_path_buf(),
            source,
        })?;
        return Ok(Some(path.to_path_buf()));
    }

    if let Some(source) = source_path {
        write_atomic(source, content).map_err(|source_err| WriteLogError::WriteOutput {
            path: source.to_path_buf(),
            source: source_err,
        })?;
        return Ok(Some(source.to_path_buf()));
    }

    Ok(None)
}

/// Writes `content` to the lowest-numbered free `did-pending-<N>.jsonl` in the
/// current working directory, where `N` is a positive integer. Used as a
/// recovery path when a registry publish fails and there is no local log file
/// to retry from. Returns the chosen path.
pub(crate) fn write_pending_log(content: &str) -> Result<PathBuf, WriteLogError> {
    for n in 1..=MAX_PENDING_INDEX {
        let path = PathBuf::from(format!("did-pending-{n}.jsonl"));
        if path.exists() {
            continue;
        }
        fs::write(&path, content).map_err(|source| WriteLogError::WriteOutput {
            path: path.clone(),
            source,
        })?;
        return Ok(path);
    }
    Err(WriteLogError::PendingExhausted {
        max: MAX_PENDING_INDEX,
    })
}

fn write_atomic(target: &Path, content: &str) -> std::io::Result<()> {
    let mut tmp_name = target.as_os_str().to_os_string();
    tmp_name.push(".tmp");
    let tmp = PathBuf::from(tmp_name);
    fs::write(&tmp, content)?;
    fs::rename(&tmp, target)
}
