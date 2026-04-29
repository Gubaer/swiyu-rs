use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum WriteLogError {
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
}

/// Writes the DID log to either an explicit `out` path (with overwrite gated
/// by `force`) or atomically back to `source_path` when `out` is `None`.
/// Returns the path that was written.
///
/// `source_path` is `None` when the log was fetched over HTTPS (no local
/// source file to write back to); in that case `out` must be provided.
pub(crate) fn write_log(
    content: &str,
    source_path: Option<&Path>,
    out: Option<&Path>,
    force: bool,
) -> Result<PathBuf, WriteLogError> {
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
        return Ok(path.to_path_buf());
    }

    let source = source_path.ok_or(WriteLogError::OutRequiredForRemote)?;
    write_atomic(source, content).map_err(|source_err| WriteLogError::WriteOutput {
        path: source.to_path_buf(),
        source: source_err,
    })?;
    Ok(source.to_path_buf())
}

/// Writes `content` to `target` via a sibling `.tmp` file followed by an
/// atomic rename, so a crash mid-write cannot corrupt an existing file at
/// `target`.
pub(crate) fn write_atomic(target: &Path, content: &str) -> std::io::Result<()> {
    let mut tmp_name = target.as_os_str().to_os_string();
    tmp_name.push(".tmp");
    let tmp = PathBuf::from(tmp_name);
    fs::write(&tmp, content)?;
    fs::rename(&tmp, target)
}
