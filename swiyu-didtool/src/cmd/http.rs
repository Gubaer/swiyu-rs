//! Shared HTTPS-fetch primitives used by didtool's three fetchers (DID log,
//! trust registry, status list). Constants and the `fetch_text` helper live
//! here; per-command wrappers translate `FetchError` into their own error
//! types via `#[from]`.

use std::io::Read;

/// Default cap on HTTPS response body size, in bytes (50 MiB). Overridable via
/// the `DIDTOOL_HTTP_MAX_BYTES` environment variable.
pub(crate) const DEFAULT_MAX_BYTES: usize = 50 * 1024 * 1024;

/// Name of the environment variable that overrides [`DEFAULT_MAX_BYTES`].
pub(crate) const ENV_MAX_BYTES: &str = "DIDTOOL_HTTP_MAX_BYTES";

/// Maximum number of characters from a non-2xx response body to include in the
/// error message. Keeps error output readable when servers return long HTML
/// error pages.
pub(crate) const FETCH_BODY_SNIPPET: usize = 200;

/// Outcome of a successful fetch. Whether `NotFound` is treated as an error or
/// as "absent" is the caller's call — the trust registry uses absent semantics
/// (no statements for that DID), the DID-log fetcher treats it as an error.
pub(crate) enum FetchOutcome {
    Ok(String),
    NotFound,
}

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("cannot fetch '{url}': {source}")]
    Http {
        url: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("'{url}' returned {status}: {body}")]
    HttpStatus {
        url: String,
        status: u16,
        body: String,
    },
    #[error("response from '{url}' exceeds {max_bytes} bytes (override with {ENV_MAX_BYTES})")]
    TooLarge { url: String, max_bytes: usize },
    #[error("response from '{url}' is not valid UTF-8")]
    NonUtf8 { url: String },
    #[error("reading response body for '{url}' failed: {source}")]
    Io {
        url: String,
        #[source]
        source: std::io::Error,
    },
}

/// Performs a blocking HTTPS GET against `url` and returns the body text. A
/// 404 response is reported as [`FetchOutcome::NotFound`] rather than an error,
/// so callers can distinguish "absent" from "broken". All other non-2xx
/// statuses, network failures, oversize responses, and UTF-8 issues come back
/// as [`FetchError`] variants.
pub(crate) fn fetch_text(url: &str) -> Result<FetchOutcome, FetchError> {
    let max_bytes = std::env::var(ENV_MAX_BYTES)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(DEFAULT_MAX_BYTES);

    let client = reqwest::blocking::Client::new();
    let response = client.get(url).send().map_err(|e| FetchError::Http {
        url: url.to_string(),
        source: e,
    })?;

    let status = response.status();
    if status.as_u16() == 404 {
        return Ok(FetchOutcome::NotFound);
    }
    if !status.is_success() {
        let body = response.text().unwrap_or_default();
        let snippet: String = body.chars().take(FETCH_BODY_SNIPPET).collect();
        return Err(FetchError::HttpStatus {
            url: url.to_string(),
            status: status.as_u16(),
            body: snippet,
        });
    }

    let mut buf = Vec::with_capacity(max_bytes.min(1024 * 64));
    response
        .take((max_bytes + 1) as u64)
        .read_to_end(&mut buf)
        .map_err(|e| FetchError::Io {
            url: url.to_string(),
            source: e,
        })?;

    if buf.len() > max_bytes {
        return Err(FetchError::TooLarge {
            url: url.to_string(),
            max_bytes,
        });
    }

    let text = String::from_utf8(buf).map_err(|_| FetchError::NonUtf8 {
        url: url.to_string(),
    })?;
    Ok(FetchOutcome::Ok(text))
}
