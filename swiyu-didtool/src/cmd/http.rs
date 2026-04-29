//! Shared HTTPS-fetch primitives used by didtool's three fetchers (DID log,
//! trust registry, status list). Constants and the `fetch_text` helper live
//! here; per-command wrappers translate `FetchError` into their own error
//! types via `#[from]`.

use std::io::Read;

/// Hard cap on HTTPS response body size, in bytes (1 MiB). Generous compared to
/// realistic response sizes (DID logs in the hundreds of KB; trust statements
/// and status lists in the tens of KB) but tight enough to keep a misbehaving
/// server from streaming the process to death.
pub(crate) const MAX_BYTES: usize = 1024 * 1024;

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
    #[error("response from '{url}' exceeds {max_bytes} bytes")]
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

    let mut buf = Vec::with_capacity(MAX_BYTES.min(1024 * 64));
    response
        .take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut buf)
        .map_err(|e| FetchError::Io {
            url: url.to_string(),
            source: e,
        })?;

    if buf.len() > MAX_BYTES {
        return Err(FetchError::TooLarge {
            url: url.to_string(),
            max_bytes: MAX_BYTES,
        });
    }

    let text = String::from_utf8(buf).map_err(|_| FetchError::NonUtf8 {
        url: url.to_string(),
    })?;
    Ok(FetchOutcome::Ok(text))
}
