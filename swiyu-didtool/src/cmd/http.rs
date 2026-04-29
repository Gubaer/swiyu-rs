//! Constants shared by didtool's HTTPS fetch helpers (DID log, trust registry,
//! status list). When the per-helper fetch functions are deduplicated, the
//! shared `fetch_text` will live here too.

/// Default cap on HTTPS response body size, in bytes (50 MiB). Overridable via
/// the `DIDTOOL_HTTP_MAX_BYTES` environment variable.
pub(crate) const DEFAULT_MAX_BYTES: usize = 50 * 1024 * 1024;

/// Name of the environment variable that overrides [`DEFAULT_MAX_BYTES`].
pub(crate) const ENV_MAX_BYTES: &str = "DIDTOOL_HTTP_MAX_BYTES";

/// Maximum number of characters from a non-2xx response body to include in the
/// error message. Keeps error output readable when servers return long HTML
/// error pages.
pub(crate) const FETCH_BODY_SNIPPET: usize = 200;
