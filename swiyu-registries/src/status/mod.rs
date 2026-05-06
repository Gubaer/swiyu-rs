//! Async client for the SWIYU Status Registry.

mod create;
mod list;
mod update;

pub use create::StatusListEntry;
pub use list::{ListParams, StatusListEntriesPage, StatusListEntrySummary};

use std::time::Duration;

use crate::common::{AccessToken, RegistryError};

/// Async HTTP client for the SWIYU Status Registry.
///
/// `new` builds a hardened default `reqwest::Client` (30 s request
/// timeout, 10 s connect timeout, HTTPS-only, identifying user
/// agent). `with_http` injects a pre-configured client — used by
/// tests against local mock servers and by callers that want to
/// share a connection pool across multiple registries.
///
/// Methods take `&self`, and `reqwest::Client` is internally
/// `Arc`-shared, so a single instance can serve a worker pool
/// without further wrapping.
pub struct StatusRegistryClient {
    base_url: String,
    access_token: AccessToken,
    http: reqwest::Client,
}

impl StatusRegistryClient {
    pub fn new(base_url: String, access_token: AccessToken) -> Result<Self, RegistryError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .https_only(true)
            .user_agent(concat!(
                "swiyu-status-registry-client/",
                env!("CARGO_PKG_VERSION")
            ))
            .build()
            .map_err(RegistryError::Transport)?;
        Ok(Self::with_http(base_url, access_token, http))
    }

    pub fn with_http(base_url: String, access_token: AccessToken, http: reqwest::Client) -> Self {
        Self {
            base_url,
            access_token,
            http,
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}
