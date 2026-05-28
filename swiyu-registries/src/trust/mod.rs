//! Async client for the SWIYU Trust Registry.

mod fetch;

use std::time::Duration;

use crate::common::RegistryError;

/// Async HTTP client for the SWIYU Trust Registry.
pub struct TrustRegistryClient {
    base_url: String,
    http: reqwest::Client,
}

impl TrustRegistryClient {
    /// Builds a client with a hardened default `reqwest::Client`: 30 s request
    /// timeout, 10 s connect timeout, HTTPS-only, identifying user agent.
    pub fn new(base_url: String) -> Result<Self, RegistryError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .https_only(true)
            .user_agent(concat!(
                "swiyu-trust-registry-client/",
                env!("CARGO_PKG_VERSION")
            ))
            .build()
            .map_err(RegistryError::Transport)?;
        Ok(Self::with_http(base_url, http))
    }

    /// Injects a pre-configured client — used by tests against local mock
    /// servers and by callers sharing a connection pool across registries.
    pub fn with_http(base_url: String, http: reqwest::Client) -> Self {
        Self { base_url, http }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}
