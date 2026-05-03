//! Async client for the SWIYU Identifier Registry.
//!
//! Currently a placeholder: the v1 issuer-management slice will fill
//! in `allocate_did`, `publish_log_entry`, and `fetch_log` against
//! the real registry endpoints. Until then this module exists so
//! downstream crates can pin the dependency surface.

use crate::common::RegistryError;

/// Async client for the SWIYU Identifier Registry.
pub struct IdentifierRegistryClient {
    base_url: String,
    http: reqwest::Client,
}

impl IdentifierRegistryClient {
    pub fn new(base_url: String) -> Result<Self, RegistryError> {
        let http = reqwest::Client::builder()
            .build()
            .map_err(RegistryError::Transport)?;
        Ok(Self { base_url, http })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn http(&self) -> &reqwest::Client {
        &self.http
    }
}
