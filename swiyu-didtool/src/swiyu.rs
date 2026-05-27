//! Thin synchronous adapter over the async SWIYU Identifier Registry client in
//! `swiyu-registries`. didtool is otherwise synchronous, so each call is driven
//! to completion via [`crate::cmd::block_on`]. The bearer token is resolved here
//! from `SWIYU_ACCESS_TOKEN`; the registry client itself is credential-agnostic
//! and takes the token per call.

use swiyu_registries::common::{AccessToken, RegistryError};
use swiyu_registries::identifier::{Allocation, IdentifierRegistryClient};

use crate::cmd::block_on;

#[derive(Debug, thiserror::Error)]
pub enum SwiyuError {
    #[error("SWIYU_ACCESS_TOKEN is not set")]
    AccessTokenMissing,
    #[error(transparent)]
    Registry(#[from] RegistryError),
}

/// Allocates a new DID space via the SWIYU identifier registry and returns the
/// registry-published DID-log URL plus the UUID extracted from it.
///
/// `SWIYU_ACCESS_TOKEN` must be set; otherwise [`SwiyuError::AccessTokenMissing`].
pub fn allocate_did_url(
    partner_id: String,
    registry_url: String,
) -> Result<Allocation, SwiyuError> {
    let token = access_token()?;
    let client = IdentifierRegistryClient::new(registry_url)?;
    Ok(block_on(client.allocate_did(&token, &partner_id))?)
}

/// Uploads `entry_body` (a single line of JSON, no trailing newline) to the
/// registry, completing the registration started by [`allocate_did_url`].
pub fn publish_entry(
    registry_url: &str,
    partner_id: &str,
    identifier: &str,
    entry_body: &str,
) -> Result<(), SwiyuError> {
    let token = access_token()?;
    let client = IdentifierRegistryClient::new(registry_url.to_string())?;
    Ok(block_on(client.publish_log_entry(
        &token, partner_id, identifier, entry_body,
    ))?)
}

fn access_token() -> Result<AccessToken, SwiyuError> {
    std::env::var("SWIYU_ACCESS_TOKEN")
        .map(AccessToken::new)
        .map_err(|_| SwiyuError::AccessTokenMissing)
}
