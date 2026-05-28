//! Thin synchronous adapter over the async SWIYU Identifier Registry client in
//! `swiyu-registries`. didtool is otherwise synchronous, so each call is driven
//! to completion via [`crate::cmd::block_on`]. The bearer token is obtained by
//! exchanging the refresh token from the environment at the SWIYU OAuth2 token
//! endpoint (see [`crate::oauth2`]); the registry client itself is
//! credential-agnostic and takes the token per call.

use swiyu_registries::common::RegistryError;
use swiyu_registries::identifier::{Allocation, IdentifierRegistryClient};

use crate::cmd::block_on;
use crate::oauth2::{OAuth2Error, OAuthCredentials, refresh_token_grant};

#[derive(Debug, thiserror::Error)]
pub enum SwiyuError {
    #[error(transparent)]
    OAuth2(#[from] OAuth2Error),
    #[error(transparent)]
    Registry(#[from] RegistryError),
}

/// Allocates a new DID space via the SWIYU identifier registry and returns the
/// registry-published DID-log URL plus the UUID extracted from it.
pub fn allocate_did_url(
    partner_id: String,
    registry_url: String,
) -> Result<Allocation, SwiyuError> {
    let creds = OAuthCredentials::from_env()?;
    block_on(async move {
        let token = refresh_token_grant(&creds).await?;
        let client = IdentifierRegistryClient::new(registry_url)?;
        Ok(client.allocate_did(&token, &partner_id).await?)
    })
}

/// Uploads `entry_body` (a single line of JSON, no trailing newline) to the
/// registry, completing the registration started by [`allocate_did_url`].
pub fn publish_entry(
    registry_url: &str,
    partner_id: &str,
    identifier: &str,
    entry_body: &str,
) -> Result<(), SwiyuError> {
    let creds = OAuthCredentials::from_env()?;
    block_on(async move {
        let token = refresh_token_grant(&creds).await?;
        let client = IdentifierRegistryClient::new(registry_url.to_string())?;
        Ok(client
            .publish_log_entry(&token, partner_id, identifier, entry_body)
            .await?)
    })
}
