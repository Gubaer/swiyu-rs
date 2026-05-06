//! Construct an [`AnySigningEngine`] from process environment.
//!
//! Both binaries (`issuer-mgmt` and `issuer-oidc`) need the same
//! selection at startup; this module is the single source for the
//! env contract. Reads:
//!
//! | Variable                     | Required             | Default                                              |
//! | ---------------------------- | -------------------- | ---------------------------------------------------- |
//! | `SIGNING_ENGINE`             | no                   | `"dev"`                                              |
//! | `VAULT_ADDR`                 | when engine=`vault`  | —                                                    |
//! | `VAULT_TOKEN`                | when engine=`vault`  | —                                                    |
//! | `VAULT_TRANSIT_PATH`         | no                   | [`VaultSigningEngineConfig::DEFAULT_TRANSIT_PATH`]   |
//! | `VAULT_REQUEST_TIMEOUT_SECS` | no                   | [`VaultSigningEngineConfig::DEFAULT_REQUEST_TIMEOUT`]|

use std::env;
use std::time::Duration;

use reqwest::Url;
use secrecy::SecretString;
use sqlx::PgPool;
use thiserror::Error;

use super::{AnySigningEngine, DevSigningEngine, VaultSigningEngine, VaultSigningEngineConfig};

#[derive(Debug, Error)]
pub enum BuildError {
    #[error("SIGNING_ENGINE must be `dev` or `vault`, got `{0}`")]
    UnknownKind(String),
    #[error("{0} must be set when SIGNING_ENGINE=vault")]
    VaultEnvMissing(&'static str),
    #[error("VAULT_ADDR is not a valid URL: {0}")]
    VaultAddrInvalid(String),
    #[error("VAULT_REQUEST_TIMEOUT_SECS is not a u64: {0}")]
    VaultTimeoutInvalid(std::num::ParseIntError),
}

pub fn build_from_env(pool: PgPool) -> Result<AnySigningEngine, BuildError> {
    let kind = env::var("SIGNING_ENGINE").unwrap_or_else(|_| "dev".to_string());
    match kind.as_str() {
        "dev" => Ok(AnySigningEngine::Dev(DevSigningEngine::new(pool))),
        "vault" => Ok(AnySigningEngine::Vault(build_vault()?)),
        other => Err(BuildError::UnknownKind(other.to_string())),
    }
}

fn build_vault() -> Result<VaultSigningEngine, BuildError> {
    let address = env::var("VAULT_ADDR").map_err(|_| BuildError::VaultEnvMissing("VAULT_ADDR"))?;
    let token = env::var("VAULT_TOKEN").map_err(|_| BuildError::VaultEnvMissing("VAULT_TOKEN"))?;
    let transit_path = env::var("VAULT_TRANSIT_PATH")
        .unwrap_or_else(|_| VaultSigningEngineConfig::DEFAULT_TRANSIT_PATH.to_string());
    let request_timeout = match env::var("VAULT_REQUEST_TIMEOUT_SECS") {
        Ok(s) => Duration::from_secs(s.parse::<u64>().map_err(BuildError::VaultTimeoutInvalid)?),
        Err(_) => VaultSigningEngineConfig::DEFAULT_REQUEST_TIMEOUT,
    };
    Ok(VaultSigningEngine::new(VaultSigningEngineConfig {
        address: Url::parse(&address).map_err(|e| BuildError::VaultAddrInvalid(e.to_string()))?,
        token: SecretString::from(token),
        transit_path,
        request_timeout,
    }))
}
