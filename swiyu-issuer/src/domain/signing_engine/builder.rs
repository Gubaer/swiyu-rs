//! Construct an [`AnySigningEngine`] from process environment.
//!
//! Both binaries (`swiyu-issuer-mgmtapi` and `swiyu-issuer-oidcapi`) need the same
//! selection at startup; this module is the single source for the
//! env contract. Reads:
//!
//! | Variable                     | Required             | Default                                              |
//! | ---------------------------- | -------------------- | ---------------------------------------------------- |
//! | `SIGNING_ENGINE`             | no                   | `"dev"`                                              |
//! | `VAULT_ADDR`                 | when engine=`vault`  | —                                                    |
//! | `VAULT_TOKEN`                | when engine=`vault`  | —                                                    |
//! | `SIGNING_VAULT_TRANSIT_PATH` | no                   | [`VaultSigningEngineConfig::DEFAULT_TRANSIT_PATH`]   |
//! | `VAULT_REQUEST_TIMEOUT_SECS` | no                   | [`VaultSigningEngineConfig::DEFAULT_REQUEST_TIMEOUT`]|
//!
//! `VAULT_ADDR`, `VAULT_TOKEN`, and `VAULT_REQUEST_TIMEOUT_SECS` are
//! shared with the secret-encryption engine; the Transit mount path
//! is engine-scoped so signing keys and secret-encryption keys can
//! live under different mounts with different ACL policies.

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
    let kind = env::var("SIGNING_ENGINE").unwrap_or_default();
    match kind.trim() {
        "dev" | "" => Ok(AnySigningEngine::Dev(DevSigningEngine::new(pool))),
        "vault" => Ok(AnySigningEngine::Vault(build_vault()?)),
        other => Err(BuildError::UnknownKind(other.to_string())),
    }
}

fn non_blank_env(name: &'static str) -> Result<String, BuildError> {
    let value = env::var(name).unwrap_or_default();
    match value.trim() {
        "" => Err(BuildError::VaultEnvMissing(name)),
        s => Ok(s.to_string()),
    }
}

fn build_vault() -> Result<VaultSigningEngine, BuildError> {
    let address = non_blank_env("VAULT_ADDR")?;
    let token = non_blank_env("VAULT_TOKEN")?;
    let transit_path_raw = env::var("SIGNING_VAULT_TRANSIT_PATH").unwrap_or_default();
    let transit_path = match transit_path_raw.trim() {
        "" => VaultSigningEngineConfig::DEFAULT_TRANSIT_PATH.to_string(),
        s => s.to_string(),
    };
    let request_timeout_raw = env::var("VAULT_REQUEST_TIMEOUT_SECS").unwrap_or_default();
    let request_timeout = match request_timeout_raw.trim() {
        "" => VaultSigningEngineConfig::DEFAULT_REQUEST_TIMEOUT,
        s => Duration::from_secs(s.parse::<u64>().map_err(BuildError::VaultTimeoutInvalid)?),
    };
    Ok(VaultSigningEngine::new(VaultSigningEngineConfig {
        address: Url::parse(&address).map_err(|e| BuildError::VaultAddrInvalid(e.to_string()))?,
        token: SecretString::from(token),
        transit_path,
        request_timeout,
    }))
}
