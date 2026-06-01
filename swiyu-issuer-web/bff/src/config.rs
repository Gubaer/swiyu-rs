use std::env::{self, VarError};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("required env var `{0}` is missing or empty")]
    MissingVar(&'static str),
    #[error("env var `{name}` is not valid UTF-8")]
    NonUnicodeVar { name: &'static str },
    #[error("env var `{name}` could not be parsed as a port: {source}")]
    InvalidPort {
        name: &'static str,
        #[source]
        source: std::num::ParseIntError,
    },
}

#[derive(Debug)]
pub struct Config {
    pub bff_port: u16,
    pub mgmtapi_url: String,
    pub mgmtapi_token: String,
    // Only used if identifier-registry write APIs are added later;
    // DID-log fetches resolve through the DID's own `log_url`.
    pub identifier_registry_url: String,
    pub dev_user_id: String,
    pub dev_tenant_name: String,
    // Directory of built SPA assets to serve as a static fallback. When
    // unset (the dev workflow, where `ng serve` serves the SPA and proxies
    // `/api` here), the BFF serves only the `/api` routes.
    pub spa_dir: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            bff_port: parse_port("BFF_PORT", 3000)?,
            mgmtapi_url: required("MGMTAPI_URL")?,
            mgmtapi_token: required("MGMTAPI_TOKEN")?,
            identifier_registry_url: optional("IDENTIFIER_REGISTRY_URL", ""),
            dev_user_id: optional("DEV_USER_ID", "test"),
            dev_tenant_name: optional("DEV_TENANT_NAME", "dev"),
            spa_dir: optional_present("SPA_DIR"),
        })
    }
}

fn required(name: &'static str) -> Result<String, ConfigError> {
    match env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(value),
        Ok(_) | Err(VarError::NotPresent) => Err(ConfigError::MissingVar(name)),
        Err(VarError::NotUnicode(_)) => Err(ConfigError::NonUnicodeVar { name }),
    }
}

fn optional(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_string())
}

fn optional_present(name: &str) -> Option<String> {
    match env::var(name) {
        Ok(value) if !value.trim().is_empty() => Some(value),
        _ => None,
    }
}

fn parse_port(name: &'static str, default: u16) -> Result<u16, ConfigError> {
    match env::var(name) {
        Ok(value) => value
            .parse()
            .map_err(|source| ConfigError::InvalidPort { name, source }),
        Err(VarError::NotPresent) => Ok(default),
        Err(VarError::NotUnicode(_)) => Err(ConfigError::NonUnicodeVar { name }),
    }
}
