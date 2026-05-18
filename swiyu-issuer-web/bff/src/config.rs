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
    pub dev_user_id: String,
    pub dev_tenant_name: String,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            bff_port: parse_port("BFF_PORT", 3000)?,
            mgmtapi_url: required("MGMTAPI_URL")?,
            mgmtapi_token: required("MGMTAPI_TOKEN")?,
            dev_user_id: optional("DEV_USER_ID", "test"),
            dev_tenant_name: optional("DEV_TENANT_NAME", "dev"),
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

fn parse_port(name: &'static str, default: u16) -> Result<u16, ConfigError> {
    match env::var(name) {
        Ok(value) => value
            .parse()
            .map_err(|source| ConfigError::InvalidPort { name, source }),
        Err(VarError::NotPresent) => Ok(default),
        Err(VarError::NotUnicode(_)) => Err(ConfigError::NonUnicodeVar { name }),
    }
}
