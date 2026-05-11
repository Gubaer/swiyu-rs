//! Builds an [`AnySecretEncryptionEngine`] from process environment.
//!
//! Reads:
//!
//!   `SECRET_ENCRYPTION_ENGINE`         — `dev` (default) or `vault`
//!   `SECRET_ENCRYPTION_DEV_MASTER_KEY` — required when engine=`dev`
//!
//! When engine=`vault` the builder additionally reads the same set of
//! variables the signing-engine builder reads (`VAULT_ADDR`,
//! `VAULT_TOKEN`, `VAULT_TRANSIT_PATH`, `VAULT_REQUEST_TIMEOUT_SECS`).
//! A single Vault deployment serves both engines; operators wanting to
//! isolate signing keys from secret-encryption keys point each engine
//! at a different Vault mount via the relevant `*_TRANSIT_PATH` knob
//! (out-of-band Vault configuration).

use std::env;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use reqwest::Url;
use secrecy::SecretString;
use thiserror::Error;

use super::{
    AnySecretEncryptionEngine, DevSecretEncryptionEngine, VaultSecretEncryptionEngine,
    VaultSecretEncryptionEngineConfig,
};

const MASTER_KEY_LEN: usize = 32;

#[derive(Debug, Error)]
pub enum BuildError {
    #[error("SECRET_ENCRYPTION_ENGINE must be `dev` or `vault`, got `{0}`")]
    UnknownKind(String),

    #[error("SECRET_ENCRYPTION_DEV_MASTER_KEY must be set when SECRET_ENCRYPTION_ENGINE=dev")]
    DevMasterKeyMissing,

    #[error("SECRET_ENCRYPTION_DEV_MASTER_KEY is not valid base64: {0}")]
    DevMasterKeyMalformed(String),

    #[error(
        "SECRET_ENCRYPTION_DEV_MASTER_KEY must decode to exactly {expected} bytes, got {actual}"
    )]
    DevMasterKeyWrongLength { expected: usize, actual: usize },

    #[error("{0} must be set when SECRET_ENCRYPTION_ENGINE=vault")]
    VaultEnvMissing(&'static str),

    #[error("VAULT_ADDR is not a valid URL: {0}")]
    VaultAddrInvalid(String),

    #[error("VAULT_REQUEST_TIMEOUT_SECS is not a u64: {0}")]
    VaultTimeoutInvalid(std::num::ParseIntError),
}

pub fn build_from_env() -> Result<AnySecretEncryptionEngine, BuildError> {
    let kind = env::var("SECRET_ENCRYPTION_ENGINE").unwrap_or_default();
    match kind.trim() {
        "dev" | "" => {
            let raw = env::var("SECRET_ENCRYPTION_DEV_MASTER_KEY").unwrap_or_default();
            let master_key = parse_master_key(&raw)?;
            Ok(AnySecretEncryptionEngine::Dev(
                DevSecretEncryptionEngine::new(master_key),
            ))
        }
        "vault" => Ok(AnySecretEncryptionEngine::Vault(build_vault()?)),
        other => Err(BuildError::UnknownKind(other.to_string())),
    }
}

fn parse_master_key(raw: &str) -> Result<[u8; MASTER_KEY_LEN], BuildError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(BuildError::DevMasterKeyMissing);
    }
    let decoded = decode_base64_permissive(trimmed)
        .map_err(|e| BuildError::DevMasterKeyMalformed(e.to_string()))?;
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| BuildError::DevMasterKeyWrongLength {
            expected: MASTER_KEY_LEN,
            actual: decoded.len(),
        })
}

// Try padded forms first (which strictly enforce trailing `=`), then
// the no-pad forms; surface the last error if all four fail.
fn decode_base64_permissive(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    if let Ok(b) = STANDARD.decode(s) {
        return Ok(b);
    }
    if let Ok(b) = URL_SAFE.decode(s) {
        return Ok(b);
    }
    if let Ok(b) = STANDARD_NO_PAD.decode(s) {
        return Ok(b);
    }
    URL_SAFE_NO_PAD.decode(s)
}

fn non_blank_env(name: &'static str) -> Result<String, BuildError> {
    let value = env::var(name).unwrap_or_default();
    match value.trim() {
        "" => Err(BuildError::VaultEnvMissing(name)),
        s => Ok(s.to_string()),
    }
}

fn build_vault() -> Result<VaultSecretEncryptionEngine, BuildError> {
    let address = non_blank_env("VAULT_ADDR")?;
    let token = non_blank_env("VAULT_TOKEN")?;
    let transit_path_raw = env::var("VAULT_TRANSIT_PATH").unwrap_or_default();
    let transit_path = match transit_path_raw.trim() {
        "" => VaultSecretEncryptionEngineConfig::DEFAULT_TRANSIT_PATH.to_string(),
        s => s.to_string(),
    };
    let request_timeout_raw = env::var("VAULT_REQUEST_TIMEOUT_SECS").unwrap_or_default();
    let request_timeout = match request_timeout_raw.trim() {
        "" => VaultSecretEncryptionEngineConfig::DEFAULT_REQUEST_TIMEOUT,
        s => Duration::from_secs(s.parse::<u64>().map_err(BuildError::VaultTimeoutInvalid)?),
    };
    Ok(VaultSecretEncryptionEngine::new(
        VaultSecretEncryptionEngineConfig {
            address: Url::parse(&address)
                .map_err(|e| BuildError::VaultAddrInvalid(e.to_string()))?,
            token: SecretString::from(token),
            transit_path,
            request_timeout,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_blank_master_key() {
        let err = parse_master_key("").unwrap_err();
        assert!(matches!(err, BuildError::DevMasterKeyMissing));
        let err = parse_master_key("   \n").unwrap_err();
        assert!(matches!(err, BuildError::DevMasterKeyMissing));
    }

    #[test]
    fn rejects_malformed_base64_master_key() {
        let err = parse_master_key("not!valid!base64!").unwrap_err();
        assert!(matches!(err, BuildError::DevMasterKeyMalformed(_)));
    }

    #[test]
    fn rejects_wrong_length_master_key() {
        // 16 bytes of zeros, base64-encoded — decodes successfully but is
        // the wrong length for AES-256.
        let raw = STANDARD.encode([0u8; 16]);
        let err = parse_master_key(&raw).unwrap_err();
        match err {
            BuildError::DevMasterKeyWrongLength { expected, actual } => {
                assert_eq!(expected, 32);
                assert_eq!(actual, 16);
            }
            other => panic!("expected DevMasterKeyWrongLength, got: {other:?}"),
        }
    }

    #[test]
    fn accepts_standard_base64() {
        let key = [0x42u8; 32];
        let encoded = STANDARD.encode(key);
        let parsed = parse_master_key(&encoded).unwrap();
        assert_eq!(parsed, key);
    }

    #[test]
    fn accepts_url_safe_base64() {
        let key = [0xffu8; 32];
        let encoded = URL_SAFE.encode(key);
        let parsed = parse_master_key(&encoded).unwrap();
        assert_eq!(parsed, key);
    }

    #[test]
    fn accepts_unpadded_base64() {
        let key = [0x77u8; 32];
        let encoded = STANDARD_NO_PAD.encode(key);
        let parsed = parse_master_key(&encoded).unwrap();
        assert_eq!(parsed, key);
    }

    #[test]
    fn trims_surrounding_whitespace() {
        let key = [0x11u8; 32];
        let encoded = format!("  {}\n", STANDARD.encode(key));
        let parsed = parse_master_key(&encoded).unwrap();
        assert_eq!(parsed, key);
    }
}
