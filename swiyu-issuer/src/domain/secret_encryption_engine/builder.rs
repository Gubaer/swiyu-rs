// Builds an `AnySecretEncryptionEngine` from process environment.
//
// Reads:
//
//   `SECRET_ENCRYPTION_ENGINE`         — `dev` (default) or `vault`
//   `SECRET_ENCRYPTION_DEV_MASTER_KEY` — required when engine=`dev`
//
// `SECRET_ENCRYPTION_ENGINE=vault` is not yet implemented; the builder
// rejects it with `BuildError::VaultNotYetImplemented`.

use std::env;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use thiserror::Error;

use super::{AnySecretEncryptionEngine, DevSecretEncryptionEngine};

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

    #[error("SECRET_ENCRYPTION_ENGINE=vault is not yet implemented")]
    VaultNotYetImplemented,
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
        "vault" => Err(BuildError::VaultNotYetImplemented),
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

// Accepts standard or URL-safe base64, with or without padding. Try the
// padded forms first (which strictly enforce trailing `=`), then the
// no-pad forms; surface the last error if all four fail.
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
