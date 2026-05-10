use std::future::Future;

use thiserror::Error;

pub mod any;
pub mod builder;
pub mod dev;
pub mod vault;

pub use any::AnySecretEncryptionEngine;
pub use builder::{BuildError, build_from_env};
pub use dev::DevSecretEncryptionEngine;
pub use vault::VaultSecretEncryptionEngine;

// Persisted as a single `BYTEA` column. Format version, `key_name`, and
// `key_version` travel inside the blob, so callers do not carry companion
// columns to identify the key under which the value was encrypted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext(Vec<u8>);

impl Ciphertext {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for Ciphertext {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

#[derive(Debug, Error)]
pub enum SecretEncryptionError {
    #[error("key not configured: {0}")]
    KeyNotFound(String),

    #[error("ciphertext envelope is malformed")]
    MalformedCiphertext,

    #[error(
        "ciphertext key_name does not match argument: envelope={envelope}, argument={argument}"
    )]
    KeyNameMismatch { envelope: String, argument: String },

    #[error("ciphertext key_version is not configured: {key_name} v{version}")]
    KeyVersionNotFound { key_name: String, version: u32 },

    #[error("authentication tag verification failed")]
    Tampered,

    #[error("backend error: {0}")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync>),
}

// Invariant: a symmetric key never leaves the engine. Callers pass
// plaintext in and get a `Ciphertext` back; key material stays internal
// to each backend.
pub trait SecretEncryptionEngine: Send + Sync {
    fn encrypt(
        &self,
        key_name: &str,
        plaintext: &[u8],
    ) -> impl Future<Output = Result<Ciphertext, SecretEncryptionError>> + Send;

    fn decrypt(
        &self,
        key_name: &str,
        ciphertext: &Ciphertext,
    ) -> impl Future<Output = Result<Vec<u8>, SecretEncryptionError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ciphertext_round_trip_via_from_and_into_bytes() {
        let original = vec![1, 2, 3, 4, 5];
        let ct = Ciphertext::from(original.clone());
        assert_eq!(ct.as_bytes(), original.as_slice());
        assert_eq!(ct.into_bytes(), original);
    }
}
