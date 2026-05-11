mod envelope;

use std::future::Future;
use std::sync::Arc;

use aes_gcm::aead::{Aead, AeadCore};
use aes_gcm::{Aes256Gcm, KeyInit};
use hkdf::Hkdf;
use rand_core::OsRng;
use secrecy::{ExposeSecret, SecretBox};
use sha2::Sha256;

use super::{Ciphertext, SecretEncryptionEngine, SecretEncryptionError};
use envelope::{Envelope, NONCE_LEN};

/// Domain-separator prefix mixed into HKDF `info` together with `key_name`.
/// Different prefixes ensure derived keys cannot collide with any future
/// HKDF usage that reuses the same master key for a different purpose.
const HKDF_INFO_PREFIX: &[u8] = b"swiyu-issuer/v1/secret-management/";
const DEV_KEY_VERSION: u32 = 1;
const MASTER_KEY_LEN: usize = 32;

/// Low-maturity [`SecretEncryptionEngine`] for development and integration
/// tests.
///
/// A single in-process master key is the only long-term secret. Per-key
/// AES-256 keys are derived via HKDF-SHA256 with `key_name` mixed into
/// `info`, so distinct `key_name`s yield distinct derived keys without
/// the engine knowing anything about tenants. Must not be used in
/// production — production uses
/// [`VaultSecretEncryptionEngine`][super::VaultSecretEncryptionEngine].
pub struct DevSecretEncryptionEngine {
    master_key: Arc<SecretBox<[u8; MASTER_KEY_LEN]>>,
}

impl DevSecretEncryptionEngine {
    pub fn new(master_key: [u8; MASTER_KEY_LEN]) -> Self {
        Self {
            master_key: Arc::new(SecretBox::new(Box::new(master_key))),
        }
    }

    fn derive_key(&self, key_name: &str) -> [u8; 32] {
        let mut info = Vec::with_capacity(HKDF_INFO_PREFIX.len() + key_name.len());
        info.extend_from_slice(HKDF_INFO_PREFIX);
        info.extend_from_slice(key_name.as_bytes());
        let hk = Hkdf::<Sha256>::new(None, self.master_key.expose_secret().as_slice());
        let mut okm = [0u8; 32];
        // 32-byte output is well within HKDF-SHA256's 255*HashLen budget.
        hk.expand(&info, &mut okm)
            .expect("HKDF okm length 32 is valid for SHA-256");
        okm
    }

    // `aes-gcm` 0.10 still exposes nonces as `generic_array::GenericArray`,
    // which carries an upstream deprecation steering callers to
    // generic-array 1.x. The migration ships with `aes-gcm` 0.11 (currently
    // a release candidate); until then we acknowledge the lint here.
    #[allow(deprecated)]
    fn encrypt_sync(
        &self,
        key_name: &str,
        plaintext: &[u8],
    ) -> Result<Ciphertext, SecretEncryptionError> {
        let derived = self.derive_key(key_name);
        let cipher = Aes256Gcm::new_from_slice(&derived)
            .expect("32-byte HKDF output is the AES-256 key length");
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ct_and_tag = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| SecretEncryptionError::Backend(format!("aes-gcm encrypt: {e}").into()))?;
        let nonce_bytes: [u8; NONCE_LEN] = nonce
            .as_slice()
            .try_into()
            .expect("Aes256Gcm nonce is exactly 12 bytes");
        let env = Envelope {
            key_name,
            key_version: DEV_KEY_VERSION,
            nonce: &nonce_bytes,
            ct_and_tag: &ct_and_tag,
        };
        let bytes = env.encode()?;
        Ok(Ciphertext(bytes))
    }

    #[allow(deprecated)]
    fn decrypt_sync(
        &self,
        key_name: &str,
        ciphertext: &Ciphertext,
    ) -> Result<Vec<u8>, SecretEncryptionError> {
        let env = Envelope::decode(ciphertext.as_bytes())?;
        if env.key_name != key_name {
            return Err(SecretEncryptionError::KeyNameMismatch {
                envelope: env.key_name.to_string(),
                argument: key_name.to_string(),
            });
        }
        if env.key_version != DEV_KEY_VERSION {
            return Err(SecretEncryptionError::KeyVersionNotFound {
                key_name: key_name.to_string(),
                version: env.key_version,
            });
        }
        let derived = self.derive_key(key_name);
        let cipher = Aes256Gcm::new_from_slice(&derived)
            .expect("32-byte HKDF output is the AES-256 key length");
        // Round-trip through `generate_nonce` to obtain a typed nonce, then
        // overwrite its bytes with the envelope's nonce.
        let mut nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        nonce.as_mut_slice().copy_from_slice(env.nonce);
        cipher
            .decrypt(&nonce, env.ct_and_tag)
            .map_err(|_| SecretEncryptionError::Tampered)
    }
}

impl SecretEncryptionEngine for DevSecretEncryptionEngine {
    fn encrypt(
        &self,
        key_name: &str,
        plaintext: &[u8],
    ) -> impl Future<Output = Result<Ciphertext, SecretEncryptionError>> + Send {
        let result = self.encrypt_sync(key_name, plaintext);
        std::future::ready(result)
    }

    fn decrypt(
        &self,
        key_name: &str,
        ciphertext: &Ciphertext,
    ) -> impl Future<Output = Result<Vec<u8>, SecretEncryptionError>> + Send {
        let result = self.decrypt_sync(key_name, ciphertext);
        std::future::ready(result)
    }
}

#[cfg(test)]
mod tests {
    use super::envelope::{FORMAT, NONCE_LEN};
    use super::*;

    fn fixed_engine() -> DevSecretEncryptionEngine {
        // Fixed test master key — value is unimportant, just deterministic.
        DevSecretEncryptionEngine::new([0x42u8; MASTER_KEY_LEN])
    }

    #[tokio::test]
    async fn round_trip_for_a_handful_of_key_names() {
        let engine = fixed_engine();
        for key_name in [
            "oauth2_refresh_token",
            "tenant/4Mk7yK5pQR7sN3/oauth2_refresh_token",
            "tenant/4Mk7yK5pQR7sN3/oauth2_client_secret",
        ] {
            let plaintext = b"hello, world";
            let ct = engine.encrypt(key_name, plaintext).await.unwrap();
            let pt = engine.decrypt(key_name, &ct).await.unwrap();
            assert_eq!(pt.as_slice(), plaintext);
        }
    }

    #[tokio::test]
    async fn key_name_mismatch_on_decrypt() {
        let engine = fixed_engine();
        let ct = engine.encrypt("name-a", b"payload").await.unwrap();
        let err = engine.decrypt("name-b", &ct).await.unwrap_err();
        match err {
            SecretEncryptionError::KeyNameMismatch { envelope, argument } => {
                assert_eq!(envelope, "name-a");
                assert_eq!(argument, "name-b");
            }
            other => panic!("expected KeyNameMismatch, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn key_version_not_found_for_non_one_version() {
        let engine = fixed_engine();
        // Hand-craft an envelope whose key_version is 2.
        let key_name = b"name";
        let mut bytes = vec![FORMAT, key_name.len() as u8];
        bytes.extend_from_slice(key_name);
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(&[0u8; NONCE_LEN]);
        bytes.extend_from_slice(&[0u8; 16]); // dummy ct_and_tag (>= tag length)
        let ct = Ciphertext::from(bytes);

        let err = engine.decrypt("name", &ct).await.unwrap_err();
        match err {
            SecretEncryptionError::KeyVersionNotFound { key_name, version } => {
                assert_eq!(key_name, "name");
                assert_eq!(version, 2);
            }
            other => panic!("expected KeyVersionNotFound, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn tampered_ciphertext_is_rejected() {
        let engine = fixed_engine();
        let mut ct = engine.encrypt("name", b"payload").await.unwrap();
        // Flip a bit in the ct_and_tag tail.
        let last = ct.0.len() - 1;
        ct.0[last] ^= 0x01;
        let err = engine.decrypt("name", &ct).await.unwrap_err();
        assert!(matches!(err, SecretEncryptionError::Tampered));
    }

    #[tokio::test]
    async fn malformed_ciphertext_is_rejected() {
        let engine = fixed_engine();
        // Truncated buffer (shorter than the minimum preamble).
        let too_short = Ciphertext::from(vec![FORMAT]);
        let err = engine.decrypt("name", &too_short).await.unwrap_err();
        assert!(matches!(err, SecretEncryptionError::MalformedCiphertext));

        // Format byte ≠ 0x01.
        let mut bad_format_bytes = engine
            .encrypt("name", b"payload")
            .await
            .unwrap()
            .into_bytes();
        bad_format_bytes[0] = 0x02;
        let err = engine
            .decrypt("name", &Ciphertext::from(bad_format_bytes))
            .await
            .unwrap_err();
        assert!(matches!(err, SecretEncryptionError::MalformedCiphertext));
    }

    #[test]
    fn distinct_key_names_yield_distinct_derived_keys() {
        let engine = fixed_engine();
        let a = engine.derive_key("name-a");
        let b = engine.derive_key("name-b");
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn nonce_is_fresh_per_call() {
        let engine = fixed_engine();
        let ct1 = engine.encrypt("name", b"payload").await.unwrap();
        let ct2 = engine.encrypt("name", b"payload").await.unwrap();
        // With a 12-byte random nonce, two encryptions of the same plaintext
        // under the same key must differ.
        assert_ne!(ct1, ct2);
    }
}
