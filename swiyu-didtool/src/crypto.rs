use std::path::Path;

use ed25519_dalek::SigningKey as Ed25519SigningKey;
use ed25519_dalek::VerifyingKey as Ed25519VerifyingKey;
use p256::ecdsa::{SigningKey as EcdsaSigningKey, VerifyingKey as EcdsaVerifyingKey};
use pkcs8::spki::{DecodePublicKey, EncodePublicKey};
use pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rand::rngs::OsRng;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid key: {0}")]
    InvalidKey(String),
}

pub type CryptoResult<T> = Result<T, CryptoError>;

/// Generates an ECDSA key pair over P-256 (secp256r1).
///
/// P-256 is fixed: while ECDSA supports multiple curves, P-256 is the curve
/// mandated by the did:tdw and did:webvh specifications for ECDSA keys.
pub fn generate_ecdsa_key_pair() -> (EcdsaSigningKey, EcdsaVerifyingKey) {
    let signing_key = EcdsaSigningKey::random(&mut OsRng);
    let verifying_key = *signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Generates an EdDSA key pair over Ed25519 (Edwards25519).
///
/// Curve25519 is fixed: while EdDSA supports multiple curves, Ed25519 over
/// Curve25519 is the curve mandated by the did:tdw and did:webvh specifications
/// for EdDSA keys.
pub fn generate_eddsa_key_pair() -> (Ed25519SigningKey, Ed25519VerifyingKey) {
    let signing_key = Ed25519SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Writes an ECDSA private key to a file in PKCS#8 PEM format.
///
/// On Unix the file is created with mode 0600 (owner read/write only).
pub fn write_private_key_ecdsa(key: &EcdsaSigningKey, path: &Path) -> CryptoResult<()> {
    let pem = key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
    write_private_key_file(path, pem.as_bytes())
}

/// Reads an ECDSA private key from a PKCS#8 PEM file.
pub fn read_private_key_ecdsa(path: &Path) -> CryptoResult<EcdsaSigningKey> {
    let pem = std::fs::read_to_string(path)?;
    EcdsaSigningKey::from_pkcs8_pem(&pem).map_err(|e| CryptoError::InvalidKey(e.to_string()))
}

/// Writes an ECDSA public key to a file in SPKI PEM format.
pub fn write_public_key_ecdsa(key: &EcdsaVerifyingKey, path: &Path) -> CryptoResult<()> {
    let pem = key
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
    std::fs::write(path, pem.as_bytes())?;
    Ok(())
}

/// Reads an ECDSA public key from a SPKI PEM file.
pub fn read_public_key_ecdsa(path: &Path) -> CryptoResult<EcdsaVerifyingKey> {
    let pem = std::fs::read_to_string(path)?;
    EcdsaVerifyingKey::from_public_key_pem(&pem).map_err(|e| CryptoError::InvalidKey(e.to_string()))
}

/// Writes an EdDSA private key to a file in PKCS#8 PEM format.
///
/// On Unix the file is created with mode 0600 (owner read/write only).
pub fn write_private_key_eddsa(key: &Ed25519SigningKey, path: &Path) -> CryptoResult<()> {
    let pem = key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
    write_private_key_file(path, pem.as_bytes())
}

/// Reads an EdDSA private key from a PKCS#8 PEM file.
pub fn read_private_key_eddsa(path: &Path) -> CryptoResult<Ed25519SigningKey> {
    let pem = std::fs::read_to_string(path)?;
    Ed25519SigningKey::from_pkcs8_pem(&pem).map_err(|e| CryptoError::InvalidKey(e.to_string()))
}

/// Writes an EdDSA public key to a file in SPKI PEM format.
pub fn write_public_key_eddsa(key: &Ed25519VerifyingKey, path: &Path) -> CryptoResult<()> {
    let pem = key
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
    std::fs::write(path, pem.as_bytes())?;
    Ok(())
}

/// Reads an EdDSA public key from a SPKI PEM file.
pub fn read_public_key_eddsa(path: &Path) -> CryptoResult<Ed25519VerifyingKey> {
    let pem = std::fs::read_to_string(path)?;
    Ed25519VerifyingKey::from_public_key_pem(&pem)
        .map_err(|e| CryptoError::InvalidKey(e.to_string()))
}

/// Creates `path` and writes `contents` to it, ensuring the file is never visible with
/// permissions broader than 0600. On Unix the file is opened with mode 0600 at creation
/// time, avoiding the race between write and a subsequent chmod.
fn write_private_key_file(path: &Path, contents: &[u8]) -> CryptoResult<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?
            .write_all(contents)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdsa_key_pair_signs_and_verifies() {
        use p256::ecdsa::{
            Signature,
            signature::{Signer as _, Verifier as _},
        };
        let (signing_key, verifying_key) = generate_ecdsa_key_pair();
        let signature: Signature = signing_key.sign(b"test message");
        assert!(verifying_key.verify(b"test message", &signature).is_ok());
    }

    #[test]
    fn ecdsa_verifying_key_matches_signing_key() {
        let (signing_key, verifying_key) = generate_ecdsa_key_pair();
        assert_eq!(signing_key.verifying_key(), &verifying_key);
    }

    #[test]
    fn eddsa_key_pair_signs_and_verifies() {
        use ed25519_dalek::{Signer as _, Verifier as _};
        let (signing_key, verifying_key) = generate_eddsa_key_pair();
        let signature = signing_key.sign(b"test message");
        assert!(verifying_key.verify(b"test message", &signature).is_ok());
    }

    #[test]
    fn eddsa_verifying_key_matches_signing_key() {
        let (signing_key, verifying_key) = generate_eddsa_key_pair();
        assert_eq!(signing_key.verifying_key(), verifying_key);
    }

    #[test]
    fn ecdsa_private_key_roundtrip() {
        let path = std::env::temp_dir().join("swiyu_test_ecdsa_private.pem");
        let (key, _) = generate_ecdsa_key_pair();
        write_private_key_ecdsa(&key, &path).unwrap();
        let read_back = read_private_key_ecdsa(&path).unwrap();
        assert_eq!(key.verifying_key(), read_back.verifying_key());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn ecdsa_public_key_roundtrip() {
        let path = std::env::temp_dir().join("swiyu_test_ecdsa_public.pem");
        let (_, key) = generate_ecdsa_key_pair();
        write_public_key_ecdsa(&key, &path).unwrap();
        let read_back = read_public_key_ecdsa(&path).unwrap();
        assert_eq!(key, read_back);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn eddsa_private_key_roundtrip() {
        let path = std::env::temp_dir().join("swiyu_test_eddsa_private.pem");
        let (key, _) = generate_eddsa_key_pair();
        write_private_key_eddsa(&key, &path).unwrap();
        let read_back = read_private_key_eddsa(&path).unwrap();
        assert_eq!(key.verifying_key(), read_back.verifying_key());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn eddsa_public_key_roundtrip() {
        let path = std::env::temp_dir().join("swiyu_test_eddsa_public.pem");
        let (_, key) = generate_eddsa_key_pair();
        write_public_key_eddsa(&key, &path).unwrap();
        let read_back = read_public_key_eddsa(&path).unwrap();
        assert_eq!(key, read_back);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    #[cfg(unix)]
    fn ecdsa_private_key_has_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join("swiyu_test_ecdsa_private_perms.pem");
        let (key, _) = generate_ecdsa_key_pair();
        write_private_key_ecdsa(&key, &path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    #[cfg(unix)]
    fn eddsa_private_key_has_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join("swiyu_test_eddsa_private_perms.pem");
        let (key, _) = generate_eddsa_key_pair();
        write_private_key_eddsa(&key, &path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let _ = std::fs::remove_file(&path);
    }
}
