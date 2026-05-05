//! Integration tests for `VaultSigningEngine`.
//!
//! Hits a real Vault Transit backend over HTTP. `#[ignore]` by default so
//! that `cargo test` stays green in environments without Vault. Run them
//! explicitly:
//!
//! ```sh
//! docker compose up -d vault vault-init
//! cargo test --test vault_signing_engine -- --ignored
//! docker compose down -v
//! ```
//!
//! Reads `VAULT_ADDR` and `VAULT_TOKEN` from the environment; defaults
//! match the dev compose so the tests run unmodified against the local
//! container.

use std::env;

use ed25519_dalek::Signature as Ed25519Signature;
use ed25519_dalek::Verifier;
use ed25519_dalek::VerifyingKey as Ed25519VerifyingKey;
use p256::ecdsa::Signature as EcdsaSignature;
use p256::ecdsa::VerifyingKey as EcdsaVerifyingKey;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use reqwest::Url;
use secrecy::SecretString;

use swiyu_issuer::domain::{
    KeyAlgorithm, KeyPairId, KeyRole, SigningEngineError, VaultSigningEngine,
    VaultSigningEngineConfig,
};

const DEFAULT_VAULT_ADDR: &str = "http://127.0.0.1:8200";
const DEFAULT_VAULT_TOKEN: &str = "dev-only-root";

fn engine() -> VaultSigningEngine {
    let address = env::var("VAULT_ADDR").unwrap_or_else(|_| DEFAULT_VAULT_ADDR.to_string());
    let token = env::var("VAULT_TOKEN").unwrap_or_else(|_| DEFAULT_VAULT_TOKEN.to_string());
    VaultSigningEngine::new(VaultSigningEngineConfig {
        address: Url::parse(&address).expect("VAULT_ADDR must be a valid URL"),
        token: SecretString::from(token),
        transit_path: VaultSigningEngineConfig::DEFAULT_TRANSIT_PATH.to_string(),
        request_timeout: VaultSigningEngineConfig::DEFAULT_REQUEST_TIMEOUT,
    })
}

#[tokio::test]
#[ignore = "requires running Vault container"]
async fn ed25519_full_roundtrip() {
    let engine = engine();
    let pair = engine.generate_keypair(KeyRole::Authorized).await.unwrap();
    assert_eq!(pair.public_key.algorithm, KeyAlgorithm::Ed25519);
    assert_eq!(pair.public_key.bytes.len(), 32);

    let read_pk = engine.get_public_key(&pair.id).await.unwrap();
    assert_eq!(read_pk.bytes, pair.public_key.bytes);

    let input = b"hello swiyu";
    let signature = engine.sign(&pair.id, input).await.unwrap();
    assert_eq!(signature.algorithm, KeyAlgorithm::Ed25519);
    assert_eq!(signature.bytes.len(), 64);

    // Verify the signature locally with the public key Vault returned.
    let public_array: [u8; 32] = pair.public_key.bytes.as_slice().try_into().unwrap();
    let verifying_key = Ed25519VerifyingKey::from_bytes(&public_array).unwrap();
    let signature_array: [u8; 64] = signature.bytes.as_slice().try_into().unwrap();
    let sig = Ed25519Signature::from_bytes(&signature_array);
    verifying_key
        .verify(input, &sig)
        .expect("Vault Ed25519 signature should verify locally");

    engine.delete_keypair(&pair.id).await.unwrap();
    let err = engine.sign(&pair.id, input).await.unwrap_err();
    match err {
        SigningEngineError::KeyNotFound(returned) => assert_eq!(returned, pair.id),
        other => panic!("expected KeyNotFound after delete, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "requires running Vault container"]
async fn ecdsa_p256_full_roundtrip() {
    let engine = engine();
    let pair = engine.generate_keypair(KeyRole::Assertion).await.unwrap();
    assert_eq!(pair.public_key.algorithm, KeyAlgorithm::EcdsaP256);
    // SEC1 uncompressed: 0x04 || x || y, 65 bytes.
    assert_eq!(pair.public_key.bytes.len(), 65);
    assert_eq!(pair.public_key.bytes[0], 0x04);

    let read_pk = engine.get_public_key(&pair.id).await.unwrap();
    assert_eq!(read_pk.bytes, pair.public_key.bytes);

    let digest = [0xa5_u8; 32];
    let signature = engine.sign(&pair.id, &digest).await.unwrap();
    assert_eq!(signature.algorithm, KeyAlgorithm::EcdsaP256);
    assert_eq!(signature.bytes.len(), 64);

    let verifying_key = EcdsaVerifyingKey::from_sec1_bytes(&pair.public_key.bytes).unwrap();
    let sig = EcdsaSignature::from_slice(&signature.bytes).unwrap();
    verifying_key
        .verify_prehash(&digest, &sig)
        .expect("Vault ECDSA signature should verify locally");

    engine.delete_keypair(&pair.id).await.unwrap();
    let err = engine.sign(&pair.id, &digest).await.unwrap_err();
    assert!(matches!(err, SigningEngineError::KeyNotFound(_)));
}

#[tokio::test]
#[ignore = "requires running Vault container"]
async fn ed25519_signs_variable_length_inputs() {
    let engine = engine();
    let pair = engine.generate_keypair(KeyRole::Authorized).await.unwrap();
    let public_array: [u8; 32] = pair.public_key.bytes.as_slice().try_into().unwrap();
    let verifying_key = Ed25519VerifyingKey::from_bytes(&public_array).unwrap();

    // Catches any accidental pre-hashing on the engine side: Ed25519 must
    // accept arbitrary input lengths and feed them to plain Ed25519.
    for len in [32_usize, 64, 100] {
        let input = vec![0x3c_u8; len];
        let signature = engine.sign(&pair.id, &input).await.unwrap();
        let signature_array: [u8; 64] = signature.bytes.as_slice().try_into().unwrap();
        let sig = Ed25519Signature::from_bytes(&signature_array);
        verifying_key
            .verify(&input, &sig)
            .unwrap_or_else(|e| panic!("verify failed for len={len}: {e}"));
    }

    engine.delete_keypair(&pair.id).await.unwrap();
}

#[tokio::test]
#[ignore = "requires running Vault container"]
async fn ecdsa_p256_rejects_31_byte_input_and_accepts_32() {
    let engine = engine();
    let pair = engine.generate_keypair(KeyRole::Assertion).await.unwrap();

    let err = engine.sign(&pair.id, &[0x5a_u8; 31]).await.unwrap_err();
    assert!(matches!(
        err,
        SigningEngineError::InvalidInputLength {
            expected: 32,
            actual: 31,
        }
    ));

    engine.sign(&pair.id, &[0x5a_u8; 32]).await.unwrap();

    engine.delete_keypair(&pair.id).await.unwrap();
}

#[tokio::test]
#[ignore = "requires running Vault container"]
async fn delete_keypair_for_unknown_id_is_ok() {
    let engine = engine();
    let unknown = KeyPairId::generate();
    engine.delete_keypair(&unknown).await.unwrap();
}

#[tokio::test]
#[ignore = "requires running Vault container"]
async fn delete_keypair_is_idempotent() {
    let engine = engine();
    let pair = engine.generate_keypair(KeyRole::Authorized).await.unwrap();
    engine.delete_keypair(&pair.id).await.unwrap();
    engine.delete_keypair(&pair.id).await.unwrap();
}
