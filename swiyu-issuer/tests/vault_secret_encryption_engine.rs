//! Integration tests for `VaultSecretEncryptionEngine`.
//!
//! Hits a real Vault Transit backend over HTTP. `#[ignore]` by default so
//! that `cargo test` stays green in environments without Vault. Run them
//! explicitly:
//!
//! ```sh
//! docker compose up -d vault vault-init
//! cargo test --test vault_secret_encryption_engine -- --ignored
//! docker compose down -v
//! ```
//!
//! Reads `VAULT_ADDR` and `VAULT_TOKEN` from the environment; defaults
//! match the dev compose so the tests run unmodified against the local
//! container. Each test creates a throwaway Transit key under a UUID
//! name; keys are intentionally not deleted (Vault Transit deletion
//! requires a per-key config dance, and `docker compose down -v` wipes
//! the container anyway).
//!
//! These tests are the canary against silent wording changes in Vault's
//! 400 response bodies (`encryption key not found`,
//! `cipher: message authentication failed`).

#[path = "common/mod.rs"]
mod common;
use common::vault::{vault_addr, vault_token};

use reqwest::{Client, Url};
use secrecy::SecretString;
use serde_json::json;
use uuid::Uuid;

use swiyu_issuer::domain::{
    Ciphertext, SecretEncryptionEngine, SecretEncryptionError, VaultSecretEncryptionEngine,
    VaultSecretEncryptionEngineConfig,
};

fn engine() -> VaultSecretEncryptionEngine {
    VaultSecretEncryptionEngine::new(VaultSecretEncryptionEngineConfig {
        address: Url::parse(&vault_addr()).expect("VAULT_ADDR must be a valid URL"),
        token: SecretString::from(vault_token()),
        transit_path: VaultSecretEncryptionEngineConfig::DEFAULT_TRANSIT_PATH.to_string(),
        request_timeout: VaultSecretEncryptionEngineConfig::DEFAULT_REQUEST_TIMEOUT,
    })
}

fn unique_key_name() -> String {
    // UUID rather than a tenant-shaped name: these are throwaway test
    // keys, not real tenant keys, and the engine accepts any string.
    format!("secret-mgmt-it-{}", Uuid::new_v4())
}

async fn create_transit_key(name: &str) {
    let client = Client::new();
    let url = format!("{}/v1/transit/keys/{name}", vault_addr());
    let response = client
        .post(&url)
        .header("X-Vault-Token", vault_token())
        .json(&json!({ "type": "aes256-gcm96" }))
        .send()
        .await
        .expect("Vault create-key request");
    assert!(
        response.status().is_success(),
        "Vault create-key failed: {} {}",
        response.status(),
        response.text().await.unwrap_or_default()
    );
}

#[tokio::test]
#[ignore = "requires running Vault container"]
async fn round_trip() {
    let key_name = unique_key_name();
    create_transit_key(&key_name).await;
    let engine = engine();
    let plaintext = b"hello, swiyu";
    let ct = engine.encrypt(&key_name, plaintext).await.unwrap();
    let pt = engine.decrypt(&key_name, &ct).await.unwrap();
    assert_eq!(pt.as_slice(), plaintext);
}

#[tokio::test]
#[ignore = "requires running Vault container"]
async fn encrypt_unknown_key_returns_key_not_found() {
    // Body-substring canary: Vault 1.18 returns
    // `encryption key not found` on POST encrypt/<missing>.
    let missing = unique_key_name();
    let engine = engine();
    let err = engine.encrypt(&missing, b"x").await.unwrap_err();
    match err {
        SecretEncryptionError::KeyNotFound(name) => assert_eq!(name, missing),
        other => panic!("expected KeyNotFound, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "requires running Vault container"]
async fn decrypt_unknown_key_returns_key_not_found() {
    // The decrypt request reaches Vault only because the envelope's
    // `key_name` matches the argument; Vault then surfaces the missing
    // key.
    let missing = unique_key_name();
    let engine = engine();
    let envelope_bytes = synthetic_vault_envelope(&missing, 1, b"vault-payload-bytes");
    let ct = Ciphertext::from(envelope_bytes);
    let err = engine.decrypt(&missing, &ct).await.unwrap_err();
    match err {
        SecretEncryptionError::KeyNotFound(name) => assert_eq!(name, missing),
        other => panic!("expected KeyNotFound, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "requires running Vault container"]
async fn tampered_payload_returns_tampered() {
    // Body-substring canary: Vault 1.18 returns
    // `cipher: message authentication failed` when the inner GCM tag
    // fails to verify.
    let key_name = unique_key_name();
    create_transit_key(&key_name).await;
    let engine = engine();
    let mut ct = engine.encrypt(&key_name, b"plaintext").await.unwrap();
    // Mutate a byte inside the vault_payload (past the preamble:
    // 1 byte format + 1 byte key_name_len + key_name + 4 bytes
    // key_version). Picking the very last byte hits ciphertext, not the
    // envelope frame.
    let bytes = ct.as_bytes().to_vec();
    let last = bytes.len() - 1;
    let mut mutated = bytes;
    mutated[last] ^= 0x01;
    ct = Ciphertext::from(mutated);
    let err = engine.decrypt(&key_name, &ct).await.unwrap_err();
    assert!(
        matches!(err, SecretEncryptionError::Tampered),
        "expected Tampered, got {err:?}"
    );
}

// Hand-rolls a format-0x02 envelope. Mirrors the encoder in
// `secret_encryption_engine::vault::envelope`; duplicated here so the
// integration test does not depend on the internal helper.
fn synthetic_vault_envelope(key_name: &str, key_version: u32, vault_payload: &[u8]) -> Vec<u8> {
    let key_name_bytes = key_name.as_bytes();
    assert!(key_name_bytes.len() <= 255);
    let mut out = Vec::with_capacity(1 + 1 + key_name_bytes.len() + 4 + vault_payload.len());
    out.push(0x02);
    out.push(key_name_bytes.len() as u8);
    out.extend_from_slice(key_name_bytes);
    out.extend_from_slice(&key_version.to_be_bytes());
    out.extend_from_slice(vault_payload);
    out
}
