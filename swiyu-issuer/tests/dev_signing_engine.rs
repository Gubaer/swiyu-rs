//! Integration tests for `DevSigningEngine`.
//!
//! Each test runs against a freshly created Postgres database created
//! by `sqlx::test`; migrations are applied automatically. Requires
//! `DATABASE_URL` to point to a Postgres instance whose user has
//! `CREATEDB` privilege.

use ed25519_dalek::Signature as Ed25519Signature;
use ed25519_dalek::Verifier;
use ed25519_dalek::VerifyingKey as Ed25519VerifyingKey;
use p256::ecdsa::Signature as EcdsaSignature;
use p256::ecdsa::VerifyingKey as EcdsaVerifyingKey;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use sqlx::PgPool;

use swiyu_issuer::domain::{
    DevSigningEngine, KeyAlgorithm, KeyPairId, KeyRole, SigningEngine, SigningEngineError,
};

#[sqlx::test(migrations = "./migrations")]
async fn generate_keypair_persists_row(pool: PgPool) {
    let engine = DevSigningEngine::new(pool.clone());

    let kp = engine.generate_keypair(KeyRole::Authorized).await.unwrap();

    let (algorithm, public_key): (String, Vec<u8>) = sqlx::query_as(
        "SELECT algorithm, public_key FROM signing_engine_dev_keypairs WHERE id = $1",
    )
    .bind(kp.id.as_uuid())
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(algorithm, "ed25519");
    assert_eq!(public_key, kp.public_key.bytes);
    assert_eq!(kp.public_key.algorithm, KeyAlgorithm::Ed25519);
}

#[sqlx::test(migrations = "./migrations")]
async fn generated_keys_per_role_have_expected_algorithm(pool: PgPool) {
    let engine = DevSigningEngine::new(pool);

    for role in [
        KeyRole::Authorized,
        KeyRole::Authentication,
        KeyRole::Assertion,
    ] {
        let kp = engine.generate_keypair(role).await.unwrap();
        assert_eq!(kp.public_key.algorithm, KeyAlgorithm::for_role(role));
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn sign_with_ed25519_id_produces_verifiable_signature(pool: PgPool) {
    let engine = DevSigningEngine::new(pool);

    let kp = engine.generate_keypair(KeyRole::Authorized).await.unwrap();
    let input = [0xa5_u8; 32];

    let signature = engine.sign(&kp.id, &input).await.unwrap();
    assert_eq!(signature.algorithm, KeyAlgorithm::Ed25519);
    assert_eq!(signature.bytes.len(), 64);

    let public_array: [u8; 32] = kp.public_key.bytes.as_slice().try_into().unwrap();
    let verifying_key = Ed25519VerifyingKey::from_bytes(&public_array).unwrap();
    let signature_array: [u8; 64] = signature.bytes.as_slice().try_into().unwrap();
    let parsed = Ed25519Signature::from_bytes(&signature_array);
    verifying_key.verify(&input, &parsed).unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn sign_with_ecdsa_id_produces_verifiable_signature(pool: PgPool) {
    let engine = DevSigningEngine::new(pool);

    let kp = engine.generate_keypair(KeyRole::Assertion).await.unwrap();
    let input = [0x5a_u8; 32];

    let signature = engine.sign(&kp.id, &input).await.unwrap();
    assert_eq!(signature.algorithm, KeyAlgorithm::EcdsaP256);
    assert_eq!(signature.bytes.len(), 64);

    let verifying_key = EcdsaVerifyingKey::from_sec1_bytes(&kp.public_key.bytes).unwrap();
    let parsed = EcdsaSignature::from_slice(&signature.bytes).unwrap();
    verifying_key.verify_prehash(&input, &parsed).unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn sign_with_ed25519_id_accepts_64_byte_message(pool: PgPool) {
    // The eddsa-jcs-2022 cryptosuite hands Ed25519 a 64-byte concatenation
    // of two SHA-256 hashes; the engine must accept variable-length input
    // for Ed25519 keys and feed it straight into the signer.
    let engine = DevSigningEngine::new(pool);

    let kp = engine.generate_keypair(KeyRole::Authorized).await.unwrap();
    let input = [0x3c_u8; 64];

    let signature = engine.sign(&kp.id, &input).await.unwrap();
    assert_eq!(signature.algorithm, KeyAlgorithm::Ed25519);
    assert_eq!(signature.bytes.len(), 64);

    let public_array: [u8; 32] = kp.public_key.bytes.as_slice().try_into().unwrap();
    let verifying_key = Ed25519VerifyingKey::from_bytes(&public_array).unwrap();
    let signature_array: [u8; 64] = signature.bytes.as_slice().try_into().unwrap();
    let parsed = Ed25519Signature::from_bytes(&signature_array);
    verifying_key.verify(&input, &parsed).unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn sign_with_ecdsa_id_rejects_non_32_byte_input(pool: PgPool) {
    let engine = DevSigningEngine::new(pool);

    let kp = engine.generate_keypair(KeyRole::Assertion).await.unwrap();
    let input = [0x5a_u8; 31];

    let result = engine.sign(&kp.id, &input).await;

    match result {
        Err(SigningEngineError::InvalidInputLength { expected, actual }) => {
            assert_eq!(expected, 32);
            assert_eq!(actual, 31);
        }
        other => panic!("expected InvalidInputLength, got: {other:?}"),
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn sign_with_unknown_id_returns_key_not_found(pool: PgPool) {
    let engine = DevSigningEngine::new(pool);
    let unknown = KeyPairId::generate();
    let input = [0_u8; 32];

    let result = engine.sign(&unknown, &input).await;

    match result {
        Err(SigningEngineError::KeyNotFound(id)) => assert_eq!(id, unknown),
        other => panic!("expected KeyNotFound, got: {other:?}"),
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn get_public_key_returns_what_generate_keypair_returned(pool: PgPool) {
    let engine = DevSigningEngine::new(pool);

    for role in [
        KeyRole::Authorized,
        KeyRole::Authentication,
        KeyRole::Assertion,
    ] {
        let kp = engine.generate_keypair(role).await.unwrap();
        let fetched = engine.get_public_key(&kp.id).await.unwrap();
        assert_eq!(fetched, kp.public_key, "role={role:?}");
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn get_public_key_with_unknown_id_returns_key_not_found(pool: PgPool) {
    let engine = DevSigningEngine::new(pool);
    let unknown = KeyPairId::generate();

    let result = engine.get_public_key(&unknown).await;

    match result {
        Err(SigningEngineError::KeyNotFound(id)) => assert_eq!(id, unknown),
        other => panic!("expected KeyNotFound, got: {other:?}"),
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn delete_keypair_removes_row_and_is_idempotent(pool: PgPool) {
    let engine = DevSigningEngine::new(pool.clone());

    let kp = engine.generate_keypair(KeyRole::Authorized).await.unwrap();

    engine.delete_keypair(&kp.id).await.unwrap();

    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM signing_engine_dev_keypairs WHERE id = $1")
            .bind(kp.id.as_uuid())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 0);

    // Second call must succeed even though the key is already gone.
    engine.delete_keypair(&kp.id).await.unwrap();
}
