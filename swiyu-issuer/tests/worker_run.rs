//! Integration tests for `worker::Worker::run`.
//!
//! Exercises the dispatch loop end-to-end against a real Postgres pool
//! (`sqlx::test`) and the in-memory mocks from `worker::test_support`.

#[path = "common/mod.rs"]
mod common;
use common::rng::ConstantRng;
use common::time::now_micros;

use std::time::Duration;

use serde_json::json;
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use wiremock::MockServer;

use swiyu_issuer::domain::signing_engine::test_support::{
    GenerateKeypairCall, GetPublicKeyCall, MockSigningEngine, SignCall,
};
use swiyu_issuer::domain::{
    GeneratedKeyPair, IssuerId, KeyAlgorithm, KeyPairId, OperationTask, ProviderRegistry,
    RawPublicKey, Signature, TaskId, TaskState, TaskType, TenantId,
};
use swiyu_issuer::persistence::{issuers, operation_tasks};
use swiyu_issuer::worker::Worker;
use swiyu_issuer::worker::test_support::{
    AllocateCall, MockRegistry, MockStatusRegistry, PublishCall,
};

fn fixture_kid(byte: u8) -> KeyPairId {
    let mut bytes = [byte; 16];
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    KeyPairId::from(Uuid::from_bytes(bytes))
}

fn fixture_ed25519_pk() -> RawPublicKey {
    RawPublicKey {
        algorithm: KeyAlgorithm::Ed25519,
        bytes: vec![0xab; 32],
    }
}

fn fixture_p256_pk() -> RawPublicKey {
    let mut bytes = vec![0x04];
    bytes.extend_from_slice(&[0xcd; 32]);
    bytes.extend_from_slice(&[0xef; 32]);
    RawPublicKey {
        algorithm: KeyAlgorithm::EcdsaP256,
        bytes,
    }
}

fn fixture_signature() -> Signature {
    Signature {
        algorithm: KeyAlgorithm::Ed25519,
        bytes: vec![0x42; 64],
    }
}

fn fixture_keypair(byte: u8, algorithm: KeyAlgorithm) -> GeneratedKeyPair {
    GeneratedKeyPair {
        id: fixture_kid(byte),
        public_key: match algorithm {
            KeyAlgorithm::Ed25519 => fixture_ed25519_pk(),
            KeyAlgorithm::EcdsaP256 => fixture_p256_pk(),
        },
    }
}

fn fixture_allocation() -> swiyu_registries::identifier::Allocation {
    swiyu_registries::identifier::Allocation {
        url: "https://reg.example.com/api/v1/did/abc/did.jsonl".into(),
        identifier: "abc".into(),
    }
}

/// Pre-loads every mock-engine and mock-registry response the
/// happy-path saga consumes:
/// - registry: 1 allocate, 1 publish.
/// - engine: 3 generate, 9 get_public_key (one per role × three
///   steps that build the entry), 3 sign.
fn load_happy_path_mocks(registry: &MockRegistry, engine: &MockSigningEngine) {
    registry.enqueue_allocate(AllocateCall::Ok(fixture_allocation()));
    registry.enqueue_publish(PublishCall::Ok);

    engine.enqueue_generate(GenerateKeypairCall::Ok(fixture_keypair(
        0x11,
        KeyAlgorithm::Ed25519,
    )));
    engine.enqueue_generate(GenerateKeypairCall::Ok(fixture_keypair(
        0x22,
        KeyAlgorithm::EcdsaP256,
    )));
    engine.enqueue_generate(GenerateKeypairCall::Ok(fixture_keypair(
        0x33,
        KeyAlgorithm::EcdsaP256,
    )));

    for _ in 0..3 {
        engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_ed25519_pk()));
        engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_p256_pk()));
        engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_p256_pk()));
        engine.enqueue_sign(SignCall::Ok(fixture_signature()));
    }
}

async fn build_provider_setup(
    pool: &PgPool,
    engine: std::sync::Arc<swiyu_issuer::domain::AnySecretEncryptionEngine>,
) -> (MockServer, std::sync::Arc<ProviderRegistry>) {
    let server = common::oauth::mock_token_endpoint().await;
    let providers = common::oauth::build_provider_registry(pool.clone(), server.uri(), engine);
    (server, providers)
}

fn pending_create_issuer_task(tenant_id: &TenantId, issuer_id: IssuerId) -> OperationTask {
    let now = now_micros();
    OperationTask {
        input: json!({
            "description": common::issuers::SAMPLE_DESCRIPTION,
            "display_name": common::issuers::SAMPLE_DISPLAY_NAME,
        }),
        result_issuer_id: Some(issuer_id),
        created_at: now,
        updated_at: now,
        ..common::operation_tasks::pending(tenant_id, TaskType::CreateIssuer)
    }
}

async fn wait_for_task_state(
    pool: &PgPool,
    tenant_id: &TenantId,
    task_id: &TaskId,
    target: TaskState,
    timeout: Duration,
) -> OperationTask {
    let start = std::time::Instant::now();
    loop {
        let mut conn = pool.acquire().await.unwrap();
        let task = operation_tasks::find_by_id(&mut conn, tenant_id, task_id)
            .await
            .unwrap();
        if task.state == target {
            return task;
        }
        if start.elapsed() >= timeout {
            panic!(
                "wait_for_task_state timed out: target={:?}, last={:?}",
                target, task.state,
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn happy_path_drives_task_to_completion(pool: PgPool) {
    let secret_engine = common::oauth::test_engine();
    let tenant_id = TenantId::generate();
    common::oauth::insert_test_tenant_with_oauth(&pool, &tenant_id, &secret_engine).await;

    let issuer_id = IssuerId::generate();
    let task = pending_create_issuer_task(&tenant_id, issuer_id.clone());
    let task_id = task.id.clone();

    common::operation_tasks::insert(&pool, &task).await;

    let registry = MockRegistry::new();
    let engine = MockSigningEngine::new();
    load_happy_path_mocks(&registry, &engine);
    let status_registry = common::status_registry::with_one_ok();

    let (_token_server, providers) =
        build_provider_setup(&pool, std::sync::Arc::clone(&secret_engine)).await;
    let shutdown = CancellationToken::new();
    let worker = Worker::new(
        pool.clone(),
        registry,
        engine,
        status_registry,
        providers,
        Box::new(ConstantRng(0)),
    )
    .with_poll_interval(Duration::from_millis(20));
    let handle = tokio::spawn(worker.run(shutdown.clone()));

    let final_task = wait_for_task_state(
        &pool,
        &tenant_id,
        &task_id,
        TaskState::Completed,
        Duration::from_secs(5),
    )
    .await;

    shutdown.cancel();
    handle.await.unwrap();

    assert_eq!(final_task.state, TaskState::Completed);
    assert_eq!(final_task.result_issuer_id, Some(issuer_id.clone()));
    assert!(final_task.completed_at.is_some());
    assert_eq!(final_task.state_data["didlog_published"], json!(true));
    assert_eq!(final_task.state_data["assigned_identifier"], json!("abc"));
    assert!(final_task.state_data["assigned_did_url"].is_string());
    assert!(final_task.state_data["key_ids"].is_object());

    let mut conn = pool.acquire().await.unwrap();
    let issuer = issuers::find_by_id(&mut conn, &issuer_id)
        .await
        .unwrap()
        .expect("issuer row inserted");
    assert_eq!(issuer.tenant_id, tenant_id);
    assert!(issuer.did.starts_with("did:tdw:"));
}

#[sqlx::test(migrations = "./migrations")]
async fn shutdown_exits_idle_loop(pool: PgPool) {
    let registry = MockRegistry::new();
    let engine = MockSigningEngine::new();
    let status_registry = MockStatusRegistry::new();
    let secret_engine = common::oauth::test_engine();
    let (_token_server, providers) = build_provider_setup(&pool, secret_engine).await;
    let shutdown = CancellationToken::new();
    let worker = Worker::new(
        pool.clone(),
        registry,
        engine,
        status_registry,
        providers,
        Box::new(ConstantRng(0)),
    )
    .with_poll_interval(Duration::from_millis(20));
    let handle = tokio::spawn(worker.run(shutdown.clone()));

    // Let the loop poll a couple of times against an empty queue.
    tokio::time::sleep(Duration::from_millis(60)).await;
    shutdown.cancel();

    // The loop should exit within one poll interval after cancel.
    tokio::time::timeout(Duration::from_millis(500), handle)
        .await
        .expect("worker exits promptly after cancel")
        .unwrap();
}
