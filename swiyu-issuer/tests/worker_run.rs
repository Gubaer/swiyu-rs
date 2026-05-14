//! Integration tests for `worker::Worker::run`.
//!
//! Exercises the dispatch loop end-to-end against a real Postgres pool
//! (`sqlx::test`) and the in-memory mocks from `test_support::worker`.

use swiyu_issuer::test_support::fixture_kid;
use swiyu_issuer::test_support::fixtures::{SAMPLE_DESCRIPTION, SAMPLE_DISPLAY_NAME};
use swiyu_issuer::test_support::oauth;
use swiyu_issuer::test_support::persistence::operation_tasks as test_operation_tasks;
use swiyu_issuer::test_support::registry::status as test_status_registry;
use swiyu_issuer::test_support::worker::ConstantRng;

use std::time::Duration;

use serde_json::json;
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;

use swiyu_issuer::domain::{
    GeneratedKeyPair, IssuerId, KeyAlgorithm, OperationTask, TaskState, TaskType, TenantId,
};
use swiyu_issuer::persistence::issuers;
use swiyu_issuer::test_support::domain::signing_engine::{
    GenerateKeypairCall, MockSigningEngine, fixture_ed25519_pk, fixture_p256_pk,
};
use swiyu_issuer::test_support::worker::{
    AllocateCall, MockRegistry, MockStatusRegistry, PublishCall,
};
use swiyu_issuer::worker::Worker;

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

// Happy-path call counts: 1 allocate + 1 publish on the registry;
// 3 generate + 9 get_public_key (role × entry-building step) + 3 sign on the engine.
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
        engine.enqueue_happy_step();
    }
}

fn pending_create_issuer_task(tenant_id: &TenantId, issuer_id: IssuerId) -> OperationTask {
    OperationTask {
        input: json!({
            "description": SAMPLE_DESCRIPTION,
            "display_name": SAMPLE_DISPLAY_NAME,
        }),
        result_issuer_id: Some(issuer_id),
        ..test_operation_tasks::pending(tenant_id, TaskType::CreateIssuer)
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn happy_path_drives_task_to_completion(pool: PgPool) {
    let secret_engine = oauth::test_engine();
    let tenant_id = TenantId::generate();
    oauth::insert_test_tenant_with_oauth(&pool, &tenant_id, &secret_engine).await;

    let issuer_id = IssuerId::generate();
    let task = pending_create_issuer_task(&tenant_id, issuer_id.clone());
    let task_id = task.id.clone();

    test_operation_tasks::insert(&pool, &task).await;

    let registry = MockRegistry::new();
    let engine = MockSigningEngine::new();
    load_happy_path_mocks(&registry, &engine);
    let status_registry = test_status_registry::with_one_ok();

    let (_token_server, providers) =
        oauth::build_provider_setup(&pool, std::sync::Arc::clone(&secret_engine)).await;
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

    let final_task = test_operation_tasks::wait_for_state(
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
    let secret_engine = oauth::test_engine();
    let (_token_server, providers) = oauth::build_provider_setup(&pool, secret_engine).await;
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
