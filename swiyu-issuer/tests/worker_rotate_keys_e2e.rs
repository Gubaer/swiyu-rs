//! End-to-end integration tests for the `RotateKeys` saga.
//!
//! Mirrors `tests/worker_deactivate_e2e.rs` but exercises the
//! rotate-keys path: the saga loads an already-`Active` issuer with
//! its current key triple, generates new key pairs for the
//! requested roles via the `DevSigningEngine`, fetches the
//! registry's DIDLog tail, builds and signs a rotation entry with
//! the *outgoing* Authorized key, PUTs the entry, then atomically
//! swaps the local issuer row's three key columns to the new
//! triple.
//!
//! The fetched genesis log is hand-rolled rather than derived from
//! a prior `CreateIssuer` run — `build_rotation_entry` does not
//! verify the predecessor signature, so a minimal but well-formed
//! TDW 0.3 entry is enough to drive the saga.

#[path = "common/mod.rs"]
mod common;
use common::fixtures::{SAMPLE_PARTNER_ID, SAMPLE_REGISTRY_UUID};
use common::identifier_registry::{SAMPLE_SCID, fixture_did};
use common::rng::ConstantRng;
use common::time::now_micros;

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;

use swiyu_core::didlog::DIDLogEntry;
use swiyu_issuer::domain::{
    DevSigningEngine, Issuer, IssuerId, IssuerState, KeyPairId, KeyRole, OperationTask,
    SigningEngine, TaskState, TaskType, TenantId,
};
use swiyu_issuer::persistence::issuers;
use swiyu_issuer::worker::Worker;
use swiyu_issuer::worker::test_support::{
    FetchLogCall, MockRegistry, MockStatusRegistry, PublishCall,
};

/// Builds a minimal but parseable did:tdw 0.3 genesis entry for
/// `fixture_did()`. The `build_rotation_entry` step only reads
/// `version_id`, `parameters.update_keys` (for the saga-resume
/// short-circuit comparison), and the embedded DID document
/// (which must parse via `DIDDoc::try_from`); signature bytes
/// and parameter fields beyond those are not required.
fn fixture_genesis_entry() -> DIDLogEntry {
    let value: Value = json!([
        "1-Qmfixture-genesis-version-id",
        "2026-04-01T00:00:00Z",
        {
            "method": "did:tdw:0.3",
            "scid": SAMPLE_SCID,
            "updateKeys": ["z6Mk-old-fixture-authorized"],
            "portable": false,
        },
        {
            "value": {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": fixture_did(),
            }
        },
        [],
    ]);
    DIDLogEntry::try_from(&value).expect("fixture genesis parses")
}

/// Returns the inserted issuer (so callers can compare the post-
/// saga key columns against the pre-saga ones) and the engine
/// they were generated through (the same engine instance must run
/// inside the worker so the saga can sign with those keys).
async fn insert_active_issuer(pool: &PgPool, tenant_id: &TenantId) -> (Issuer, DevSigningEngine) {
    let engine = DevSigningEngine::new(pool.clone());
    let authorized = engine.generate_keypair(KeyRole::Authorized).await.unwrap();
    let authentication = engine
        .generate_keypair(KeyRole::Authentication)
        .await
        .unwrap();
    let assertion = engine.generate_keypair(KeyRole::Assertion).await.unwrap();

    let issuer = Issuer {
        did: fixture_did(),
        authorized_key_id: Some(authorized.id),
        authentication_key_id: Some(authentication.id),
        assertion_key_id: Some(assertion.id),
        created_at: now_micros(),
        ..common::issuers::active(tenant_id)
    };
    common::issuers::insert(pool, &issuer).await;
    (issuer, engine)
}

/// `roles` is the wire form: lowercase snake-case role names or
/// the sentinel `"all"`.
fn rotate_task(tenant_id: &TenantId, issuer_id: IssuerId, roles: Vec<&str>) -> OperationTask {
    let now = now_micros();
    OperationTask {
        input: json!({"roles": roles}),
        result_issuer_id: Some(issuer_id),
        created_at: now,
        updated_at: now,
        ..common::operation_tasks::pending(tenant_id, TaskType::RotateKeys)
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn happy_path_rotates_all_three_keys(pool: PgPool) {
    let registry = Arc::new(MockRegistry::new());
    // Two fetch_log calls: build_rotation_didlog + publish_didlog.
    registry.enqueue_fetch_log(FetchLogCall::Ok(vec![fixture_genesis_entry()]));
    registry.enqueue_fetch_log(FetchLogCall::Ok(vec![fixture_genesis_entry()]));
    registry.enqueue_publish(PublishCall::Ok);

    let secret_engine = common::oauth::test_engine();
    let tenant_id = TenantId::generate();
    common::oauth::insert_test_tenant_with_oauth(&pool, &tenant_id, &secret_engine).await;
    let (issuer, engine) = insert_active_issuer(&pool, &tenant_id).await;

    let task = rotate_task(&tenant_id, issuer.id.clone(), vec!["all"]);
    let task_id = task.id.clone();
    common::operation_tasks::insert(&pool, &task).await;

    let (_token_server, providers) =
        common::oauth::build_provider_setup(&pool, Arc::clone(&secret_engine)).await;
    let shutdown = CancellationToken::new();
    let worker = Worker::new(
        pool.clone(),
        Arc::clone(&registry),
        engine,
        MockStatusRegistry::new(),
        providers,
        Box::new(ConstantRng(0)),
    )
    .with_poll_interval(Duration::from_millis(20));
    let handle = tokio::spawn(worker.run(shutdown.clone()));

    let final_task = common::operation_tasks::wait_for_state(
        &pool,
        &tenant_id,
        &task_id,
        TaskState::Completed,
        Duration::from_secs(10),
    )
    .await;

    shutdown.cancel();
    handle.await.unwrap();

    assert_eq!(final_task.state, TaskState::Completed);
    assert_eq!(final_task.state_data["didlog_published"], json!(true));

    // The three key columns on the issuer row changed to fresh ids.
    let mut conn = pool.acquire().await.unwrap();
    let loaded = issuers::find_by_id(&mut conn, &issuer.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.state, Some(IssuerState::Active));
    let new_authorized = loaded.authorized_key_id.unwrap();
    let new_authentication = loaded.authentication_key_id.unwrap();
    let new_assertion = loaded.assertion_key_id.unwrap();
    assert_ne!(Some(new_authorized), issuer.authorized_key_id);
    assert_ne!(Some(new_authentication), issuer.authentication_key_id);
    assert_ne!(Some(new_assertion), issuer.assertion_key_id);

    // The new triple is also recorded in state_data.
    let triple = &final_task.state_data["new_key_triple"];
    assert_eq!(triple["authorized"], json!(new_authorized));
    assert_eq!(triple["authentication"], json!(new_authentication));
    assert_eq!(triple["assertion"], json!(new_assertion));

    // Registry got exactly one publish_log_entry call. The body is
    // the full updated log (genesis + rotation); inspect the LAST
    // line for the rotation entry's parameters.
    let publishes = registry.publish_invocations.lock().unwrap();
    assert_eq!(publishes.len(), 1);
    let (partner, identifier, body_str) = &publishes[0];
    assert_eq!(partner, SAMPLE_PARTNER_ID);
    assert_eq!(identifier, SAMPLE_REGISTRY_UUID);
    let last_line = body_str
        .trim_end_matches('\n')
        .rsplit('\n')
        .next()
        .expect("non-empty body");
    let entry: Value = serde_json::from_str(last_line).unwrap();
    let arr = entry.as_array().expect("entry is a JSON array");
    assert_eq!(arr.len(), 5, "did:tdw 0.3 entries are 5-element arrays");
    let update_keys = arr[2]["updateKeys"].as_array().expect("updateKeys array");
    assert_eq!(update_keys.len(), 1);
    assert_ne!(
        update_keys[0],
        json!("z6Mk-old-fixture-authorized"),
        "rotation entry must advertise a new authorized key, not the old one",
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn rotates_only_authentication(pool: PgPool) {
    let registry = Arc::new(MockRegistry::new());
    registry.enqueue_fetch_log(FetchLogCall::Ok(vec![fixture_genesis_entry()]));
    registry.enqueue_fetch_log(FetchLogCall::Ok(vec![fixture_genesis_entry()]));
    registry.enqueue_publish(PublishCall::Ok);

    let secret_engine = common::oauth::test_engine();
    let tenant_id = TenantId::generate();
    common::oauth::insert_test_tenant_with_oauth(&pool, &tenant_id, &secret_engine).await;
    let (issuer, engine) = insert_active_issuer(&pool, &tenant_id).await;
    let original_authorized: KeyPairId = issuer.authorized_key_id.unwrap();
    let original_assertion: KeyPairId = issuer.assertion_key_id.unwrap();

    let task = rotate_task(&tenant_id, issuer.id.clone(), vec!["authentication"]);
    let task_id = task.id.clone();
    common::operation_tasks::insert(&pool, &task).await;

    let (_token_server, providers) =
        common::oauth::build_provider_setup(&pool, Arc::clone(&secret_engine)).await;
    let shutdown = CancellationToken::new();
    let worker = Worker::new(
        pool.clone(),
        Arc::clone(&registry),
        engine,
        MockStatusRegistry::new(),
        providers,
        Box::new(ConstantRng(0)),
    )
    .with_poll_interval(Duration::from_millis(20));
    let handle = tokio::spawn(worker.run(shutdown.clone()));

    let _final_task = common::operation_tasks::wait_for_state(
        &pool,
        &tenant_id,
        &task_id,
        TaskState::Completed,
        Duration::from_secs(10),
    )
    .await;

    shutdown.cancel();
    handle.await.unwrap();

    // Only authentication changed.
    let mut conn = pool.acquire().await.unwrap();
    let loaded = issuers::find_by_id(&mut conn, &issuer.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.authorized_key_id, Some(original_authorized));
    assert_eq!(loaded.assertion_key_id, Some(original_assertion));
    assert_ne!(loaded.authentication_key_id, issuer.authentication_key_id);
}
