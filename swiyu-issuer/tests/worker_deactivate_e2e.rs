//! End-to-end integration tests for the `DeactivateIssuer` saga.
//!
//! Mirrors `tests/worker_e2e.rs` but exercises the deactivation path:
//! the saga loads an already-`Active` issuer, fetches the registry's
//! DIDLog tail, builds and signs a deactivation entry, PUTs it to
//! the registry, then flips the local issuer row to `Deactivated`
//! and bulk-cancels its pending offers.
//!
//! The fetched genesis log is hand-rolled rather than derived from
//! a prior `CreateIssuer` run — `build_deactivation_entry` does not
//! verify the predecessor signature, so a minimal but well-formed
//! TDW 0.3 entry is enough to drive the saga.

#[path = "common/mod.rs"]
mod common;
use common::fixtures::{SAMPLE_PARTNER_ID, SAMPLE_REGISTRY_UUID};
use common::rng::ConstantRng;
use common::time::now_micros;

use std::sync::Arc;
use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use serde_json::{Value, json};
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;

use swiyu_issuer::domain::{
    CredentialOffer, CredentialOfferState, IssuerId, IssuerState, OperationTask, PreAuthCode,
    TaskState, TaskType, TenantId,
};
use swiyu_issuer::persistence::{credential_offers, issuers};
use swiyu_issuer::worker::Worker;
use swiyu_issuer::worker::test_support::{
    FetchLogCall, MockRegistry, MockStatusRegistry, PublishCall,
};

async fn insert_pending_offer(
    pool: &PgPool,
    tenant_id: &TenantId,
    issuer_id: &IssuerId,
) -> CredentialOffer {
    let offer = common::credential_offers::pending(tenant_id, issuer_id);
    common::credential_offers::insert(pool, &offer).await;
    offer
}

async fn insert_issued_offer(
    pool: &PgPool,
    tenant_id: &TenantId,
    issuer_id: &IssuerId,
) -> CredentialOffer {
    let mut offer = CredentialOffer::new(
        tenant_id.clone(),
        issuer_id.clone(),
        "https://example.com/vct/test".into(),
        json!({"first_name": "Beat"}),
        PreAuthCode::generate(),
        Utc::now() + ChronoDuration::hours(1),
    );
    offer.state = CredentialOfferState::Issued;
    offer.issued_at = Some(now_micros());
    offer.pre_auth_code = None;
    common::credential_offers::insert(pool, &offer).await;
    offer
}

fn deactivate_task(tenant_id: &TenantId, issuer_id: IssuerId) -> OperationTask {
    OperationTask {
        result_issuer_id: Some(issuer_id),
        ..common::operation_tasks::pending(tenant_id, TaskType::DeactivateIssuer)
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn happy_path_deactivates_issuer_and_cancels_pending_offers(pool: PgPool) {
    let registry = Arc::new(MockRegistry::new());
    // Two fetch_log calls: one in build_deactivation_didlog, one in
    // publish_didlog.
    registry.enqueue_fetch_log(FetchLogCall::Ok(vec![
        common::identifier_registry::fixture_genesis_entry(&["z6Mk-fixture-authorized"]),
    ]));
    registry.enqueue_fetch_log(FetchLogCall::Ok(vec![
        common::identifier_registry::fixture_genesis_entry(&["z6Mk-fixture-authorized"]),
    ]));
    // One publish_log_entry call from publish_didlog.
    registry.enqueue_publish(PublishCall::Ok);

    let secret_engine = common::oauth::test_engine();
    let tenant_id = TenantId::generate();
    common::oauth::insert_test_tenant_with_oauth(&pool, &tenant_id, &secret_engine).await;
    let (issuer, engine) = common::issuers::insert_active_with_engine_keys(&pool, &tenant_id).await;
    let issuer_id = issuer.id.clone();

    let pending_a = insert_pending_offer(&pool, &tenant_id, &issuer_id).await;
    let pending_b = insert_pending_offer(&pool, &tenant_id, &issuer_id).await;
    let issued = insert_issued_offer(&pool, &tenant_id, &issuer_id).await;

    let task = deactivate_task(&tenant_id, issuer_id.clone());
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
    assert_eq!(final_task.result_issuer_id, Some(issuer_id.clone()));
    assert_eq!(final_task.state_data["didlog_published"], json!(true));

    let mut conn = pool.acquire().await.unwrap();
    let loaded_issuer = issuers::find_by_id(&mut conn, &issuer_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded_issuer.state, Some(IssuerState::Deactivated));

    // Pending offers were cancelled.
    let loaded_a = credential_offers::find_by_id(&mut conn, &tenant_id, &issuer_id, &pending_a.id)
        .await
        .unwrap();
    assert_eq!(loaded_a.state, CredentialOfferState::Cancelled);
    assert!(loaded_a.pre_auth_code.is_none());

    let loaded_b = credential_offers::find_by_id(&mut conn, &tenant_id, &issuer_id, &pending_b.id)
        .await
        .unwrap();
    assert_eq!(loaded_b.state, CredentialOfferState::Cancelled);

    // Issued offers untouched.
    let loaded_issued =
        credential_offers::find_by_id(&mut conn, &tenant_id, &issuer_id, &issued.id)
            .await
            .unwrap();
    assert_eq!(loaded_issued.state, CredentialOfferState::Issued);
    assert_eq!(loaded_issued.issued_at, issued.issued_at);

    // Registry got exactly one publish_log_entry call. The wire form
    // is a single JSONL line (the deactivation entry only — the
    // publish_didlog step builds the full updated log itself, but the
    // mock records what the worker passed to publish_log_entry, which
    // is the concatenated JSONL body). Inspect the LAST line, which
    // is the new deactivation entry.
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
    assert_eq!(arr[2]["deactivated"], json!(true));
    assert_eq!(arr[2]["updateKeys"], json!([]));
}
