//! End-to-end integration tests for the operation-task worker.
//!
//! Exercises the full saga against:
//! - a real Postgres pool (`sqlx::test`)
//! - a real `IdentifierRegistryClient` pointed at a wiremock server
//! - a real `DevSigningEngine` against the test pool
//!
//! The only mocked component is the registry's HTTP endpoint; the
//! client logic, signing engine, and persistence layer all run for
//! real. Complements the in-memory mock-based tests in
//! `tests/worker_run.rs`.

#[path = "common/mod.rs"]
mod common;
use common::fixtures::SAMPLE_REGISTRY_UUID;
use common::identifier_registry::{allocate_path, publish_path, registry_url_in_response};
use common::time::now_micros;

use std::time::Duration;

use serde_json::json;
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use swiyu_issuer::domain::{IssuerId, OperationTask, TaskState, TaskType, TenantId};
use swiyu_issuer::persistence::issuers;

fn pending_task(tenant_id: &TenantId, issuer_id: IssuerId) -> OperationTask {
    let now = now_micros();
    OperationTask {
        input: json!({
            "description": "E2E test issuer",
            "display_name": "E2E",
        }),
        result_issuer_id: Some(issuer_id),
        created_at: now,
        updated_at: now,
        ..common::operation_tasks::pending(tenant_id, TaskType::CreateIssuer)
    }
}

/// Spawn a wiremock token endpoint and build a `ProviderRegistry`
/// pointed at it. The returned `MockServer` must be kept alive for
/// the duration of the worker run; once it drops, the bound port
/// closes and any further `provider.get()` calls would fail.
#[sqlx::test(migrations = "./migrations")]
async fn happy_path_drives_task_to_completion(pool: PgPool) {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path(allocate_path()))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "identifierRegistryUrl": registry_url_in_response() })),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("PUT"))
        .and(path(publish_path()))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let engine = common::oauth::test_engine();
    let tenant_id = TenantId::generate();
    common::oauth::insert_test_tenant_with_oauth(&pool, &tenant_id, &engine).await;

    let issuer_id = IssuerId::generate();
    let task = pending_task(&tenant_id, issuer_id.clone());
    let task_id = task.id.clone();
    common::operation_tasks::insert(&pool, &task).await;

    let (_token_server, providers) =
        common::oauth::build_provider_setup(&pool, std::sync::Arc::clone(&engine)).await;
    let shutdown = CancellationToken::new();
    let worker = common::worker::build_real(pool.clone(), &server, providers);
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

    // The allocate response carried SAMPLE_REGISTRY_UUID in the URL; verify it
    // round-tripped into state_data.
    assert_eq!(
        final_task.state_data["assigned_identifier"],
        json!(SAMPLE_REGISTRY_UUID)
    );
    assert_eq!(final_task.state_data["didlog_published"], json!(true));

    let mut conn = pool.acquire().await.unwrap();
    let issuer = issuers::find_by_id(&mut conn, &issuer_id)
        .await
        .unwrap()
        .expect("issuer row inserted");
    assert!(issuer.did.starts_with("did:tdw:"));

    // The DevSigningEngine should have written three keys for this task.
    let key_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM signing_engine_dev_keypairs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(key_count, 3);
}

#[sqlx::test(migrations = "./migrations")]
async fn registry_503_on_publish_is_retried_until_success(pool: PgPool) {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path(allocate_path()))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "identifierRegistryUrl": registry_url_in_response() })),
        )
        .expect(1)
        .mount(&server)
        .await;

    // 503 for the first call. wiremock matches in registration order,
    // so this stub serves the first request, then `up_to_n_times`
    // exhausts and the always-204 stub below takes over.
    Mock::given(method("PUT"))
        .and(path(publish_path()))
        .respond_with(ResponseTemplate::new(503).set_body_string("service unavailable"))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("PUT"))
        .and(path(publish_path()))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let engine = common::oauth::test_engine();
    let tenant_id = TenantId::generate();
    common::oauth::insert_test_tenant_with_oauth(&pool, &tenant_id, &engine).await;

    let issuer_id = IssuerId::generate();
    let task = pending_task(&tenant_id, issuer_id.clone());
    let task_id = task.id.clone();
    common::operation_tasks::insert(&pool, &task).await;

    let (_token_server, providers) =
        common::oauth::build_provider_setup(&pool, std::sync::Arc::clone(&engine)).await;
    let shutdown = CancellationToken::new();
    // ConstantRng(0) → backoff_delay returns 0ms, so the retry fires on
    // the very next poll without waiting on real exponential backoff.
    let worker = common::worker::build_real(pool.clone(), &server, providers);
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

    // The publish endpoint was hit at least twice (one 503 + one 200).
    let publish_hits = server
        .received_requests()
        .await
        .expect("request recording enabled")
        .iter()
        .filter(|req| req.method == wiremock::http::Method::PUT && req.url.path() == publish_path())
        .count();
    assert!(
        publish_hits >= 2,
        "expected at least 2 publish attempts, got {publish_hits}",
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn resume_after_crash_skips_allocate_did(pool: PgPool) {
    let server = MockServer::start().await;

    // No allocate mock: a request would 404 and the task would Terminal-
    // fail. The whole point of this test is that allocate_did's
    // idempotency check short-circuits before any registry call.
    Mock::given(method("PUT"))
        .and(path(publish_path()))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let engine = common::oauth::test_engine();
    let tenant_id = TenantId::generate();
    common::oauth::insert_test_tenant_with_oauth(&pool, &tenant_id, &engine).await;

    // Pre-populate state_data with allocate_did's output, simulating a
    // crash that occurred after allocate_did succeeded but before
    // generate_keys.
    let issuer_id = IssuerId::generate();
    let mut task = pending_task(&tenant_id, issuer_id.clone());
    task.state_data = json!({
        "assigned_did_url": registry_url_in_response(),
        "assigned_identifier": SAMPLE_REGISTRY_UUID,
    });
    let task_id = task.id.clone();
    common::operation_tasks::insert(&pool, &task).await;

    let (_token_server, providers) =
        common::oauth::build_provider_setup(&pool, std::sync::Arc::clone(&engine)).await;
    let shutdown = CancellationToken::new();
    let worker = common::worker::build_real(pool.clone(), &server, providers);
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

    // Verify allocate_did was skipped — the registry got no POST.
    let allocate_hits = server
        .received_requests()
        .await
        .expect("request recording enabled")
        .iter()
        .filter(|req| {
            req.method == wiremock::http::Method::POST && req.url.path() == allocate_path()
        })
        .count();
    assert_eq!(
        allocate_hits, 0,
        "allocate_did should have been skipped on resume",
    );
}
