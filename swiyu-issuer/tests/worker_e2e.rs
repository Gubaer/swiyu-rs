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

use std::time::Duration;

use chrono::{DateTime, Timelike, Utc};
use rand_core::RngCore;
use serde_json::json;
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use swiyu_issuer::domain::{
    DevSigningEngine, IssuerId, OperationTask, TaskId, TaskState, TaskType, TenantId,
};
use swiyu_issuer::persistence::{issuers, operation_tasks};
use swiyu_issuer::worker::Worker;
use swiyu_issuer::worker::test_support::{CreateStatusListEntryCall, MockStatusRegistry};
use swiyu_registries::identifier::IdentifierRegistryClient;
use swiyu_registries::status::StatusListEntry;

const STATUS_ENTRY_ID: &str = "11111111-2222-3333-4444-555555555555";
const STATUS_REGISTRY_URL: &str = "https://status-reg.test/lists/abc.jwt";

fn status_registry_with_one_ok() -> MockStatusRegistry {
    let r = MockStatusRegistry::new();
    r.enqueue_create(CreateStatusListEntryCall::Ok(StatusListEntry {
        id: STATUS_ENTRY_ID.into(),
        registry_url: STATUS_REGISTRY_URL.into(),
    }));
    r
}

const PARTNER_ID: &str = "4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef";
const REGISTRY_UUID: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

fn allocate_path() -> String {
    format!("/api/v1/identifier/business-entities/{PARTNER_ID}/identifier-entries")
}

fn publish_path() -> String {
    format!("/api/v1/identifier/business-entities/{PARTNER_ID}/identifier-entries/{REGISTRY_UUID}")
}

/// The URL the registry returns in the allocate response. Picked so
/// didlog_builder's URL parser can derive a clean did:tdw host/path.
fn registry_url_in_response() -> String {
    format!("https://reg.test/api/v1/did/{REGISTRY_UUID}/did.jsonl")
}

fn now_micros() -> DateTime<Utc> {
    let t = Utc::now();
    let nanos = t.nanosecond();
    t.with_nanosecond(nanos - (nanos % 1_000)).unwrap()
}

struct ConstantRng(u64);

impl RngCore for ConstantRng {
    fn next_u32(&mut self) -> u32 {
        self.0 as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.0
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let bytes = self.0.to_le_bytes();
            let take = chunk.len().min(bytes.len());
            chunk[..take].copy_from_slice(&bytes[..take]);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

async fn insert_test_tenant(
    pool: &PgPool,
    tenant_id: &TenantId,
    partner_id: &str,
    engine: &swiyu_issuer::domain::AnySecretEncryptionEngine,
) {
    common::oauth::insert_tenant_with_oauth_secrets(
        pool,
        tenant_id,
        Some(partner_id),
        engine,
        "test-client",
        "test-secret",
        "test-refresh",
    )
    .await;
}

fn pending_task(tenant_id: TenantId, issuer_id: IssuerId) -> OperationTask {
    let now = now_micros();
    OperationTask {
        id: TaskId::generate(),
        tenant_id,
        task_type: TaskType::CreateIssuer,
        state: TaskState::Pending,
        step: None,
        attempts: 0,
        next_attempt_at: None,
        error_code: None,
        error_message: None,
        input: json!({
            "description": "E2E test issuer",
            "display_name": "E2E",
        }),
        state_data: json!({}),
        result_issuer_id: Some(issuer_id),
        created_at: now,
        updated_at: now,
        completed_at: None,
    }
}

fn build_registry_client(server: &MockServer) -> IdentifierRegistryClient {
    IdentifierRegistryClient::with_http(server.uri(), reqwest::Client::new())
}

/// Spawn a wiremock token endpoint and build a `ProviderRegistry`
/// pointed at it. The returned `MockServer` must be kept alive for
/// the duration of the worker run; once it drops, the bound port
/// closes and any further `provider.get()` calls would fail.
async fn build_provider_setup(
    pool: &PgPool,
    engine: std::sync::Arc<swiyu_issuer::domain::AnySecretEncryptionEngine>,
) -> (
    MockServer,
    std::sync::Arc<swiyu_issuer::domain::ProviderRegistry>,
) {
    let server = common::oauth::mock_token_endpoint().await;
    let providers = common::oauth::build_provider_registry(pool.clone(), server.uri(), engine);
    (server, providers)
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
                "wait_for_task_state timed out after {:?}: target={:?}, last={:?}",
                timeout, target, task.state,
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

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
    insert_test_tenant(&pool, &tenant_id, PARTNER_ID, &engine).await;

    let issuer_id = IssuerId::generate();
    let task = pending_task(tenant_id.clone(), issuer_id.clone());
    let task_id = task.id.clone();
    let mut conn = pool.acquire().await.unwrap();
    operation_tasks::insert(&mut conn, &task).await.unwrap();
    drop(conn);

    let (_token_server, providers) =
        build_provider_setup(&pool, std::sync::Arc::clone(&engine)).await;
    let shutdown = CancellationToken::new();
    let worker = Worker::new(
        pool.clone(),
        build_registry_client(&server),
        DevSigningEngine::new(pool.clone()),
        status_registry_with_one_ok(),
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
        Duration::from_secs(10),
    )
    .await;

    shutdown.cancel();
    handle.await.unwrap();

    assert_eq!(final_task.state, TaskState::Completed);
    assert_eq!(final_task.result_issuer_id, Some(issuer_id.clone()));

    // The allocate response carried REGISTRY_UUID in the URL; verify it
    // round-tripped into state_data.
    assert_eq!(
        final_task.state_data["assigned_identifier"],
        json!(REGISTRY_UUID)
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
    insert_test_tenant(&pool, &tenant_id, PARTNER_ID, &engine).await;

    let issuer_id = IssuerId::generate();
    let task = pending_task(tenant_id.clone(), issuer_id.clone());
    let task_id = task.id.clone();
    let mut conn = pool.acquire().await.unwrap();
    operation_tasks::insert(&mut conn, &task).await.unwrap();
    drop(conn);

    let (_token_server, providers) =
        build_provider_setup(&pool, std::sync::Arc::clone(&engine)).await;
    let shutdown = CancellationToken::new();
    // ConstantRng(0) → backoff_delay returns 0ms, so the retry fires on
    // the very next poll without waiting on real exponential backoff.
    let worker = Worker::new(
        pool.clone(),
        build_registry_client(&server),
        DevSigningEngine::new(pool.clone()),
        status_registry_with_one_ok(),
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
    insert_test_tenant(&pool, &tenant_id, PARTNER_ID, &engine).await;

    // Pre-populate state_data with allocate_did's output, simulating a
    // crash that occurred after allocate_did succeeded but before
    // generate_keys.
    let issuer_id = IssuerId::generate();
    let mut task = pending_task(tenant_id.clone(), issuer_id.clone());
    task.state_data = json!({
        "assigned_did_url": registry_url_in_response(),
        "assigned_identifier": REGISTRY_UUID,
    });
    let task_id = task.id.clone();
    let mut conn = pool.acquire().await.unwrap();
    operation_tasks::insert(&mut conn, &task).await.unwrap();
    drop(conn);

    let (_token_server, providers) =
        build_provider_setup(&pool, std::sync::Arc::clone(&engine)).await;
    let shutdown = CancellationToken::new();
    let worker = Worker::new(
        pool.clone(),
        build_registry_client(&server),
        DevSigningEngine::new(pool.clone()),
        status_registry_with_one_ok(),
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
