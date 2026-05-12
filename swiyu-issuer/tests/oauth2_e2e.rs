//! End-to-end OAuth2 integration test.
//!
//! Mocks two HTTP boundaries with `wiremock` — the OAuth2 token
//! endpoint and the SWIYU identifier registry — and exercises one
//! full `CreateIssuer` saga round through `Worker`. Everything else
//! (the worker's persistence, the saga executors, the with_refreshed
//! retry helper, the per-tenant `OAuth2TokenProvider`) runs for real.
//!
//! Scenarios:
//! - cold-start grant → bearer-on-registry-call → refresh-token rotation
//!   lands in the DB
//! - 401 from the identifier registry triggers exactly one
//!   invalidate-driven retry; second registry call succeeds

#[path = "common/mod.rs"]
mod common;

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Timelike, Utc};
use rand_core::RngCore;
use serde_json::json;
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use swiyu_issuer::domain::{
    DevSigningEngine, IssuerId, OperationTask, ProviderRegistry, TaskId, TaskState, TaskType,
    TenantId,
};
use swiyu_issuer::persistence::operation_tasks;
use swiyu_issuer::worker::Worker;
use swiyu_issuer::worker::test_support::{CreateStatusListEntryCall, MockStatusRegistry};
use swiyu_registries::identifier::IdentifierRegistryClient;
use swiyu_registries::status::StatusListEntry;

const PARTNER_ID: &str = "4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef";
const REGISTRY_UUID: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const STATUS_ENTRY_ID: &str = "11111111-2222-3333-4444-555555555555";
const STATUS_REGISTRY_URL: &str = "https://status-reg.test/lists/abc.jwt";

fn allocate_path() -> String {
    format!("/api/v1/identifier/business-entities/{PARTNER_ID}/identifier-entries")
}

fn publish_path() -> String {
    format!("/api/v1/identifier/business-entities/{PARTNER_ID}/identifier-entries/{REGISTRY_UUID}")
}

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

async fn insert_tenant_with_oauth(
    pool: &PgPool,
    tenant_id: &TenantId,
    engine: &swiyu_issuer::domain::AnySecretEncryptionEngine,
) {
    common::oauth::insert_tenant_with_oauth_secrets(
        pool,
        tenant_id,
        PARTNER_ID.parse().unwrap(),
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
            "description": "OAuth2 e2e test issuer",
            "display_name": "OAuth2-E2E",
        }),
        state_data: json!({}),
        result_issuer_id: Some(issuer_id),
        created_at: now,
        updated_at: now,
        completed_at: None,
    }
}

fn status_registry_with_one_ok() -> MockStatusRegistry {
    let r = MockStatusRegistry::new();
    r.enqueue_create(CreateStatusListEntryCall::Ok(StatusListEntry {
        id: STATUS_ENTRY_ID.into(),
        registry_url: STATUS_REGISTRY_URL.into(),
    }));
    r
}

fn build_registry_client(server: &MockServer) -> IdentifierRegistryClient {
    IdentifierRegistryClient::with_http(server.uri(), reqwest::Client::new())
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

fn build_worker(
    pool: PgPool,
    registry_server: &MockServer,
    providers: Arc<ProviderRegistry>,
) -> Worker<IdentifierRegistryClient, DevSigningEngine, MockStatusRegistry> {
    Worker::new(
        pool.clone(),
        build_registry_client(registry_server),
        DevSigningEngine::new(pool),
        status_registry_with_one_ok(),
        providers,
        Box::new(ConstantRng(0)),
    )
    .with_poll_interval(Duration::from_millis(20))
}

#[sqlx::test(migrations = "./migrations")]
async fn cold_start_grants_token_calls_registry_with_bearer_and_rotates_refresh(pool: PgPool) {
    let token_server = common::oauth::mock_token_endpoint().await;
    let secret_engine = common::oauth::test_engine();
    let providers = common::oauth::build_provider_registry(
        pool.clone(),
        token_server.uri(),
        Arc::clone(&secret_engine),
    );

    let registry_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(allocate_path()))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "identifierRegistryUrl": registry_url_in_response() })),
        )
        .expect(1)
        .mount(&registry_server)
        .await;
    Mock::given(method("PUT"))
        .and(path(publish_path()))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&registry_server)
        .await;

    let tenant_id = TenantId::generate();
    insert_tenant_with_oauth(&pool, &tenant_id, &secret_engine).await;

    let issuer_id = IssuerId::generate();
    let task = pending_task(tenant_id.clone(), issuer_id.clone());
    let task_id = task.id.clone();
    let mut conn = pool.acquire().await.unwrap();
    operation_tasks::insert(&mut conn, &task).await.unwrap();
    drop(conn);

    let shutdown = CancellationToken::new();
    let worker = build_worker(pool.clone(), &registry_server, providers);
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

    // The wiremock token stub returned `rotated-refresh`; the
    // OAuth2TokenProvider should have written it back to the row.
    assert_eq!(
        common::oauth::read_refresh_token(&pool, &tenant_id, &secret_engine)
            .await
            .as_deref(),
        Some("rotated-refresh"),
        "refresh token was not rotated in the DB",
    );

    // The allocate POST should have carried the access token from
    // the token endpoint as a bearer header.
    let allocate_request = registry_server
        .received_requests()
        .await
        .expect("request recording enabled")
        .into_iter()
        .find(|req| req.method == wiremock::http::Method::POST && req.url.path() == allocate_path())
        .expect("allocate POST was made");
    let auth = allocate_request
        .headers
        .get("authorization")
        .expect("Authorization header present")
        .to_str()
        .unwrap();
    assert_eq!(auth, "Bearer test-access");
}

#[sqlx::test(migrations = "./migrations")]
async fn registry_401_triggers_invalidate_and_retry(pool: PgPool) {
    let token_server = common::oauth::mock_token_endpoint().await;
    let secret_engine = common::oauth::test_engine();
    let providers = common::oauth::build_provider_registry(
        pool.clone(),
        token_server.uri(),
        Arc::clone(&secret_engine),
    );

    let registry_server = MockServer::start().await;
    // First allocate POST: 401 — simulates a stale access token at
    // the registry boundary. wiremock matches in registration order,
    // so this serves the first request and `up_to_n_times(1)` then
    // exhausts; the always-200 stub below takes over from the second
    // request onward.
    Mock::given(method("POST"))
        .and(path(allocate_path()))
        .respond_with(ResponseTemplate::new(401).set_body_string("unauthorized"))
        .up_to_n_times(1)
        .mount(&registry_server)
        .await;
    Mock::given(method("POST"))
        .and(path(allocate_path()))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "identifierRegistryUrl": registry_url_in_response() })),
        )
        .mount(&registry_server)
        .await;
    Mock::given(method("PUT"))
        .and(path(publish_path()))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&registry_server)
        .await;

    let tenant_id = TenantId::generate();
    insert_tenant_with_oauth(&pool, &tenant_id, &secret_engine).await;

    let issuer_id = IssuerId::generate();
    let task = pending_task(tenant_id.clone(), issuer_id.clone());
    let task_id = task.id.clone();
    let mut conn = pool.acquire().await.unwrap();
    operation_tasks::insert(&mut conn, &task).await.unwrap();
    drop(conn);

    let shutdown = CancellationToken::new();
    let worker = build_worker(pool.clone(), &registry_server, providers);
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

    let received = registry_server
        .received_requests()
        .await
        .expect("request recording enabled");
    let allocate_hits = received
        .iter()
        .filter(|req| {
            req.method == wiremock::http::Method::POST && req.url.path() == allocate_path()
        })
        .count();
    assert_eq!(
        allocate_hits, 2,
        "401 should trigger exactly one retry, leaving 2 allocate calls",
    );

    // The token endpoint should have served two grants: the initial
    // cold-start, and the post-invalidate refresh after the 401.
    let token_hits = token_server
        .received_requests()
        .await
        .expect("request recording enabled")
        .len();
    assert_eq!(
        token_hits, 2,
        "expected one initial grant + one invalidate-driven re-grant",
    );
}
