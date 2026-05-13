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
use common::identifier_registry::{allocate_path, publish_path, registry_url_in_response};
use common::rng::ConstantRng;
use common::time::now_micros;

use std::sync::Arc;
use std::time::Duration;

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
use swiyu_issuer::worker::test_support::MockStatusRegistry;
use swiyu_registries::identifier::IdentifierRegistryClient;

fn pending_task(tenant_id: &TenantId, issuer_id: IssuerId) -> OperationTask {
    let now = now_micros();
    OperationTask {
        input: json!({
            "description": "OAuth2 e2e test issuer",
            "display_name": "OAuth2-E2E",
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
        common::identifier_registry::build_client(registry_server),
        DevSigningEngine::new(pool),
        common::status_registry::with_one_ok(),
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
    common::oauth::insert_test_tenant_with_oauth(&pool, &tenant_id, &secret_engine).await;

    let issuer_id = IssuerId::generate();
    let task = pending_task(&tenant_id, issuer_id.clone());
    let task_id = task.id.clone();
    common::operation_tasks::insert(&pool, &task).await;

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
    common::oauth::insert_test_tenant_with_oauth(&pool, &tenant_id, &secret_engine).await;

    let issuer_id = IssuerId::generate();
    let task = pending_task(&tenant_id, issuer_id.clone());
    let task_id = task.id.clone();
    common::operation_tasks::insert(&pool, &task).await;

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
