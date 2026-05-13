//! End-to-end integration tests for the status-list publish loop.
//!
//! Exercises the full saga against:
//! - a real Postgres pool (`sqlx::test`)
//! - a real `StatusRegistryClient` pointed at a wiremock server
//! - a real `DevSigningEngine` against the test pool
//!
//! Complements the in-memory mock-based tests in
//! `tests/status_list_publisher.rs`.

#[path = "common/mod.rs"]
mod common;
use common::fixtures::{SAMPLE_PARTNER_ID, SAMPLE_STATUS_ENTRY_ID};
use common::rng::ConstantRng;

use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use sqlx::PgPool;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use swiyu_core::statuslist::{StatusListJwtPayload, StatusValue};
use swiyu_issuer::domain::{
    DevSigningEngine, Issuer, KeyRole, ProviderRegistry, SigningEngine, StatusList, StatusListId,
    StatusListIndex, StatusValue as IssuerStatusValue, TenantId,
};
use swiyu_issuer::persistence::{self, status_lists};
use swiyu_issuer::worker::StatusListPublisher;
use swiyu_registries::status::StatusRegistryClient;

fn update_path() -> String {
    format!(
        "/api/v1/status/business-entities/{SAMPLE_PARTNER_ID}/status-list-entries/{SAMPLE_STATUS_ENTRY_ID}"
    )
}

fn build_status_client(server: &MockServer) -> StatusRegistryClient {
    StatusRegistryClient::with_http(server.uri(), reqwest::Client::new())
}

async fn build_provider_setup(
    pool: &PgPool,
    engine: Arc<swiyu_issuer::domain::AnySecretEncryptionEngine>,
) -> (MockServer, Arc<ProviderRegistry>) {
    let server = common::oauth::mock_token_endpoint().await;
    let providers = common::oauth::build_provider_registry(pool.clone(), server.uri(), engine);
    (server, providers)
}

fn registry_url_for(server: &MockServer) -> String {
    // The `sub` claim on the published JWT and the `uri` embedded in
    // every issued credential. Real deployments get this from the
    // `statusRegistryUrl` returned by `create_status_list_entry`.
    format!("{}/lists/{SAMPLE_STATUS_ENTRY_ID}.jwt", server.uri())
}

async fn seeded_environment(
    pool: &PgPool,
    server: &MockServer,
    secret_engine: &swiyu_issuer::domain::AnySecretEncryptionEngine,
) -> (Issuer, StatusList, DevSigningEngine) {
    let tenant_id = TenantId::generate();
    common::oauth::insert_tenant_with_oauth_secrets(
        pool,
        &tenant_id,
        SAMPLE_PARTNER_ID.parse().unwrap(),
        secret_engine,
        "test-client",
        "test-secret",
        "test-refresh",
    )
    .await;

    let engine = DevSigningEngine::new(pool.clone());
    let assertion = engine.generate_keypair(KeyRole::Assertion).await.unwrap();

    let issuer = Issuer {
        assertion_key_id: Some(assertion.id),
        ..common::issuers::active(&tenant_id)
    };
    let mut conn = pool.acquire().await.unwrap();
    persistence::issuers::insert(&mut conn, &issuer)
        .await
        .unwrap();
    let registry_url = registry_url_for(server);
    let list_id = status_lists::provision_for_issuer(
        &mut conn,
        &issuer.id,
        Some(SAMPLE_STATUS_ENTRY_ID),
        Some(&registry_url),
    )
    .await
    .unwrap();

    // Make it dirty: a single bit-flip bumps committed_version.
    status_lists::write_bit(
        &mut conn,
        &list_id,
        StatusListIndex::try_from(0u32).unwrap(),
        IssuerStatusValue::Revoked,
    )
    .await
    .unwrap();
    drop(conn);

    let mut conn = pool.acquire().await.unwrap();
    let acquired =
        status_lists::acquire_next_dirty(&mut conn, Utc::now(), chrono::Duration::seconds(30))
            .await
            .unwrap()
            .expect("dirty list is acquirable");
    drop(conn);

    (issuer, acquired, engine)
}

async fn fetch_publish_state(pool: &PgPool, list_id: &StatusListId) -> (i64, i32) {
    sqlx::query_as::<_, (i64, i32)>(
        "SELECT published_version, publish_attempts FROM status_lists WHERE id = $1",
    )
    .bind(list_id.bare())
    .fetch_one(pool)
    .await
    .unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn happy_path_publishes_and_advances_published_version(pool: PgPool) {
    let server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path(update_path()))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let secret_engine = common::oauth::test_engine();
    let (issuer, list, engine) = seeded_environment(&pool, &server, &secret_engine).await;
    let list_id = list.id.clone();
    let target = list.committed_version;

    let (_token_server, providers) = build_provider_setup(&pool, Arc::clone(&secret_engine)).await;
    let mut publisher = StatusListPublisher::new(
        pool.clone(),
        engine,
        build_status_client(&server),
        providers,
        Box::new(ConstantRng(0)),
    );
    publisher.run_round(list).await.unwrap();

    let (published, attempts) = fetch_publish_state(&pool, &list_id).await;
    assert_eq!(published as u64, target);
    assert_eq!(attempts, 0);

    // Inspect the JWT body the registry received.
    let put = server
        .received_requests()
        .await
        .expect("request recording enabled")
        .into_iter()
        .find(|r| r.method == wiremock::http::Method::PUT && r.url.path() == update_path())
        .expect("registry received the PUT");
    let jwt = std::str::from_utf8(&put.body).expect("utf8 body");
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3);
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
    let payload_value: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
    let payload = StatusListJwtPayload::try_from(&payload_value).unwrap();

    assert_eq!(payload.iss(), issuer.did);
    assert_eq!(payload.sub(), registry_url_for(&server));
    // iat is captured at run_round time, must be within a small window
    // of "now".
    let now = Utc::now().timestamp() as u64;
    assert!(payload.iat() <= now);
    assert!(payload.iat() >= now.saturating_sub(60));
    // The slot we flipped — index 0 — reads as Revoked through the JWT.
    assert_eq!(
        payload.list().value_at(0).unwrap(),
        StatusValue::Revoked,
        "the JWT carries the bit-flip the publisher snapshotted",
    );
    // Untouched slots remain Valid.
    assert_eq!(payload.list().value_at(1).unwrap(), StatusValue::Valid,);
}

#[sqlx::test(migrations = "./migrations")]
async fn registry_503_then_success_resets_publish_attempts(pool: PgPool) {
    let server = MockServer::start().await;

    // First call → 503 (retryable).
    Mock::given(method("PUT"))
        .and(path(update_path()))
        .respond_with(ResponseTemplate::new(503).set_body_string("service unavailable"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    // Subsequent calls → 204 (success).
    Mock::given(method("PUT"))
        .and(path(update_path()))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let secret_engine = common::oauth::test_engine();
    let (_issuer, list, engine) = seeded_environment(&pool, &server, &secret_engine).await;
    let list_id = list.id.clone();
    let target = list.committed_version;

    let (_token_server, providers) = build_provider_setup(&pool, Arc::clone(&secret_engine)).await;
    let mut publisher = StatusListPublisher::new(
        pool.clone(),
        engine,
        build_status_client(&server),
        providers,
        Box::new(ConstantRng(0)),
    );

    // Round 1 — 503, retry recorded.
    let err = publisher.run_round(list.clone()).await.unwrap_err();
    assert!(format!("{err}").contains("503"));
    let (published, attempts) = fetch_publish_state(&pool, &list_id).await;
    assert_eq!(published, 0);
    assert_eq!(attempts, 1);

    // Round 2 — 204, success bumps published_version and resets
    // publish_attempts.
    publisher.run_round(list).await.unwrap();
    let (published, attempts) = fetch_publish_state(&pool, &list_id).await;
    assert_eq!(published as u64, target);
    assert_eq!(attempts, 0);

    // The PUT endpoint was hit at least twice (one 503 + one 204).
    let publish_hits = server
        .received_requests()
        .await
        .expect("request recording enabled")
        .iter()
        .filter(|r| r.method == wiremock::http::Method::PUT && r.url.path() == update_path())
        .count();
    assert!(
        publish_hits >= 2,
        "expected >= 2 publish attempts, got {publish_hits}",
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_advance_makes_local_update_a_noop(pool: PgPool) {
    let server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path(update_path()))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let secret_engine = common::oauth::test_engine();
    let (_issuer, list, engine) = seeded_environment(&pool, &server, &secret_engine).await;
    let list_id = list.id.clone();
    let target = list.committed_version;

    // Pre-stamp published_version past the target; a concurrent worker
    // would have done this. Our run still PUTs to the registry (idempotent
    // server side) but the local conditional UPDATE rejects.
    sqlx::query("UPDATE status_lists SET published_version = $1 WHERE id = $2")
        .bind((target as i64) + 5)
        .bind(list_id.bare())
        .execute(&pool)
        .await
        .unwrap();

    let (_token_server, providers) = build_provider_setup(&pool, Arc::clone(&secret_engine)).await;
    let mut publisher = StatusListPublisher::new(
        pool.clone(),
        engine,
        build_status_client(&server),
        providers,
        Box::new(ConstantRng(0)),
    );
    publisher.run_round(list).await.unwrap();

    let (published, _attempts) = fetch_publish_state(&pool, &list_id).await;
    assert_eq!(
        published,
        (target as i64) + 5,
        "concurrent worker's higher published_version is preserved",
    );
}
