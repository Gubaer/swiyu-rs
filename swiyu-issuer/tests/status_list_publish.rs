//! End-to-end integration tests for the status-list publish loop.
//!
//! Exercises the full saga against:
//! - a real Postgres pool (`sqlx::test`)
//! - a real `StatusRegistryClient` pointed at a wiremock server
//! - a real `DevSigningEngine` against the test pool
//!
//! Complements the in-memory mock-based tests in
//! `tests/status_list_publisher.rs`.

use swiyu_issuer::test_support::fixtures::{SAMPLE_PARTNER_ID, SAMPLE_STATUS_ENTRY_ID};
use swiyu_issuer::test_support::oauth;
use swiyu_issuer::test_support::persistence::status_lists as test_status_lists;
use swiyu_issuer::test_support::worker::ConstantRng;

use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use sqlx::PgPool;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use swiyu_core::statuslist::{StatusListJwtPayload, StatusValue};
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

fn registry_url_for(server: &MockServer) -> String {
    // The `sub` claim on the published JWT and the `uri` embedded in
    // every issued credential. Real deployments get this from the
    // `statusRegistryUrl` returned by `create_status_list_entry`.
    format!("{}/lists/{SAMPLE_STATUS_ENTRY_ID}.jwt", server.uri())
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

    let secret_engine = oauth::test_engine();
    let (issuer, list, engine) = test_status_lists::seed_dirty_environment(
        &pool,
        &secret_engine,
        &registry_url_for(&server),
    )
    .await;
    let list_id = list.id.clone();
    let target = list.committed_version;

    let (_token_server, providers) =
        oauth::build_provider_setup(&pool, Arc::clone(&secret_engine)).await;
    let mut publisher = StatusListPublisher::new(
        pool.clone(),
        engine,
        build_status_client(&server),
        providers,
        Box::new(ConstantRng(0)),
    );
    publisher.run_round(list).await.unwrap();

    let (published, _committed, attempts) =
        test_status_lists::fetch_publish_state(&pool, &list_id).await;
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

    let secret_engine = oauth::test_engine();
    let (_issuer, list, engine) = test_status_lists::seed_dirty_environment(
        &pool,
        &secret_engine,
        &registry_url_for(&server),
    )
    .await;
    let list_id = list.id.clone();
    let target = list.committed_version;

    let (_token_server, providers) =
        oauth::build_provider_setup(&pool, Arc::clone(&secret_engine)).await;
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
    let (published, _committed, attempts) =
        test_status_lists::fetch_publish_state(&pool, &list_id).await;
    assert_eq!(published, 0);
    assert_eq!(attempts, 1);

    // Round 2 — 204, success bumps published_version and resets
    // publish_attempts.
    publisher.run_round(list).await.unwrap();
    let (published, _committed, attempts) =
        test_status_lists::fetch_publish_state(&pool, &list_id).await;
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

    let secret_engine = oauth::test_engine();
    let (_issuer, list, engine) = test_status_lists::seed_dirty_environment(
        &pool,
        &secret_engine,
        &registry_url_for(&server),
    )
    .await;
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

    let (_token_server, providers) =
        oauth::build_provider_setup(&pool, Arc::clone(&secret_engine)).await;
    let mut publisher = StatusListPublisher::new(
        pool.clone(),
        engine,
        build_status_client(&server),
        providers,
        Box::new(ConstantRng(0)),
    );
    publisher.run_round(list).await.unwrap();

    let (published, _committed, _attempts) =
        test_status_lists::fetch_publish_state(&pool, &list_id).await;
    assert_eq!(
        published,
        (target as i64) + 5,
        "concurrent worker's higher published_version is preserved",
    );
}
