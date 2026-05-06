//! End-to-end integration tests for the status-list publish loop.
//!
//! Exercises the full saga against:
//! - a real Postgres pool (`sqlx::test`)
//! - a real `StatusRegistryClient` pointed at a wiremock server
//! - a real `DevSigningEngine` against the test pool
//!
//! Complements the in-memory mock-based tests in
//! `tests/status_list_publisher.rs`.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use rand_core::RngCore;
use sqlx::PgPool;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use swiyu_core::statuslist::{StatusListJwtPayload, StatusValue};
use swiyu_issuer::domain::{
    DevSigningEngine, Issuer, IssuerId, IssuerState, KeyRole, SigningEngine, StatusList,
    StatusListId, StatusListIndex, StatusValue as IssuerStatusValue, TenantId,
};
use swiyu_issuer::persistence::{self, status_lists};
use swiyu_issuer::worker::StatusListPublisher;
use swiyu_registries::common::AccessToken;
use swiyu_registries::status::StatusRegistryClient;

const PARTNER_ID: &str = "4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef";
const STATUS_ENTRY_ID: &str = "11111111-2222-3333-4444-555555555555";
const FIXTURE_DID: &str = "did:tdw:dev.example.com:test";

fn update_path() -> String {
    format!("/api/v1/status/business-entities/{PARTNER_ID}/status-list-entries/{STATUS_ENTRY_ID}")
}

fn build_status_client(server: &MockServer) -> StatusRegistryClient {
    StatusRegistryClient::with_http(
        server.uri(),
        AccessToken::new("test-token".into()),
        reqwest::Client::new(),
    )
}

fn registry_url_for(server: &MockServer) -> String {
    // The `sub` claim on the published JWT and the `uri` embedded in
    // every issued credential. Real deployments get this from the
    // `statusRegistryUrl` returned by `create_status_list_entry`.
    format!("{}/lists/{STATUS_ENTRY_ID}.jwt", server.uri())
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

async fn seeded_environment(
    pool: &PgPool,
    server: &MockServer,
) -> (Issuer, StatusList, DevSigningEngine) {
    let tenant_id = TenantId::generate();
    sqlx::query("INSERT INTO tenants (id, partner_id) VALUES ($1, $2)")
        .bind(tenant_id.bare())
        .bind(PARTNER_ID)
        .execute(pool)
        .await
        .unwrap();

    let engine = DevSigningEngine::new(pool.clone());
    let assertion = engine.generate_keypair(KeyRole::Assertion).await.unwrap();

    let issuer = Issuer {
        id: IssuerId::generate(),
        tenant_id: tenant_id.clone(),
        did: FIXTURE_DID.into(),
        state: Some(IssuerState::Active),
        description: None,
        authorized_key_id: None,
        authentication_key_id: None,
        assertion_key_id: Some(assertion.id),
        display_name: Some("Test issuer".into()),
        logo_uri: None,
        locale: None,
        created_at: Utc::now(),
    };
    let mut conn = pool.acquire().await.unwrap();
    persistence::issuers::insert(&mut conn, &issuer)
        .await
        .unwrap();
    let registry_url = registry_url_for(server);
    let list_id = status_lists::provision_for_issuer(
        &mut conn,
        &issuer.id,
        Some(STATUS_ENTRY_ID),
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

    let (issuer, list, engine) = seeded_environment(&pool, &server).await;
    let list_id = list.id.clone();
    let target = list.committed_version;

    let mut publisher = StatusListPublisher::new(
        pool.clone(),
        engine,
        build_status_client(&server),
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

    let (_issuer, list, engine) = seeded_environment(&pool, &server).await;
    let list_id = list.id.clone();
    let target = list.committed_version;

    let mut publisher = StatusListPublisher::new(
        pool.clone(),
        engine,
        build_status_client(&server),
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

    let (_issuer, list, engine) = seeded_environment(&pool, &server).await;
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

    let mut publisher = StatusListPublisher::new(
        pool.clone(),
        engine,
        build_status_client(&server),
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
