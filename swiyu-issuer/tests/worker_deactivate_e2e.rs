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

use std::time::Duration;

use chrono::{DateTime, Duration as ChronoDuration, Timelike, Utc};
use rand_core::RngCore;
use serde_json::{Value, json};
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use swiyu_issuer::domain::{
    CredentialOffer, CredentialOfferState, DevSigningEngine, Issuer, IssuerId, IssuerState,
    KeyRole, OperationTask, PreAuthCode, SigningEngine, TaskId, TaskState, TaskType, TenantId,
};
use swiyu_issuer::persistence::{credential_offers, issuers, operation_tasks};
use swiyu_issuer::worker::Worker;
use swiyu_registries::common::AccessToken;
use swiyu_registries::identifier::IdentifierRegistryClient;

const PARTNER_ID: &str = "4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef";
const REGISTRY_UUID: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const FIXTURE_SCID: &str = "Qm-fixture-scid";

fn fixture_did() -> String {
    format!("did:tdw:reg.test:{REGISTRY_UUID}:{FIXTURE_SCID}")
}

fn fetch_log_path() -> String {
    format!("/api/v1/did/{REGISTRY_UUID}/did.jsonl")
}

fn publish_path() -> String {
    format!("/api/v1/identifier/business-entities/{PARTNER_ID}/identifier-entries/{REGISTRY_UUID}")
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

async fn insert_test_tenant(pool: &PgPool, tenant_id: &TenantId, partner_id: &str) {
    sqlx::query("INSERT INTO tenants (id, partner_id) VALUES ($1, $2)")
        .bind(tenant_id.bare())
        .bind(partner_id)
        .execute(pool)
        .await
        .unwrap();
}

/// Builds a minimal but parseable did:tdw 0.3 genesis entry for
/// `fixture_did()`. The `build_deactivation_entry` step only reads
/// `version_id`, `parameters.deactivated` (must not be true), and
/// the embedded DID document (which must parse via
/// `DIDDoc::try_from_jsonld`), so signature bytes and parameter
/// fields beyond those are not required.
fn fixture_genesis_jsonl() -> String {
    let entry: Value = json!([
        "1-Qmfixture-genesis-version-id",
        "2026-04-01T00:00:00Z",
        {
            "method": "did:tdw:0.3",
            "scid": FIXTURE_SCID,
            "updateKeys": ["z6Mk-fixture-authorized"],
            "portable": false,
        },
        {
            "value": {
                "@context": [
                    "https://www.w3.org/ns/did/v1",
                ],
                "id": fixture_did(),
            }
        },
        [],
    ]);
    let mut line = serde_json::to_string(&entry).unwrap();
    line.push('\n');
    line
}

async fn insert_active_issuer(pool: &PgPool, tenant_id: &TenantId) -> (IssuerId, DevSigningEngine) {
    let engine = DevSigningEngine::new(pool.clone());
    let authorized = engine.generate_keypair(KeyRole::Authorized).await.unwrap();
    let authentication = engine
        .generate_keypair(KeyRole::Authentication)
        .await
        .unwrap();
    let assertion = engine.generate_keypair(KeyRole::Assertion).await.unwrap();

    let issuer = Issuer {
        id: IssuerId::generate(),
        tenant_id: tenant_id.clone(),
        did: fixture_did(),
        state: Some(IssuerState::Active),
        description: Some("e2e fixture".into()),
        authorized_key_id: Some(authorized.id),
        authentication_key_id: Some(authentication.id),
        assertion_key_id: Some(assertion.id),
        signing_key_id: None,
        display_name: Some("E2E fixture".into()),
        logo_uri: None,
        locale: None,
        created_at: now_micros(),
    };
    let id = issuer.id.clone();
    let mut conn = pool.acquire().await.unwrap();
    issuers::insert(&mut conn, &issuer).await.unwrap();
    (id, engine)
}

async fn insert_pending_offer(
    pool: &PgPool,
    tenant_id: &TenantId,
    issuer_id: &IssuerId,
) -> CredentialOffer {
    let offer = CredentialOffer::new(
        tenant_id.clone(),
        issuer_id.clone(),
        "https://example.com/vct/test".into(),
        json!({"first_name": "Anna"}),
        PreAuthCode::generate(),
        Utc::now() + ChronoDuration::hours(1),
    );
    let mut conn = pool.acquire().await.unwrap();
    credential_offers::insert(&mut conn, &offer).await.unwrap();
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
    let mut conn = pool.acquire().await.unwrap();
    credential_offers::insert(&mut conn, &offer).await.unwrap();
    offer
}

fn deactivate_task(tenant_id: TenantId, issuer_id: IssuerId) -> OperationTask {
    let now = now_micros();
    OperationTask {
        id: TaskId::generate(),
        tenant_id,
        task_type: TaskType::DeactivateIssuer,
        state: TaskState::Pending,
        step: None,
        attempts: 0,
        next_attempt_at: None,
        error_code: None,
        error_message: None,
        input: json!({}),
        state_data: json!({}),
        result_issuer_id: Some(issuer_id),
        created_at: now,
        updated_at: now,
        completed_at: None,
    }
}

fn build_registry_client(server: &MockServer) -> IdentifierRegistryClient {
    IdentifierRegistryClient::with_http(
        server.uri(),
        AccessToken::new("test-token".into()),
        reqwest::Client::new(),
    )
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
async fn happy_path_deactivates_issuer_and_cancels_pending_offers(pool: PgPool) {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(fetch_log_path()))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture_genesis_jsonl()))
        // Two GETs: one in build_deactivation_log, one in publish_log.
        .expect(2)
        .mount(&server)
        .await;

    Mock::given(method("PUT"))
        .and(path(publish_path()))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id, PARTNER_ID).await;
    let (issuer_id, engine) = insert_active_issuer(&pool, &tenant_id).await;

    let pending_a = insert_pending_offer(&pool, &tenant_id, &issuer_id).await;
    let pending_b = insert_pending_offer(&pool, &tenant_id, &issuer_id).await;
    let issued = insert_issued_offer(&pool, &tenant_id, &issuer_id).await;

    let task = deactivate_task(tenant_id.clone(), issuer_id.clone());
    let task_id = task.id.clone();
    let mut conn = pool.acquire().await.unwrap();
    operation_tasks::insert(&mut conn, &task).await.unwrap();
    drop(conn);

    let shutdown = CancellationToken::new();
    let worker = Worker::new(
        pool.clone(),
        build_registry_client(&server),
        engine,
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
    assert_eq!(final_task.state_data["log_published"], json!(true));

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

    // Registry got the deactivation PUT, body parses as a 5-element
    // array whose parameters block carries `deactivated: true`.
    let put_requests: Vec<_> = server
        .received_requests()
        .await
        .expect("request recording enabled")
        .into_iter()
        .filter(|req| req.method == wiremock::http::Method::PUT && req.url.path() == publish_path())
        .collect();
    assert_eq!(put_requests.len(), 1, "expected exactly one PUT");
    let body: Value = serde_json::from_slice(&put_requests[0].body).unwrap();
    let arr = body.as_array().expect("entry is a JSON array");
    assert_eq!(arr.len(), 5, "did:tdw 0.3 entries are 5-element arrays");
    assert_eq!(arr[2]["deactivated"], json!(true));
    assert_eq!(arr[2]["updateKeys"], json!([]));
}
