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
use common::time::now_micros;

use std::sync::Arc;
use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use rand_core::RngCore;
use serde_json::{Value, json};
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;
use wiremock::MockServer;

use swiyu_core::didlog::DIDLogEntry;
use swiyu_issuer::domain::{
    CredentialOffer, CredentialOfferState, DevSigningEngine, Issuer, IssuerId, IssuerState,
    KeyRole, OperationTask, PreAuthCode, ProviderRegistry, SigningEngine, TaskId, TaskState,
    TaskType, TenantId,
};
use swiyu_issuer::persistence::{credential_offers, issuers, operation_tasks};
use swiyu_issuer::worker::Worker;
use swiyu_issuer::worker::test_support::{
    FetchLogCall, MockRegistry, MockStatusRegistry, PublishCall,
};

const PARTNER_ID: &str = "4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef";
const REGISTRY_UUID: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const FIXTURE_SCID: &str = "Qm-fixture-scid";

fn fixture_did() -> String {
    format!("did:tdw:{FIXTURE_SCID}:reg.test:{REGISTRY_UUID}")
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
        partner_id
            .parse()
            .expect("test partner_id must be a valid UUID"),
        engine,
        "test-client",
        "test-secret",
        "test-refresh",
    )
    .await;
}

async fn build_provider_setup(
    pool: &PgPool,
    engine: Arc<swiyu_issuer::domain::AnySecretEncryptionEngine>,
) -> (MockServer, Arc<ProviderRegistry>) {
    let server = common::oauth::mock_token_endpoint().await;
    let providers = common::oauth::build_provider_registry(pool.clone(), server.uri(), engine);
    (server, providers)
}

/// Builds a minimal but parseable did:tdw 0.3 genesis entry for
/// `fixture_did()`. The `build_deactivation_entry` step only reads
/// `version_id`, `parameters.deactivated` (must not be true), and
/// the embedded DID document (which must parse via
/// `DIDDoc::try_from_jsonld`), so signature bytes and parameter
/// fields beyond those are not required.
fn fixture_genesis_entry() -> DIDLogEntry {
    let value: Value = json!([
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
    DIDLogEntry::try_from(&value).expect("fixture genesis parses")
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
        did: fixture_did(),
        authorized_key_id: Some(authorized.id),
        authentication_key_id: Some(authentication.id),
        assertion_key_id: Some(assertion.id),
        created_at: now_micros(),
        ..common::issuers::active(tenant_id)
    };
    let id = issuer.id.clone();
    common::issuers::insert(pool, &issuer).await;
    (id, engine)
}

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
    let now = now_micros();
    OperationTask {
        result_issuer_id: Some(issuer_id),
        created_at: now,
        updated_at: now,
        ..common::operation_tasks::pending(tenant_id, TaskType::DeactivateIssuer)
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

#[sqlx::test(migrations = "./migrations")]
async fn happy_path_deactivates_issuer_and_cancels_pending_offers(pool: PgPool) {
    let registry = Arc::new(MockRegistry::new());
    // Two fetch_log calls: one in build_deactivation_didlog, one in
    // publish_didlog.
    registry.enqueue_fetch_log(FetchLogCall::Ok(vec![fixture_genesis_entry()]));
    registry.enqueue_fetch_log(FetchLogCall::Ok(vec![fixture_genesis_entry()]));
    // One publish_log_entry call from publish_didlog.
    registry.enqueue_publish(PublishCall::Ok);

    let secret_engine = common::oauth::test_engine();
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id, PARTNER_ID, &secret_engine).await;
    let (issuer_id, engine) = insert_active_issuer(&pool, &tenant_id).await;

    let pending_a = insert_pending_offer(&pool, &tenant_id, &issuer_id).await;
    let pending_b = insert_pending_offer(&pool, &tenant_id, &issuer_id).await;
    let issued = insert_issued_offer(&pool, &tenant_id, &issuer_id).await;

    let task = deactivate_task(&tenant_id, issuer_id.clone());
    let task_id = task.id.clone();
    common::operation_tasks::insert(&pool, &task).await;

    let (_token_server, providers) = build_provider_setup(&pool, Arc::clone(&secret_engine)).await;
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
    assert_eq!(partner, PARTNER_ID);
    assert_eq!(identifier, REGISTRY_UUID);
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
