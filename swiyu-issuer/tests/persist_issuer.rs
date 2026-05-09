//! Integration tests for `worker::create_issuer::execute_persist_issuer`.
//!
//! Runs against a freshly created Postgres database via `sqlx::test`;
//! migrations apply automatically. Requires `DATABASE_URL` to point
//! to a Postgres instance whose user has `CREATEDB` privilege.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use swiyu_issuer::domain::signing_engine::test_support::{
    GetPublicKeyCall, MockSigningEngine, SignCall,
};
use swiyu_issuer::domain::{
    Issuer, IssuerId, IssuerState, KeyAlgorithm, KeyPairId, RawPublicKey, Signature, StepOutcome,
    TenantId,
};
use swiyu_issuer::persistence::issuers;
use swiyu_issuer::worker::create_issuer::{
    CreateIssuerInput, CreateIssuerStateData, KeyTriple, execute_persist_issuer,
};

fn fixture_kid(byte: u8) -> KeyPairId {
    let mut bytes = [byte; 16];
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    KeyPairId::from(Uuid::from_bytes(bytes))
}

fn fixture_input() -> CreateIssuerInput {
    CreateIssuerInput {
        description: "Cantonal driver-licence issuer".into(),
        display_name: "Canton Bern Verkehrsamt".into(),
    }
}

fn fixture_state() -> CreateIssuerStateData {
    CreateIssuerStateData {
        assigned_did_url: Some("https://reg.example.com/api/v1/did/abc/did.jsonl".into()),
        assigned_identifier: Some("abc".into()),
        key_ids: Some(KeyTriple {
            authorized: fixture_kid(0x11),
            authentication: fixture_kid(0x22),
            assertion: fixture_kid(0x33),
        }),
        didlog_published: true,
        status_list_registry_entry_id: None,
        status_list_registry_url: None,
    }
}

fn fixture_now() -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(1_768_982_400, 0).unwrap()
}

fn fixture_ed25519_pk() -> RawPublicKey {
    RawPublicKey {
        algorithm: KeyAlgorithm::Ed25519,
        bytes: vec![0xab; 32],
    }
}

fn fixture_p256_pk() -> RawPublicKey {
    let mut bytes = vec![0x04];
    bytes.extend_from_slice(&[0xcd; 32]);
    bytes.extend_from_slice(&[0xef; 32]);
    RawPublicKey {
        algorithm: KeyAlgorithm::EcdsaP256,
        bytes,
    }
}

fn fixture_signature() -> Signature {
    Signature {
        algorithm: KeyAlgorithm::Ed25519,
        bytes: vec![0x42; 64],
    }
}

fn engine_for_happy_path() -> MockSigningEngine {
    let engine = MockSigningEngine::new();
    engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_ed25519_pk()));
    engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_p256_pk()));
    engine.enqueue_public_key(GetPublicKeyCall::Ok(fixture_p256_pk()));
    engine.enqueue_sign(SignCall::Ok(fixture_signature()));
    engine
}

async fn insert_test_tenant(pool: &PgPool, tenant_id: &TenantId) {
    sqlx::query("INSERT INTO tenants (id, partner_id) VALUES ($1, NULL)")
        .bind(tenant_id.bare())
        .execute(pool)
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn happy_path_inserts_issuer_row(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer_id = IssuerId::generate();
    let engine = engine_for_happy_path();

    let outcome = execute_persist_issuer(
        &pool,
        &tenant_id,
        &issuer_id,
        &fixture_input(),
        &fixture_state(),
        &engine,
        fixture_now(),
    )
    .await;

    match outcome {
        StepOutcome::Done(result) => assert!(result.state_data_patch.is_empty()),
        other => panic!("expected Done, got {other:?}"),
    }

    let mut conn = pool.acquire().await.unwrap();
    let loaded = issuers::find_by_id(&mut conn, &issuer_id)
        .await
        .unwrap()
        .expect("issuer row written");
    assert_eq!(loaded.id, issuer_id);
    assert_eq!(loaded.tenant_id, tenant_id);
    assert!(loaded.did.starts_with("did:tdw:"));
    assert_eq!(loaded.state, Some(IssuerState::Active));
    assert_eq!(
        loaded.description.as_deref(),
        Some("Cantonal driver-licence issuer")
    );
    assert_eq!(
        loaded.display_name.as_deref(),
        Some("Canton Bern Verkehrsamt")
    );
    assert_eq!(loaded.authorized_key_id, Some(fixture_kid(0x11)));
    assert_eq!(loaded.authentication_key_id, Some(fixture_kid(0x22)));
    assert_eq!(loaded.assertion_key_id, Some(fixture_kid(0x33)));
}

#[sqlx::test(migrations = "./migrations")]
async fn skips_when_issuer_row_already_exists(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer_id = IssuerId::generate();

    // Pre-insert a matching issuer row to simulate a successful previous
    // run that crashed before advancing past persist_issuer.
    let mut conn = pool.acquire().await.unwrap();
    let existing = Issuer {
        id: issuer_id.clone(),
        tenant_id: tenant_id.clone(),
        did: "did:tdw:Qm-pre-existing:reg.example.com:api:v1:did:abc".into(),
        state: Some(IssuerState::Active),
        description: Some("pre-existing".into()),
        authorized_key_id: Some(fixture_kid(0x11)),
        authentication_key_id: Some(fixture_kid(0x22)),
        assertion_key_id: Some(fixture_kid(0x33)),
        display_name: Some("pre-existing".into()),
        logo_uri: None,
        locale: None,
        created_at: Utc::now(),
    };
    issuers::insert(&mut conn, &existing).await.unwrap();

    // Engine deliberately empty — the executor must not call it on the skip path.
    let engine = MockSigningEngine::new();

    let outcome = execute_persist_issuer(
        &pool,
        &tenant_id,
        &issuer_id,
        &fixture_input(),
        &fixture_state(),
        &engine,
        fixture_now(),
    )
    .await;

    match outcome {
        StepOutcome::Done(result) => assert!(result.state_data_patch.is_empty()),
        other => panic!("expected Done, got {other:?}"),
    }
    assert!(engine.public_key_invocations.lock().unwrap().is_empty());

    // The pre-existing description remains; we did not overwrite it.
    let loaded = issuers::find_by_id(&mut conn, &issuer_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.description.as_deref(), Some("pre-existing"));
}

#[sqlx::test(migrations = "./migrations")]
async fn missing_key_ids_is_terminal(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer_id = IssuerId::generate();
    let engine = MockSigningEngine::new();
    let state = CreateIssuerStateData {
        key_ids: None,
        ..fixture_state()
    };

    let outcome = execute_persist_issuer(
        &pool,
        &tenant_id,
        &issuer_id,
        &fixture_input(),
        &state,
        &engine,
        fixture_now(),
    )
    .await;

    match outcome {
        StepOutcome::Terminal { error_code, .. } => {
            assert_eq!(error_code, "missing_state");
        }
        other => panic!("expected Terminal, got {other:?}"),
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn invalid_url_is_terminal(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer_id = IssuerId::generate();
    let engine = MockSigningEngine::new();
    let state = CreateIssuerStateData {
        assigned_did_url: Some("ftp://bad.example/did.jsonl".into()),
        ..fixture_state()
    };

    let outcome = execute_persist_issuer(
        &pool,
        &tenant_id,
        &issuer_id,
        &fixture_input(),
        &state,
        &engine,
        fixture_now(),
    )
    .await;

    match outcome {
        StepOutcome::Terminal { error_code, .. } => {
            assert_eq!(error_code, "invalid_allocation_url");
        }
        other => panic!("expected Terminal, got {other:?}"),
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn engine_backend_error_is_retryable(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer_id = IssuerId::generate();
    let engine = MockSigningEngine::new();
    engine.enqueue_public_key(GetPublicKeyCall::Backend("connection refused".into()));

    let outcome = execute_persist_issuer(
        &pool,
        &tenant_id,
        &issuer_id,
        &fixture_input(),
        &fixture_state(),
        &engine,
        fixture_now(),
    )
    .await;

    match outcome {
        StepOutcome::Retry { error_code, .. } => {
            assert_eq!(error_code, "persist_issuer_failed");
        }
        other => panic!("expected Retry, got {other:?}"),
    }

    // Idempotency: no row was written.
    let mut conn = pool.acquire().await.unwrap();
    let loaded = issuers::find_by_id(&mut conn, &issuer_id).await.unwrap();
    assert!(loaded.is_none());
}
