//! Integration tests for `worker::create_issuer::execute_persist_issuer`.
//!
//! Runs against a freshly created Postgres database via `sqlx::test`;
//! migrations apply automatically. Requires `DATABASE_URL` to point
//! to a Postgres instance whose user has `CREATEDB` privilege.

use sqlx::PgPool;

use swiyu_issuer::domain::{Issuer, IssuerId, IssuerState, StepOutcome, TenantId};
use swiyu_issuer::persistence::issuers;
use swiyu_issuer::test_support::domain::signing_engine::{GetPublicKeyCall, MockSigningEngine};
use swiyu_issuer::test_support::fixtures::{SAMPLE_DESCRIPTION, SAMPLE_DISPLAY_NAME};
use swiyu_issuer::test_support::persistence::issuers as test_issuers;
use swiyu_issuer::test_support::worker::create_issuer::fixture_state;
use swiyu_issuer::worker::create_issuer::{
    CreateIssuerInput, CreateIssuerStateData, execute_persist_issuer,
};

fn fixture_input() -> CreateIssuerInput {
    CreateIssuerInput {
        description: SAMPLE_DESCRIPTION.into(),
        display_name: SAMPLE_DISPLAY_NAME.into(),
    }
}

use swiyu_issuer::test_support::fixture_kid;
use swiyu_issuer::test_support::fixture_now;
use swiyu_issuer::test_support::persistence::tenants::insert_test_tenant;

#[sqlx::test(migrations = "./migrations")]
async fn happy_path_inserts_issuer_row(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer_id = IssuerId::generate();
    let engine = MockSigningEngine::for_happy_path();

    let outcome = execute_persist_issuer(
        &pool,
        &tenant_id,
        &issuer_id,
        &fixture_input(),
        &fixture_state(true),
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
    assert_eq!(loaded.description.as_deref(), Some(SAMPLE_DESCRIPTION));
    assert_eq!(loaded.display_name.as_deref(), Some(SAMPLE_DISPLAY_NAME));
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
        did: "did:tdw:Qm-pre-existing:reg.example.com:api:v1:did:abc".into(),
        description: Some("pre-existing".into()),
        authorized_key_id: Some(fixture_kid(0x11)),
        authentication_key_id: Some(fixture_kid(0x22)),
        assertion_key_id: Some(fixture_kid(0x33)),
        display_name: Some("pre-existing".into()),
        ..test_issuers::active(&tenant_id)
    };
    issuers::insert(&mut conn, &existing).await.unwrap();

    // Engine deliberately empty — the executor must not call it on the skip path.
    let engine = MockSigningEngine::new();

    let outcome = execute_persist_issuer(
        &pool,
        &tenant_id,
        &issuer_id,
        &fixture_input(),
        &fixture_state(true),
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
        ..fixture_state(true)
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
        ..fixture_state(true)
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
        &fixture_state(true),
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
