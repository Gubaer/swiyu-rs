//! Integration tests for
//! `worker::create_issuer::execute_provision_status_list`.
//!
//! Runs against a freshly created Postgres database via `sqlx::test`;
//! migrations apply automatically. Requires `DATABASE_URL` to point to
//! a Postgres instance whose user has `CREATEDB` privilege.

use sqlx::PgPool;

use swiyu_issuer::domain::{IssuerId, StepOutcome, TenantId};
use swiyu_issuer::persistence;
use swiyu_issuer::worker::create_issuer::{CreateIssuerStateData, execute_provision_status_list};

#[path = "common/mod.rs"]
mod common;
use common::fixtures::{SAMPLE_STATUS_ENTRY_ID, SAMPLE_STATUS_REGISTRY_URL};
use common::tenants::insert_test_tenant;

async fn insert_test_issuer(pool: &PgPool, tenant_id: &TenantId, issuer_id: &IssuerId) {
    sqlx::query(
        "INSERT INTO issuers (id, tenant_id, did, display_name) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(issuer_id.bare())
    .bind(tenant_id.bare())
    .bind(format!("did:tdw:dev.example.com:{}", issuer_id.bare()))
    .bind("Test Issuer")
    .execute(pool)
    .await
    .unwrap();
}

fn fixture_state() -> CreateIssuerStateData {
    CreateIssuerStateData {
        status_list_registry_entry_id: Some(SAMPLE_STATUS_ENTRY_ID.into()),
        status_list_registry_url: Some(SAMPLE_STATUS_REGISTRY_URL.into()),
        ..CreateIssuerStateData::default()
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn happy_path_provisions_row_and_repoints_pointer(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer_id = IssuerId::generate();
    insert_test_issuer(&pool, &tenant_id, &issuer_id).await;

    let outcome = execute_provision_status_list(&pool, &issuer_id, &fixture_state()).await;
    assert!(matches!(outcome, StepOutcome::Done(_)));

    let mut conn = pool.acquire().await.unwrap();
    let pointer = persistence::status_lists::current_for_issuer(&mut conn, &issuer_id)
        .await
        .unwrap()
        .expect("issuers.current_status_list_id is set after provisioning");

    let row: (Option<String>, Option<String>) =
        sqlx::query_as("SELECT registry_entry_id, registry_url FROM status_lists WHERE id = $1")
            .bind(pointer.bare())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        row,
        (
            Some(SAMPLE_STATUS_ENTRY_ID.into()),
            Some(SAMPLE_STATUS_REGISTRY_URL.into())
        )
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn idempotent_on_resume_when_pointer_already_set(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer_id = IssuerId::generate();
    insert_test_issuer(&pool, &tenant_id, &issuer_id).await;

    // First run provisions normally.
    let outcome = execute_provision_status_list(&pool, &issuer_id, &fixture_state()).await;
    assert!(matches!(outcome, StepOutcome::Done(_)));

    let mut conn = pool.acquire().await.unwrap();
    let first_pointer = persistence::status_lists::current_for_issuer(&mut conn, &issuer_id)
        .await
        .unwrap()
        .unwrap();
    drop(conn);

    // Second run observes the pointer set and short-circuits without
    // creating a duplicate row.
    let outcome = execute_provision_status_list(&pool, &issuer_id, &fixture_state()).await;
    assert!(matches!(outcome, StepOutcome::Done(_)));

    let mut conn = pool.acquire().await.unwrap();
    let second_pointer = persistence::status_lists::current_for_issuer(&mut conn, &issuer_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first_pointer, second_pointer);

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM status_lists WHERE issuer_id = $1")
        .bind(issuer_id.bare())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1, "no duplicate row created on resume");
}

#[sqlx::test(migrations = "./migrations")]
async fn missing_entry_id_is_terminal(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer_id = IssuerId::generate();
    insert_test_issuer(&pool, &tenant_id, &issuer_id).await;

    let state = CreateIssuerStateData {
        status_list_registry_entry_id: None,
        status_list_registry_url: Some(SAMPLE_STATUS_REGISTRY_URL.into()),
        ..CreateIssuerStateData::default()
    };
    let outcome = execute_provision_status_list(&pool, &issuer_id, &state).await;
    match outcome {
        StepOutcome::Terminal { error_code, .. } => assert_eq!(error_code, "missing_state"),
        other => panic!("expected Terminal; got {other:?}"),
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn missing_registry_url_is_terminal(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer_id = IssuerId::generate();
    insert_test_issuer(&pool, &tenant_id, &issuer_id).await;

    let state = CreateIssuerStateData {
        status_list_registry_entry_id: Some(SAMPLE_STATUS_ENTRY_ID.into()),
        status_list_registry_url: None,
        ..CreateIssuerStateData::default()
    };
    let outcome = execute_provision_status_list(&pool, &issuer_id, &state).await;
    match outcome {
        StepOutcome::Terminal { error_code, .. } => assert_eq!(error_code, "missing_state"),
        other => panic!("expected Terminal; got {other:?}"),
    }
}
