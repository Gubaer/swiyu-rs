//! Integration tests for `persistence::issuer_credential_types`.
//!
//! Each test runs against a freshly created Postgres database via
//! `sqlx::test`; migrations apply automatically.

use sqlx::PgPool;

use swiyu_issuer::domain::{CredentialTypeId, IssuerCredentialTypeAssignment, IssuerId, TenantId};
use swiyu_issuer::persistence::issuer_credential_types::{self, AssignOutcome, UnassignOutcome};

use swiyu_issuer::test_support::persistence::credential_types as test_credential_types;
use swiyu_issuer::test_support::persistence::issuer_credential_types as test_assignments;
use swiyu_issuer::test_support::persistence::issuers as test_issuers;
use swiyu_issuer::test_support::persistence::tenants::insert_test_tenant;

#[sqlx::test(migrations = "./migrations")]
async fn assign_inserts_new_row(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer = test_issuers::insert_active(&pool, &tenant_id).await;
    let credential_type = test_credential_types::seed(&pool, &tenant_id).await;

    let assignment = IssuerCredentialTypeAssignment::new(
        issuer.id.clone(),
        credential_type.id.clone(),
        tenant_id.clone(),
    );
    let mut conn = pool.acquire().await.unwrap();
    let outcome = issuer_credential_types::assign(&mut conn, &assignment)
        .await
        .unwrap();
    assert_eq!(outcome, AssignOutcome::NowAssigned);

    let rows = issuer_credential_types::list_by_issuer(&mut conn, &issuer.id)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].issuer_id, issuer.id);
    assert_eq!(rows[0].credential_type_id, credential_type.id);
    assert_eq!(rows[0].tenant_id, tenant_id);
}

#[sqlx::test(migrations = "./migrations")]
async fn assign_is_idempotent_on_existing_row(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer = test_issuers::insert_active(&pool, &tenant_id).await;
    let credential_type = test_credential_types::seed(&pool, &tenant_id).await;

    let assignment = IssuerCredentialTypeAssignment::new(
        issuer.id.clone(),
        credential_type.id.clone(),
        tenant_id.clone(),
    );
    let mut conn = pool.acquire().await.unwrap();
    assert_eq!(
        issuer_credential_types::assign(&mut conn, &assignment)
            .await
            .unwrap(),
        AssignOutcome::NowAssigned
    );
    assert_eq!(
        issuer_credential_types::assign(&mut conn, &assignment)
            .await
            .unwrap(),
        AssignOutcome::AlreadyAssigned
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn unassign_removes_existing_row(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer = test_issuers::insert_active(&pool, &tenant_id).await;
    let credential_type = test_credential_types::seed(&pool, &tenant_id).await;
    let _assignment =
        test_assignments::seed(&pool, &issuer.id, &credential_type.id, &tenant_id).await;

    let mut conn = pool.acquire().await.unwrap();
    let outcome = issuer_credential_types::unassign(&mut conn, &issuer.id, &credential_type.id)
        .await
        .unwrap();
    assert_eq!(outcome, UnassignOutcome::NowUnassigned);

    let rows = issuer_credential_types::list_by_issuer(&mut conn, &issuer.id)
        .await
        .unwrap();
    assert!(rows.is_empty());
}

#[sqlx::test(migrations = "./migrations")]
async fn unassign_is_idempotent_on_absent_row(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer = test_issuers::insert_active(&pool, &tenant_id).await;
    let credential_type = test_credential_types::seed(&pool, &tenant_id).await;

    let mut conn = pool.acquire().await.unwrap();
    // No row to remove; the call must report `NotAssigned`.
    let outcome = issuer_credential_types::unassign(&mut conn, &issuer.id, &credential_type.id)
        .await
        .unwrap();
    assert_eq!(outcome, UnassignOutcome::NotAssigned);
}

#[sqlx::test(migrations = "./migrations")]
async fn list_by_issuer_scopes_to_issuer(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer_a = test_issuers::insert_active(&pool, &tenant_id).await;
    let issuer_b = test_issuers::insert_active(&pool, &tenant_id).await;
    let credential_type = test_credential_types::seed(&pool, &tenant_id).await;

    // Only assign to issuer_a.
    let _assignment =
        test_assignments::seed(&pool, &issuer_a.id, &credential_type.id, &tenant_id).await;

    let mut conn = pool.acquire().await.unwrap();
    let a_rows = issuer_credential_types::list_by_issuer(&mut conn, &issuer_a.id)
        .await
        .unwrap();
    let b_rows = issuer_credential_types::list_by_issuer(&mut conn, &issuer_b.id)
        .await
        .unwrap();

    assert_eq!(a_rows.len(), 1);
    assert!(b_rows.is_empty());
}

#[sqlx::test(migrations = "./migrations")]
async fn list_by_credential_type_returns_all_assignments(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer_a = test_issuers::insert_active(&pool, &tenant_id).await;
    let issuer_b = test_issuers::insert_active(&pool, &tenant_id).await;
    let credential_type = test_credential_types::seed(&pool, &tenant_id).await;

    let _a = test_assignments::seed(&pool, &issuer_a.id, &credential_type.id, &tenant_id).await;
    let _b = test_assignments::seed(&pool, &issuer_b.id, &credential_type.id, &tenant_id).await;

    let mut conn = pool.acquire().await.unwrap();
    let rows = issuer_credential_types::list_by_credential_type(&mut conn, &credential_type.id)
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    let issuer_ids: std::collections::HashSet<_> =
        rows.iter().map(|a| a.issuer_id.clone()).collect();
    assert!(issuer_ids.contains(&issuer_a.id));
    assert!(issuer_ids.contains(&issuer_b.id));
}

#[sqlx::test(migrations = "./migrations")]
async fn is_assigned_reports_membership(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer = test_issuers::insert_active(&pool, &tenant_id).await;
    let credential_type = test_credential_types::seed(&pool, &tenant_id).await;

    let mut conn = pool.acquire().await.unwrap();
    assert!(
        !issuer_credential_types::is_assigned(&mut conn, &issuer.id, &credential_type.id)
            .await
            .unwrap()
    );

    let _assignment =
        test_assignments::seed(&pool, &issuer.id, &credential_type.id, &tenant_id).await;
    assert!(
        issuer_credential_types::is_assigned(&mut conn, &issuer.id, &credential_type.id)
            .await
            .unwrap()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn assign_with_unknown_issuer_is_a_foreign_key_violation(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let credential_type = test_credential_types::seed(&pool, &tenant_id).await;

    let assignment =
        IssuerCredentialTypeAssignment::new(IssuerId::generate(), credential_type.id, tenant_id);
    let mut conn = pool.acquire().await.unwrap();
    let result = issuer_credential_types::assign(&mut conn, &assignment).await;
    assert!(result.is_err());
}

#[sqlx::test(migrations = "./migrations")]
async fn assign_with_unknown_credential_type_is_a_foreign_key_violation(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer = test_issuers::insert_active(&pool, &tenant_id).await;

    let assignment =
        IssuerCredentialTypeAssignment::new(issuer.id, CredentialTypeId::generate(), tenant_id);
    let mut conn = pool.acquire().await.unwrap();
    let result = issuer_credential_types::assign(&mut conn, &assignment).await;
    assert!(result.is_err());
}
