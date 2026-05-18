//! Integration tests for `persistence::credential_types`.
//!
//! Each test runs against a freshly created Postgres database via
//! `sqlx::test`; migrations apply automatically. Requires
//! `DATABASE_URL` to point to a Postgres instance whose user has
//! `CREATEDB` privilege.

use chrono::{Duration, Utc};
use serde_json::json;
use sqlx::PgPool;

use swiyu_issuer::domain::{CredentialType, CredentialTypeId, RevocationMode, TenantId};
use swiyu_issuer::persistence::credential_types::{
    self, ListPageQuery, StructuredUpdate, UpdateOutcome,
};

use swiyu_issuer::test_support::persistence::credential_types as test_credential_types;
use swiyu_issuer::test_support::persistence::issuer_credential_types as test_assignments;
use swiyu_issuer::test_support::persistence::issuers as test_issuers;
use swiyu_issuer::test_support::persistence::tenants::insert_test_tenant;

#[sqlx::test(migrations = "./migrations")]
async fn insert_and_find_by_id_round_trips(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;

    let credential_type = test_credential_types::sample(&tenant_id);
    let mut conn = pool.acquire().await.unwrap();
    credential_types::insert(&mut conn, &credential_type)
        .await
        .unwrap();

    let loaded = credential_types::find_by_id(&mut conn, &credential_type.id)
        .await
        .unwrap()
        .expect("inserted credential type should be found");

    assert_eq!(loaded.id, credential_type.id);
    assert_eq!(loaded.tenant_id, credential_type.tenant_id);
    assert_eq!(loaded.vct, credential_type.vct);
    assert_eq!(loaded.display, credential_type.display);
    assert_eq!(
        loaded.internal_description,
        credential_type.internal_description
    );
    assert_eq!(loaded.claim_schema, credential_type.claim_schema);
    assert_eq!(loaded.claims, credential_type.claims);
    assert_eq!(
        loaded.default_validity_duration,
        credential_type.default_validity_duration
    );
    assert_eq!(loaded.revocation_mode, credential_type.revocation_mode);
    assert!(loaded.retired_at.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn find_by_id_for_tenant_returns_none_for_cross_tenant(pool: PgPool) {
    let tenant_owner = TenantId::generate();
    let tenant_other = TenantId::generate();
    insert_test_tenant(&pool, &tenant_owner).await;
    insert_test_tenant(&pool, &tenant_other).await;

    let credential_type = test_credential_types::seed(&pool, &tenant_owner).await;
    let mut conn = pool.acquire().await.unwrap();
    let result =
        credential_types::find_by_id_for_tenant(&mut conn, &tenant_other, &credential_type.id)
            .await
            .unwrap();
    assert!(result.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn find_by_id_for_tenant_returns_row_for_owning_tenant(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;

    let credential_type = test_credential_types::seed(&pool, &tenant_id).await;
    let mut conn = pool.acquire().await.unwrap();
    let loaded =
        credential_types::find_by_id_for_tenant(&mut conn, &tenant_id, &credential_type.id)
            .await
            .unwrap()
            .expect("owning tenant must see its credential type");
    assert_eq!(loaded.id, credential_type.id);
}

#[sqlx::test(migrations = "./migrations")]
async fn list_returns_tenants_credential_types_only(pool: PgPool) {
    let tenant_a = TenantId::generate();
    let tenant_b = TenantId::generate();
    insert_test_tenant(&pool, &tenant_a).await;
    insert_test_tenant(&pool, &tenant_b).await;

    let _ct_a = test_credential_types::seed(&pool, &tenant_a).await;
    let _ct_b = test_credential_types::seed(&pool, &tenant_b).await;

    let mut conn = pool.acquire().await.unwrap();
    let page = credential_types::list(
        &mut conn,
        &tenant_a,
        ListPageQuery {
            cursor: None,
            limit: 50,
            include_retired: false,
        },
    )
    .await
    .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].tenant_id, tenant_a);
    assert!(!page.has_more);
}

#[sqlx::test(migrations = "./migrations")]
async fn list_excludes_retired_by_default(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;

    let active = test_credential_types::seed(&pool, &tenant_id).await;
    let retired = {
        let mut ct = CredentialType::new(
            tenant_id.clone(),
            "urn:dummy:retired".into(),
            json!([]),
            None,
            test_credential_types::sample_claim_schema(),
            json!({}),
            Duration::days(90),
            RevocationMode::Revocable,
        );
        // Persist first, then retire so we exercise the retire helper.
        test_credential_types::insert(&pool, &ct).await;
        let mut conn = pool.acquire().await.unwrap();
        let outcome = credential_types::retire(&mut conn, &tenant_id, &ct.id, Utc::now())
            .await
            .unwrap();
        assert_eq!(outcome, UpdateOutcome::Updated);
        ct.retired_at = Some(Utc::now());
        ct
    };

    let mut conn = pool.acquire().await.unwrap();
    let active_only = credential_types::list(
        &mut conn,
        &tenant_id,
        ListPageQuery {
            cursor: None,
            limit: 50,
            include_retired: false,
        },
    )
    .await
    .unwrap();
    assert_eq!(active_only.items.len(), 1);
    assert_eq!(active_only.items[0].id, active.id);

    let with_retired = credential_types::list(
        &mut conn,
        &tenant_id,
        ListPageQuery {
            cursor: None,
            limit: 50,
            include_retired: true,
        },
    )
    .await
    .unwrap();
    assert_eq!(with_retired.items.len(), 2);
    assert!(with_retired.items.iter().any(|ct| ct.id == retired.id));
}

#[sqlx::test(migrations = "./migrations")]
async fn update_structured_writes_supplied_fields_only(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;

    let credential_type = test_credential_types::seed(&pool, &tenant_id).await;
    let mut conn = pool.acquire().await.unwrap();
    let outcome = credential_types::update_structured(
        &mut conn,
        &tenant_id,
        &credential_type.id,
        StructuredUpdate {
            internal_description: Some("changed"),
            revocation_mode: Some(RevocationMode::Revocable),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(outcome, UpdateOutcome::Updated);

    let loaded = credential_types::find_by_id(&mut conn, &credential_type.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.internal_description.as_deref(), Some("changed"));
    assert_eq!(loaded.revocation_mode, RevocationMode::Revocable);
    // Unchanged fields keep their value.
    assert_eq!(loaded.vct, credential_type.vct);
    assert_eq!(
        loaded.default_validity_duration,
        credential_type.default_validity_duration
    );
    // updated_at moves forward.
    assert!(loaded.updated_at >= credential_type.updated_at);
}

#[sqlx::test(migrations = "./migrations")]
async fn update_structured_returns_not_found_for_unknown_row(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;

    let mut conn = pool.acquire().await.unwrap();
    let result = credential_types::update_structured(
        &mut conn,
        &tenant_id,
        &CredentialTypeId::generate(),
        StructuredUpdate {
            internal_description: Some("never written"),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(result, UpdateOutcome::NotFound);
}

#[sqlx::test(migrations = "./migrations")]
async fn update_blob_schema_replaces_document_and_bumps_fetched_at(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;

    let credential_type = test_credential_types::seed(&pool, &tenant_id).await;
    assert!(credential_type.claim_schema_fetched_at.is_none());

    let new_schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": { "age": { "type": "integer" } },
        "required": ["age"]
    });

    let mut conn = pool.acquire().await.unwrap();
    let outcome = credential_types::update_blob_schema(
        &mut conn,
        &tenant_id,
        &credential_type.id,
        &new_schema,
    )
    .await
    .unwrap();
    assert_eq!(outcome, UpdateOutcome::Updated);

    let loaded = credential_types::find_by_id(&mut conn, &credential_type.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.claim_schema, new_schema);
    assert!(loaded.claim_schema_fetched_at.is_some());
    assert!(loaded.updated_at >= credential_type.updated_at);
}

#[sqlx::test(migrations = "./migrations")]
async fn update_blob_display_replaces_value(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;

    let credential_type = test_credential_types::seed(&pool, &tenant_id).await;
    let new_display = json!([{ "name": "Test", "locale": "en-US" }]);

    let mut conn = pool.acquire().await.unwrap();
    let outcome = credential_types::update_blob_display(
        &mut conn,
        &tenant_id,
        &credential_type.id,
        &new_display,
    )
    .await
    .unwrap();
    assert_eq!(outcome, UpdateOutcome::Updated);

    let loaded = credential_types::find_by_id(&mut conn, &credential_type.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.display, new_display);
}

#[sqlx::test(migrations = "./migrations")]
async fn update_blob_claims_replaces_value(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;

    let credential_type = test_credential_types::seed(&pool, &tenant_id).await;
    let new_claims = json!({ "first_name": { "display": [{ "name": "First name" }] } });

    let mut conn = pool.acquire().await.unwrap();
    let outcome = credential_types::update_blob_claims(
        &mut conn,
        &tenant_id,
        &credential_type.id,
        &new_claims,
    )
    .await
    .unwrap();
    assert_eq!(outcome, UpdateOutcome::Updated);

    let loaded = credential_types::find_by_id(&mut conn, &credential_type.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.claims, new_claims);
}

#[sqlx::test(migrations = "./migrations")]
async fn retire_stamps_retired_at_and_deletes_assignments(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;

    let issuer = test_issuers::insert_active(&pool, &tenant_id).await;
    let credential_type = test_credential_types::seed(&pool, &tenant_id).await;
    let _assignment =
        test_assignments::seed(&pool, &issuer.id, &credential_type.id, &tenant_id).await;

    let mut conn = pool.acquire().await.unwrap();
    let outcome = credential_types::retire(&mut conn, &tenant_id, &credential_type.id, Utc::now())
        .await
        .unwrap();
    assert_eq!(outcome, UpdateOutcome::Updated);

    let loaded = credential_types::find_by_id(&mut conn, &credential_type.id)
        .await
        .unwrap()
        .unwrap();
    assert!(loaded.retired_at.is_some());

    // The cascade DELETE in `retire` removed the link row.
    let remaining = swiyu_issuer::persistence::issuer_credential_types::list_by_credential_type(
        &mut conn,
        &credential_type.id,
    )
    .await
    .unwrap();
    assert!(remaining.is_empty());
}

#[sqlx::test(migrations = "./migrations")]
async fn retire_returns_not_found_for_unknown_id(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;

    let mut conn = pool.acquire().await.unwrap();
    let outcome = credential_types::retire(
        &mut conn,
        &tenant_id,
        &CredentialTypeId::generate(),
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(outcome, UpdateOutcome::NotFound);
}

#[sqlx::test(migrations = "./migrations")]
async fn retire_is_cross_tenant_safe(pool: PgPool) {
    let tenant_owner = TenantId::generate();
    let tenant_other = TenantId::generate();
    insert_test_tenant(&pool, &tenant_owner).await;
    insert_test_tenant(&pool, &tenant_other).await;

    let credential_type = test_credential_types::seed(&pool, &tenant_owner).await;
    let mut conn = pool.acquire().await.unwrap();

    let outcome =
        credential_types::retire(&mut conn, &tenant_other, &credential_type.id, Utc::now())
            .await
            .unwrap();
    assert_eq!(outcome, UpdateOutcome::NotFound);

    // Row is unchanged.
    let loaded = credential_types::find_by_id(&mut conn, &credential_type.id)
        .await
        .unwrap()
        .unwrap();
    assert!(loaded.retired_at.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn duplicate_vct_within_tenant_violates_unique(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;

    let first = test_credential_types::seed(&pool, &tenant_id).await;
    let mut second = test_credential_types::sample(&tenant_id);
    second.vct = first.vct.clone();

    let mut conn = pool.acquire().await.unwrap();
    let result = credential_types::insert(&mut conn, &second).await;
    assert!(matches!(
        result,
        Err(swiyu_issuer::persistence::PersistenceError::UniqueViolation { .. })
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn same_vct_across_tenants_is_allowed(pool: PgPool) {
    let tenant_a = TenantId::generate();
    let tenant_b = TenantId::generate();
    insert_test_tenant(&pool, &tenant_a).await;
    insert_test_tenant(&pool, &tenant_b).await;

    // Both tenants insert a row with the same `vct`. The UNIQUE
    // constraint is `(tenant_id, vct)`, so cross-tenant collisions
    // must be accepted.
    let _ct_a = test_credential_types::seed(&pool, &tenant_a).await;
    let _ct_b = test_credential_types::seed(&pool, &tenant_b).await;
    // Reaching this line is the assertion.
}
