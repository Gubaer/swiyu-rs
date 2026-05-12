//! Integration tests for `persistence::tenants`.
//!
//! Each test runs against a freshly created Postgres database created
//! by `sqlx::test`; migrations are applied automatically. Requires
//! `DATABASE_URL` to point to a Postgres instance whose user has
//! `CREATEDB` privilege.

use sqlx::PgPool;
use uuid::Uuid;

use swiyu_issuer::domain::TenantId;
use swiyu_issuer::persistence::PersistenceError;
use swiyu_issuer::persistence::tenants::{self, UpdateOutcome};

#[path = "common/mod.rs"]
mod common;
use common::seeded::SEEDED_DEV_TENANT_PARTNER_ID;

const TEST_PARTNER: &str = "4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef";
const ALT_PARTNER: &str = "11111111-2222-3333-4444-555555555555";

async fn insert_test_tenant(pool: &PgPool, tenant_id: &TenantId, partner_id: Uuid) {
    sqlx::query("INSERT INTO tenants (id, partner_id) VALUES ($1, $2)")
        .bind(tenant_id.bare())
        .bind(partner_id)
        .execute(pool)
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn find_by_id_returns_tenant_with_partner_id(pool: PgPool) {
    let tenant_id = TenantId::generate();
    let partner_id: Uuid = "4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef".parse().unwrap();
    insert_test_tenant(&pool, &tenant_id, partner_id).await;

    let mut conn = pool.acquire().await.unwrap();
    let tenant = tenants::find_by_id(&mut conn, &tenant_id)
        .await
        .unwrap()
        .expect("tenant exists");

    assert_eq!(tenant.id, tenant_id);
    assert_eq!(tenant.partner_id, partner_id);
}

#[sqlx::test(migrations = "./migrations")]
async fn find_by_id_returns_none_for_unknown_tenant(pool: PgPool) {
    let tenant_id = TenantId::generate();

    let mut conn = pool.acquire().await.unwrap();
    let result = tenants::find_by_id(&mut conn, &tenant_id).await.unwrap();

    assert!(result.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn seeded_dev_tenant_carries_kacon_partner_id(pool: PgPool) {
    // The seeded dev tenant carries the kacon gmbh business partner
    // id — the consolidated baseline migration (swiyu-issuer/migrations/
    // 20260430_000001_init.sql) writes it.
    let tenant_id = TenantId::from_bare("4Mk7yK5pQR7sN3").unwrap();
    let expected: Uuid = SEEDED_DEV_TENANT_PARTNER_ID.parse().unwrap();

    let mut conn = pool.acquire().await.unwrap();
    let tenant = tenants::find_by_id(&mut conn, &tenant_id)
        .await
        .unwrap()
        .expect("seeded dev tenant exists");

    assert_eq!(tenant.partner_id, expected);
}

#[sqlx::test(migrations = "./migrations")]
async fn insert_writes_all_columns(pool: PgPool) {
    let tenant_id = TenantId::generate();
    let partner_id: Uuid = TEST_PARTNER.parse().unwrap();

    let mut conn = pool.acquire().await.unwrap();
    tenants::insert(
        &mut conn,
        &tenant_id,
        partner_id,
        Some("Canton Bern"),
        Some("Cantonal e-government tenant"),
    )
    .await
    .unwrap();

    let tenant = tenants::find_by_id(&mut conn, &tenant_id)
        .await
        .unwrap()
        .expect("tenant exists");
    assert_eq!(tenant.id, tenant_id);
    assert_eq!(tenant.partner_id, partner_id);
    assert_eq!(tenant.display_name.as_deref(), Some("Canton Bern"));
    assert_eq!(
        tenant.description.as_deref(),
        Some("Cantonal e-government tenant"),
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn insert_with_null_metadata_leaves_those_columns_null(pool: PgPool) {
    let tenant_id = TenantId::generate();
    let partner_id: Uuid = TEST_PARTNER.parse().unwrap();

    let mut conn = pool.acquire().await.unwrap();
    tenants::insert(&mut conn, &tenant_id, partner_id, None, None)
        .await
        .unwrap();

    let tenant = tenants::find_by_id(&mut conn, &tenant_id)
        .await
        .unwrap()
        .expect("tenant exists");
    assert_eq!(tenant.partner_id, partner_id);
    assert!(tenant.display_name.is_none());
    assert!(tenant.description.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn insert_with_colliding_id_returns_unique_violation(pool: PgPool) {
    let tenant_id = TenantId::generate();
    let partner_id: Uuid = TEST_PARTNER.parse().unwrap();

    let mut conn = pool.acquire().await.unwrap();
    tenants::insert(&mut conn, &tenant_id, partner_id, None, None)
        .await
        .unwrap();

    let result = tenants::insert(&mut conn, &tenant_id, partner_id, None, None).await;
    match result {
        Err(PersistenceError::UniqueViolation { .. }) => {}
        other => panic!("expected UniqueViolation, got {other:?}"),
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn insert_with_duplicate_partner_id_returns_unique_violation(pool: PgPool) {
    let partner_id: Uuid = TEST_PARTNER.parse().unwrap();
    let first_id = TenantId::generate();
    let second_id = TenantId::generate();

    let mut conn = pool.acquire().await.unwrap();
    tenants::insert(&mut conn, &first_id, partner_id, None, None)
        .await
        .unwrap();

    let result = tenants::insert(&mut conn, &second_id, partner_id, None, None).await;
    match result {
        Err(PersistenceError::UniqueViolation { what }) => {
            assert_eq!(what, "tenants_partner_id_key");
        }
        other => panic!("expected UniqueViolation, got {other:?}"),
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn update_metadata_partial_display_name_only(pool: PgPool) {
    let tenant_id = TenantId::generate();
    let partner_id: Uuid = TEST_PARTNER.parse().unwrap();
    let mut conn = pool.acquire().await.unwrap();
    tenants::insert(
        &mut conn,
        &tenant_id,
        partner_id,
        Some("original-name"),
        Some("original-desc"),
    )
    .await
    .unwrap();

    let outcome = tenants::update_metadata(&mut conn, &tenant_id, None, Some("updated-name"), None)
        .await
        .unwrap();
    assert_eq!(outcome, UpdateOutcome::Updated);

    let tenant = tenants::find_by_id(&mut conn, &tenant_id)
        .await
        .unwrap()
        .expect("tenant exists");
    assert_eq!(tenant.partner_id, partner_id);
    assert_eq!(tenant.display_name.as_deref(), Some("updated-name"));
    assert_eq!(tenant.description.as_deref(), Some("original-desc"));
}

#[sqlx::test(migrations = "./migrations")]
async fn update_metadata_partial_partner_id_only(pool: PgPool) {
    let tenant_id = TenantId::generate();
    let original_partner: Uuid = TEST_PARTNER.parse().unwrap();
    let new_partner: Uuid = ALT_PARTNER.parse().unwrap();
    let mut conn = pool.acquire().await.unwrap();
    tenants::insert(
        &mut conn,
        &tenant_id,
        original_partner,
        Some("name"),
        Some("desc"),
    )
    .await
    .unwrap();

    let outcome = tenants::update_metadata(&mut conn, &tenant_id, Some(new_partner), None, None)
        .await
        .unwrap();
    assert_eq!(outcome, UpdateOutcome::Updated);

    let tenant = tenants::find_by_id(&mut conn, &tenant_id)
        .await
        .unwrap()
        .expect("tenant exists");
    assert_eq!(tenant.partner_id, new_partner);
    assert_eq!(tenant.display_name.as_deref(), Some("name"));
    assert_eq!(tenant.description.as_deref(), Some("desc"));
}

#[sqlx::test(migrations = "./migrations")]
async fn update_metadata_returns_not_found_for_unknown_tenant(pool: PgPool) {
    let tenant_id = TenantId::generate();
    let mut conn = pool.acquire().await.unwrap();

    let outcome = tenants::update_metadata(&mut conn, &tenant_id, None, Some("name"), None)
        .await
        .unwrap();
    assert_eq!(outcome, UpdateOutcome::NotFound);
}

#[sqlx::test(migrations = "./migrations")]
async fn update_metadata_with_all_none_touches_nothing(pool: PgPool) {
    let tenant_id = TenantId::generate();
    let partner_id: Uuid = TEST_PARTNER.parse().unwrap();
    let mut conn = pool.acquire().await.unwrap();
    tenants::insert(
        &mut conn,
        &tenant_id,
        partner_id,
        Some("name"),
        Some("desc"),
    )
    .await
    .unwrap();

    let outcome = tenants::update_metadata(&mut conn, &tenant_id, None, None, None)
        .await
        .unwrap();
    // Row exists -> Updated even though no columns changed; the helper
    // contract is "row matched", not "non-empty diff".
    assert_eq!(outcome, UpdateOutcome::Updated);

    let tenant = tenants::find_by_id(&mut conn, &tenant_id)
        .await
        .unwrap()
        .expect("tenant exists");
    assert_eq!(tenant.partner_id, partner_id);
    assert_eq!(tenant.display_name.as_deref(), Some("name"));
    assert_eq!(tenant.description.as_deref(), Some("desc"));
}
