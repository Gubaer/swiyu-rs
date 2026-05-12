//! Integration tests for `persistence::tenants`.
//!
//! Each test runs against a freshly created Postgres database created
//! by `sqlx::test`; migrations are applied automatically. Requires
//! `DATABASE_URL` to point to a Postgres instance whose user has
//! `CREATEDB` privilege.

use sqlx::PgPool;
use uuid::Uuid;

use swiyu_issuer::domain::TenantId;
use swiyu_issuer::persistence::tenants;

#[path = "common/mod.rs"]
mod common;
use common::seeded::SEEDED_DEV_TENANT_PARTNER_ID;

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
