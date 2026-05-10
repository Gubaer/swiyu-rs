//! Integration tests for `persistence::tenants`.
//!
//! Each test runs against a freshly created Postgres database created
//! by `sqlx::test`; migrations are applied automatically. Requires
//! `DATABASE_URL` to point to a Postgres instance whose user has
//! `CREATEDB` privilege.

use sqlx::PgPool;

use swiyu_issuer::domain::TenantId;
use swiyu_issuer::persistence::tenants;

async fn insert_test_tenant(pool: &PgPool, tenant_id: &TenantId, partner_id: Option<&str>) {
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
    insert_test_tenant(
        &pool,
        &tenant_id,
        Some("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef"),
    )
    .await;

    let mut conn = pool.acquire().await.unwrap();
    let tenant = tenants::find_by_id(&mut conn, &tenant_id)
        .await
        .unwrap()
        .expect("tenant exists");

    assert_eq!(tenant.id, tenant_id);
    assert_eq!(
        tenant.partner_id.as_deref(),
        Some("4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef"),
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn find_by_id_returns_tenant_without_partner_id(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id, None).await;

    let mut conn = pool.acquire().await.unwrap();
    let tenant = tenants::find_by_id(&mut conn, &tenant_id)
        .await
        .unwrap()
        .expect("tenant exists");

    assert_eq!(tenant.id, tenant_id);
    assert!(tenant.partner_id.is_none());
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

    let mut conn = pool.acquire().await.unwrap();
    let tenant = tenants::find_by_id(&mut conn, &tenant_id)
        .await
        .unwrap()
        .expect("seeded dev tenant exists");

    assert_eq!(
        tenant.partner_id.as_deref(),
        Some("7355b9bb-d45a-4d42-82ea-0c30b3f2fa25"),
    );
}
