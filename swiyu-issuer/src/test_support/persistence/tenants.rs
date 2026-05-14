use sqlx::PgPool;
use uuid::Uuid;

use crate::domain::TenantId;

pub async fn insert_test_tenant(pool: &PgPool, tenant_id: &TenantId) {
    sqlx::query("INSERT INTO tenants (id, partner_id) VALUES ($1, $2)")
        .bind(tenant_id.bare())
        .bind(Uuid::new_v4())
        .execute(pool)
        .await
        .unwrap();
}
