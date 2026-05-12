//! Shared tenant fixtures for integration tests. Use
//! `insert_test_tenant` when a test needs a tenant row but does not
//! care about its `partner_id`; use
//! `oauth::insert_tenant_with_oauth_secrets` when it also needs the
//! OAuth2 columns populated.

#![allow(dead_code)] // not every test module pulls in this helper

use sqlx::PgPool;
use uuid::Uuid;

use swiyu_issuer::domain::TenantId;

pub async fn insert_test_tenant(pool: &PgPool, tenant_id: &TenantId) {
    sqlx::query("INSERT INTO tenants (id, partner_id) VALUES ($1, $2)")
        .bind(tenant_id.bare())
        .bind(Uuid::new_v4())
        .execute(pool)
        .await
        .unwrap();
}
