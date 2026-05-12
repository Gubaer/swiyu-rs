//! Shared tenant fixtures for integration tests.
//!
//! `insert_test_tenant` is the shortcut for tests that need a tenant
//! row to exist but do not care which `partner_id` value it carries —
//! the helper fills in a fixed UUID so the NOT-NULL constraint is
//! satisfied without each test having to choose one. Tests that need
//! the OAuth2 columns populated use
//! `oauth::insert_tenant_with_oauth_secrets` instead.

#![allow(dead_code)] // not every test module pulls in this helper

use sqlx::PgPool;
use swiyu_issuer::domain::TenantId;

// Distinct from the seeded dev tenant's partner_id so a test using
// this helper never collides with the seeded row on a fresh DB.
pub const TEST_PARTNER_ID: &str = "4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef";

pub async fn insert_test_tenant(pool: &PgPool, tenant_id: &TenantId) {
    sqlx::query("INSERT INTO tenants (id, partner_id) VALUES ($1, $2::uuid)")
        .bind(tenant_id.bare())
        .bind(TEST_PARTNER_ID)
        .execute(pool)
        .await
        .unwrap();
}
