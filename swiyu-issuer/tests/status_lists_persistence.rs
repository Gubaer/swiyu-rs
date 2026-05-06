//! Schema-level tests for the `status_lists` table.
//!
//! Persistence-function tests (allocate / write_bit / current_for_issuer)
//! land in the next slice; this file currently exercises only the
//! migration's CHECK constraints and the FK from
//! `issuers.current_status_list_id`. Each test runs against a freshly
//! created Postgres database created by `sqlx::test`; migrations are
//! applied automatically. Requires `DATABASE_URL` to point to a
//! Postgres instance whose user has `CREATEDB` privilege.

use sqlx::PgPool;

use swiyu_issuer::domain::{BITSTRING_BYTES, LIST_CAPACITY, StatusListId, TenantId};

async fn insert_tenant(pool: &PgPool, tenant_id: &TenantId) {
    sqlx::query("INSERT INTO tenants (id) VALUES ($1)")
        .bind(tenant_id.bare())
        .execute(pool)
        .await
        .unwrap();
}

async fn insert_issuer(pool: &PgPool, tenant_id: &TenantId, issuer_id: &str) {
    sqlx::query(
        "INSERT INTO issuers (id, tenant_id, did, display_name) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(issuer_id)
    .bind(tenant_id.bare())
    .bind(format!("did:tdw:dev.example.com:{issuer_id}"))
    .bind("Test Issuer")
    .execute(pool)
    .await
    .unwrap();
}

async fn insert_status_list(
    pool: &PgPool,
    list_id: &StatusListId,
    issuer_id: &str,
    bitstring: Vec<u8>,
    allocated_count: i32,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    sqlx::query(
        "INSERT INTO status_lists (id, issuer_id, bitstring, allocated_count) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(list_id.bare())
    .bind(issuer_id)
    .bind(bitstring)
    .bind(allocated_count)
    .execute(pool)
    .await
}

#[sqlx::test(migrations = "./migrations")]
async fn well_formed_row_inserts_cleanly(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_tenant(&pool, &tenant_id).await;
    let issuer_id = "1234567890abcd";
    insert_issuer(&pool, &tenant_id, issuer_id).await;

    let list_id = StatusListId::generate();
    insert_status_list(&pool, &list_id, issuer_id, vec![0u8; BITSTRING_BYTES], 0)
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn bitstring_too_short_is_rejected(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_tenant(&pool, &tenant_id).await;
    let issuer_id = "1234567890abcd";
    insert_issuer(&pool, &tenant_id, issuer_id).await;

    let list_id = StatusListId::generate();
    let result = insert_status_list(&pool, &list_id, issuer_id, vec![0u8; 100], 0).await;
    assert!(result.is_err(), "100-byte bitstring must violate CHECK");
}

#[sqlx::test(migrations = "./migrations")]
async fn bitstring_too_long_is_rejected(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_tenant(&pool, &tenant_id).await;
    let issuer_id = "1234567890abcd";
    insert_issuer(&pool, &tenant_id, issuer_id).await;

    let list_id = StatusListId::generate();
    let result = insert_status_list(
        &pool,
        &list_id,
        issuer_id,
        vec![0u8; BITSTRING_BYTES + 1],
        0,
    )
    .await;
    assert!(result.is_err(), "33-KB bitstring must violate CHECK");
}

#[sqlx::test(migrations = "./migrations")]
async fn allocated_count_at_capacity_is_allowed(pool: PgPool) {
    // The CHECK reads `allocated_count <= 131072`; the saturated state
    // (one past the last valid index) must still pass.
    let tenant_id = TenantId::generate();
    insert_tenant(&pool, &tenant_id).await;
    let issuer_id = "1234567890abcd";
    insert_issuer(&pool, &tenant_id, issuer_id).await;

    let list_id = StatusListId::generate();
    insert_status_list(
        &pool,
        &list_id,
        issuer_id,
        vec![0u8; BITSTRING_BYTES],
        LIST_CAPACITY as i32,
    )
    .await
    .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn allocated_count_above_capacity_is_rejected(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_tenant(&pool, &tenant_id).await;
    let issuer_id = "1234567890abcd";
    insert_issuer(&pool, &tenant_id, issuer_id).await;

    let list_id = StatusListId::generate();
    let result = insert_status_list(
        &pool,
        &list_id,
        issuer_id,
        vec![0u8; BITSTRING_BYTES],
        LIST_CAPACITY as i32 + 1,
    )
    .await;
    assert!(
        result.is_err(),
        "allocated_count past capacity must violate CHECK"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn current_status_list_id_fk_is_enforced(pool: PgPool) {
    // Pointing `issuers.current_status_list_id` at a non-existent
    // status list must fail the FK. This also documents that the FK
    // is unconstrained in direction (an orphaned issuer pointer is
    // not silently allowed).
    let tenant_id = TenantId::generate();
    insert_tenant(&pool, &tenant_id).await;
    let issuer_id = "1234567890abcd";
    insert_issuer(&pool, &tenant_id, issuer_id).await;

    let result = sqlx::query("UPDATE issuers SET current_status_list_id = $1 WHERE id = $2")
        .bind("nonexistent_list")
        .bind(issuer_id)
        .execute(&pool)
        .await;
    assert!(result.is_err(), "FK to status_lists must reject unknown id");
}

#[sqlx::test(migrations = "./migrations")]
async fn current_status_list_id_can_point_at_real_list(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_tenant(&pool, &tenant_id).await;
    let issuer_id = "1234567890abcd";
    insert_issuer(&pool, &tenant_id, issuer_id).await;

    let list_id = StatusListId::generate();
    insert_status_list(&pool, &list_id, issuer_id, vec![0u8; BITSTRING_BYTES], 0)
        .await
        .unwrap();

    sqlx::query("UPDATE issuers SET current_status_list_id = $1 WHERE id = $2")
        .bind(list_id.bare())
        .bind(issuer_id)
        .execute(&pool)
        .await
        .unwrap();

    let stored: String =
        sqlx::query_scalar("SELECT current_status_list_id FROM issuers WHERE id = $1")
            .bind(issuer_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored, list_id.bare());
}
