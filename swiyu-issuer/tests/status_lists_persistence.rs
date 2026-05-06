//! Tests for the `status_lists` table and its persistence module.
//!
//! Covers two layers:
//!
//! - **Schema-level** — the migration's CHECK constraints and the FK
//!   from `issuers.current_status_list_id`.
//! - **Persistence functions** — `provision_for_issuer`,
//!   `current_for_issuer`, `allocate_index`, and `write_bit`.
//!
//! Each test runs against a freshly created Postgres database created
//! by `sqlx::test`; migrations are applied automatically. Requires
//! `DATABASE_URL` to point to a Postgres instance whose user has
//! `CREATEDB` privilege.

use sqlx::PgPool;

use swiyu_issuer::domain::{
    BITSTRING_BYTES, IssuerId, LIST_CAPACITY, StatusListId, StatusListIndex, StatusValue, TenantId,
    status_list::encoding,
};
use swiyu_issuer::persistence::status_lists;

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

// ============================================================================
// Persistence-function tests
// ============================================================================

async fn seeded_issuer(pool: &PgPool) -> IssuerId {
    let tenant_id = TenantId::generate();
    insert_tenant(pool, &tenant_id).await;
    let issuer_id = IssuerId::generate();
    insert_issuer(pool, &tenant_id, issuer_id.bare()).await;
    issuer_id
}

async fn fetch_committed_version(pool: &PgPool, list_id: &StatusListId) -> i64 {
    sqlx::query_scalar("SELECT committed_version FROM status_lists WHERE id = $1")
        .bind(list_id.bare())
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn fetch_allocated_count(pool: &PgPool, list_id: &StatusListId) -> i32 {
    sqlx::query_scalar("SELECT allocated_count FROM status_lists WHERE id = $1")
        .bind(list_id.bare())
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn fetch_bitstring(pool: &PgPool, list_id: &StatusListId) -> Vec<u8> {
    sqlx::query_scalar("SELECT bitstring FROM status_lists WHERE id = $1")
        .bind(list_id.bare())
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn current_for_issuer_is_none_for_fresh_issuer(pool: PgPool) {
    let issuer_id = seeded_issuer(&pool).await;
    let mut conn = pool.acquire().await.unwrap();

    let current = status_lists::current_for_issuer(&mut conn, &issuer_id)
        .await
        .unwrap();
    assert!(current.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn current_for_issuer_is_none_for_unknown_issuer(pool: PgPool) {
    // Unknown issuer collapses to "no current list"; the issuance
    // path tolerates this and provisions one.
    let mut conn = pool.acquire().await.unwrap();
    let unknown = IssuerId::generate();

    let current = status_lists::current_for_issuer(&mut conn, &unknown)
        .await
        .unwrap();
    assert!(current.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn provision_for_issuer_inserts_zeroed_row(pool: PgPool) {
    let issuer_id = seeded_issuer(&pool).await;
    let mut conn = pool.acquire().await.unwrap();

    let new_id = status_lists::provision_for_issuer(&mut conn, &issuer_id)
        .await
        .unwrap();

    let bitstring = fetch_bitstring(&pool, &new_id).await;
    assert_eq!(bitstring.len(), BITSTRING_BYTES);
    assert!(bitstring.iter().all(|byte| *byte == 0));
    assert_eq!(fetch_allocated_count(&pool, &new_id).await, 0);
    assert_eq!(fetch_committed_version(&pool, &new_id).await, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn provision_for_issuer_repoints_pointer(pool: PgPool) {
    let issuer_id = seeded_issuer(&pool).await;
    let mut conn = pool.acquire().await.unwrap();

    let new_id = status_lists::provision_for_issuer(&mut conn, &issuer_id)
        .await
        .unwrap();
    let current = status_lists::current_for_issuer(&mut conn, &issuer_id)
        .await
        .unwrap();
    assert_eq!(current.as_ref(), Some(&new_id));
}

#[sqlx::test(migrations = "./migrations")]
async fn provision_for_issuer_called_twice_repoints_each_time(pool: PgPool) {
    // The capacity-overflow path provisions a fresh list and
    // re-points the issuer pointer; verify the second call wins.
    let issuer_id = seeded_issuer(&pool).await;
    let mut conn = pool.acquire().await.unwrap();

    let first = status_lists::provision_for_issuer(&mut conn, &issuer_id)
        .await
        .unwrap();
    let second = status_lists::provision_for_issuer(&mut conn, &issuer_id)
        .await
        .unwrap();
    assert_ne!(first, second);

    let current = status_lists::current_for_issuer(&mut conn, &issuer_id)
        .await
        .unwrap();
    assert_eq!(current.as_ref(), Some(&second));
}

#[sqlx::test(migrations = "./migrations")]
async fn allocate_index_returns_zero_first(pool: PgPool) {
    let issuer_id = seeded_issuer(&pool).await;
    let mut conn = pool.acquire().await.unwrap();
    let list_id = status_lists::provision_for_issuer(&mut conn, &issuer_id)
        .await
        .unwrap();

    let allocated = status_lists::allocate_index(&mut conn, &list_id)
        .await
        .unwrap();
    assert_eq!(allocated, Some(StatusListIndex::try_from(0u32).unwrap()));
    assert_eq!(fetch_allocated_count(&pool, &list_id).await, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn allocate_index_hands_out_adjacent_indices(pool: PgPool) {
    let issuer_id = seeded_issuer(&pool).await;
    let mut conn = pool.acquire().await.unwrap();
    let list_id = status_lists::provision_for_issuer(&mut conn, &issuer_id)
        .await
        .unwrap();

    let mut indices: Vec<u32> = Vec::with_capacity(5);
    for _ in 0..5 {
        let allocated = status_lists::allocate_index(&mut conn, &list_id)
            .await
            .unwrap()
            .unwrap();
        indices.push(allocated.value());
    }
    assert_eq!(indices, vec![0, 1, 2, 3, 4]);
}

#[sqlx::test(migrations = "./migrations")]
async fn allocate_index_bumps_committed_version(pool: PgPool) {
    let issuer_id = seeded_issuer(&pool).await;
    let mut conn = pool.acquire().await.unwrap();
    let list_id = status_lists::provision_for_issuer(&mut conn, &issuer_id)
        .await
        .unwrap();
    assert_eq!(fetch_committed_version(&pool, &list_id).await, 0);

    for expected in 1..=3 {
        status_lists::allocate_index(&mut conn, &list_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetch_committed_version(&pool, &list_id).await, expected);
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn allocate_index_returns_none_at_capacity(pool: PgPool) {
    let issuer_id = seeded_issuer(&pool).await;

    // Pre-saturate a list directly so the test does not need to
    // hammer 131 072 allocations.
    let list_id = StatusListId::generate();
    insert_status_list(
        &pool,
        &list_id,
        issuer_id.bare(),
        vec![0u8; BITSTRING_BYTES],
        LIST_CAPACITY as i32,
    )
    .await
    .unwrap();
    let baseline_version = fetch_committed_version(&pool, &list_id).await;

    let mut conn = pool.acquire().await.unwrap();
    let allocated = status_lists::allocate_index(&mut conn, &list_id)
        .await
        .unwrap();
    assert!(
        allocated.is_none(),
        "saturated list must surface as Ok(None)"
    );
    assert_eq!(
        fetch_allocated_count(&pool, &list_id).await,
        LIST_CAPACITY as i32
    );
    assert_eq!(
        fetch_committed_version(&pool, &list_id).await,
        baseline_version,
        "the no-op UPDATE must not bump committed_version"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn allocate_index_returns_none_for_unknown_list(pool: PgPool) {
    let mut conn = pool.acquire().await.unwrap();
    let allocated = status_lists::allocate_index(&mut conn, &StatusListId::generate())
        .await
        .unwrap();
    assert!(allocated.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_allocators_get_distinct_indices(pool: PgPool) {
    // Two transactions racing on the same list must serialise on the
    // row lock and each receive a distinct index. This is the
    // invariant that lets the issuance path skip explicit locking.
    let issuer_id = seeded_issuer(&pool).await;
    let list_id = {
        let mut conn = pool.acquire().await.unwrap();
        status_lists::provision_for_issuer(&mut conn, &issuer_id)
            .await
            .unwrap()
    };

    let pool_a = pool.clone();
    let list_a = list_id.clone();
    let pool_b = pool.clone();
    let list_b = list_id.clone();

    let handle_a = tokio::spawn(async move {
        let mut tx = pool_a.begin().await.unwrap();
        let allocated = status_lists::allocate_index(&mut tx, &list_a)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        allocated.unwrap().value()
    });
    let handle_b = tokio::spawn(async move {
        let mut tx = pool_b.begin().await.unwrap();
        let allocated = status_lists::allocate_index(&mut tx, &list_b)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        allocated.unwrap().value()
    });

    let mut results = vec![handle_a.await.unwrap(), handle_b.await.unwrap()];
    results.sort();
    assert_eq!(results, vec![0, 1]);
    assert_eq!(fetch_allocated_count(&pool, &list_id).await, 2);
    assert_eq!(fetch_committed_version(&pool, &list_id).await, 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn write_bit_flips_target_slot(pool: PgPool) {
    let issuer_id = seeded_issuer(&pool).await;
    let mut conn = pool.acquire().await.unwrap();
    let list_id = status_lists::provision_for_issuer(&mut conn, &issuer_id)
        .await
        .unwrap();

    let target = StatusListIndex::try_from(7u32).unwrap();
    status_lists::write_bit(&mut conn, &list_id, target, StatusValue::Revoked)
        .await
        .unwrap();

    let bitstring = fetch_bitstring(&pool, &list_id).await;
    assert_eq!(
        encoding::read_status(&bitstring, target).unwrap(),
        StatusValue::Revoked
    );
    // Neighbouring slots stay zero (Valid).
    for other in [0u32, 1, 2, 3, 4, 5, 6, 8, 9] {
        let idx = StatusListIndex::try_from(other).unwrap();
        assert_eq!(
            encoding::read_status(&bitstring, idx).unwrap(),
            StatusValue::Valid
        );
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn write_bit_round_trips_each_value(pool: PgPool) {
    let issuer_id = seeded_issuer(&pool).await;
    let mut conn = pool.acquire().await.unwrap();
    let list_id = status_lists::provision_for_issuer(&mut conn, &issuer_id)
        .await
        .unwrap();

    let target = StatusListIndex::try_from(42u32).unwrap();
    for value in [
        StatusValue::Suspended,
        StatusValue::Revoked,
        StatusValue::Valid,
    ] {
        status_lists::write_bit(&mut conn, &list_id, target, value)
            .await
            .unwrap();
        let bitstring = fetch_bitstring(&pool, &list_id).await;
        assert_eq!(encoding::read_status(&bitstring, target).unwrap(), value);
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn write_bit_bumps_committed_version(pool: PgPool) {
    let issuer_id = seeded_issuer(&pool).await;
    let mut conn = pool.acquire().await.unwrap();
    let list_id = status_lists::provision_for_issuer(&mut conn, &issuer_id)
        .await
        .unwrap();

    let baseline = fetch_committed_version(&pool, &list_id).await;
    let target = StatusListIndex::try_from(0u32).unwrap();
    for expected_increment in 1..=3 {
        status_lists::write_bit(&mut conn, &list_id, target, StatusValue::Suspended)
            .await
            .unwrap();
        assert_eq!(
            fetch_committed_version(&pool, &list_id).await,
            baseline + expected_increment
        );
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn write_bit_returns_not_found_for_unknown_list(pool: PgPool) {
    let mut conn = pool.acquire().await.unwrap();
    let result = status_lists::write_bit(
        &mut conn,
        &StatusListId::generate(),
        StatusListIndex::try_from(0u32).unwrap(),
        StatusValue::Revoked,
    )
    .await;
    assert!(matches!(
        result,
        Err(swiyu_issuer::persistence::PersistenceError::NotFound)
    ));
}
