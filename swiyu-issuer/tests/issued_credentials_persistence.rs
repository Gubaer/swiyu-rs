//! Schema-level tests for the `issued_credentials` table.
//!
//! Persistence-function tests (insert / find / list / set_state) land
//! in the next slice; this file currently exercises only the
//! migration's UNIQUE constraints, FK enforcements, and the default
//! state value. Each test runs against a freshly created Postgres
//! database created by `sqlx::test`; migrations are applied
//! automatically. Requires `DATABASE_URL` to point to a Postgres
//! instance whose user has `CREATEDB` privilege.

use chrono::{Duration, Utc};
use sqlx::PgPool;

use swiyu_issuer::domain::{
    BITSTRING_BYTES, CredentialOfferId, IssuedCredentialId, StatusListId, TenantId,
};

const SEEDED_DEV_TENANT: &str = "4Mk7yK5pQR7sN3";
const SEEDED_DEV_ISSUER: &str = "9hXq2vRtL8pK7f";
const HOLDER_KEY_JKT_SAMPLE: &str = "abcDEF0123456789abcDEF0123456789abcDEF01234";
const VCT_SAMPLE: &str = "urn:communal:local-residence-id";

async fn insert_status_list(pool: &PgPool, list_id: &StatusListId, issuer_id: &str) {
    sqlx::query(
        "INSERT INTO status_lists (id, issuer_id, bitstring, allocated_count) \
         VALUES ($1, $2, $3, 0)",
    )
    .bind(list_id.bare())
    .bind(issuer_id)
    .bind(vec![0u8; BITSTRING_BYTES])
    .execute(pool)
    .await
    .unwrap();
}

async fn insert_credential_offer(
    pool: &PgPool,
    offer_id: &CredentialOfferId,
    tenant_id: &str,
    issuer_id: &str,
) {
    sqlx::query(
        "INSERT INTO credential_offers \
         (id, tenant_id, issuer_id, vct, claims, state, expires_at) \
         VALUES ($1, $2, $3, $4, '{}'::jsonb, 'pending', $5)",
    )
    .bind(offer_id.bare())
    .bind(tenant_id)
    .bind(issuer_id)
    .bind(VCT_SAMPLE)
    .bind(Utc::now() + Duration::days(1))
    .execute(pool)
    .await
    .unwrap();
}

#[allow(clippy::too_many_arguments)]
async fn insert_issued_credential(
    pool: &PgPool,
    credential_id: &IssuedCredentialId,
    tenant_id: &str,
    issuer_id: &str,
    offer_id: &CredentialOfferId,
    list_id: &StatusListId,
    list_index: i32,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    sqlx::query(
        "INSERT INTO issued_credentials \
         (id, tenant_id, issuer_id, credential_offer_id, vct, holder_key_jkt, \
          status_list_id, status_list_index, integrity_hash, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(credential_id.bare())
    .bind(tenant_id)
    .bind(issuer_id)
    .bind(offer_id.bare())
    .bind(VCT_SAMPLE)
    .bind(HOLDER_KEY_JKT_SAMPLE)
    .bind(list_id.bare())
    .bind(list_index)
    .bind(vec![0u8; 32])
    .bind(Utc::now() + Duration::days(365))
    .execute(pool)
    .await
}

#[sqlx::test(migrations = "./migrations")]
async fn well_formed_row_inserts_cleanly(pool: PgPool) {
    let list_id = StatusListId::generate();
    insert_status_list(&pool, &list_id, SEEDED_DEV_ISSUER).await;
    let offer_id = CredentialOfferId::generate();
    insert_credential_offer(&pool, &offer_id, SEEDED_DEV_TENANT, SEEDED_DEV_ISSUER).await;

    insert_issued_credential(
        &pool,
        &IssuedCredentialId::generate(),
        SEEDED_DEV_TENANT,
        SEEDED_DEV_ISSUER,
        &offer_id,
        &list_id,
        0,
    )
    .await
    .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn state_defaults_to_active(pool: PgPool) {
    let list_id = StatusListId::generate();
    insert_status_list(&pool, &list_id, SEEDED_DEV_ISSUER).await;
    let offer_id = CredentialOfferId::generate();
    insert_credential_offer(&pool, &offer_id, SEEDED_DEV_TENANT, SEEDED_DEV_ISSUER).await;

    let credential_id = IssuedCredentialId::generate();
    insert_issued_credential(
        &pool,
        &credential_id,
        SEEDED_DEV_TENANT,
        SEEDED_DEV_ISSUER,
        &offer_id,
        &list_id,
        0,
    )
    .await
    .unwrap();

    let state: String = sqlx::query_scalar("SELECT state FROM issued_credentials WHERE id = $1")
        .bind(credential_id.bare())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(state, "active");
}

#[sqlx::test(migrations = "./migrations")]
async fn duplicate_status_list_index_is_rejected(pool: PgPool) {
    // Two credentials cannot share the same `(status_list_id, index)`
    // pair: the bit-allocation invariant.
    let list_id = StatusListId::generate();
    insert_status_list(&pool, &list_id, SEEDED_DEV_ISSUER).await;

    let first_offer = CredentialOfferId::generate();
    insert_credential_offer(&pool, &first_offer, SEEDED_DEV_TENANT, SEEDED_DEV_ISSUER).await;
    insert_issued_credential(
        &pool,
        &IssuedCredentialId::generate(),
        SEEDED_DEV_TENANT,
        SEEDED_DEV_ISSUER,
        &first_offer,
        &list_id,
        7,
    )
    .await
    .unwrap();

    let second_offer = CredentialOfferId::generate();
    insert_credential_offer(&pool, &second_offer, SEEDED_DEV_TENANT, SEEDED_DEV_ISSUER).await;
    let result = insert_issued_credential(
        &pool,
        &IssuedCredentialId::generate(),
        SEEDED_DEV_TENANT,
        SEEDED_DEV_ISSUER,
        &second_offer,
        &list_id,
        7,
    )
    .await;
    assert!(
        result.is_err(),
        "second credential at same (list, index) must violate UNIQUE"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn same_index_in_different_lists_is_allowed(pool: PgPool) {
    // The UNIQUE is composite: index 0 in two different lists is fine.
    let first_list = StatusListId::generate();
    insert_status_list(&pool, &first_list, SEEDED_DEV_ISSUER).await;
    let second_list = StatusListId::generate();
    insert_status_list(&pool, &second_list, SEEDED_DEV_ISSUER).await;

    let first_offer = CredentialOfferId::generate();
    insert_credential_offer(&pool, &first_offer, SEEDED_DEV_TENANT, SEEDED_DEV_ISSUER).await;
    insert_issued_credential(
        &pool,
        &IssuedCredentialId::generate(),
        SEEDED_DEV_TENANT,
        SEEDED_DEV_ISSUER,
        &first_offer,
        &first_list,
        0,
    )
    .await
    .unwrap();

    let second_offer = CredentialOfferId::generate();
    insert_credential_offer(&pool, &second_offer, SEEDED_DEV_TENANT, SEEDED_DEV_ISSUER).await;
    insert_issued_credential(
        &pool,
        &IssuedCredentialId::generate(),
        SEEDED_DEV_TENANT,
        SEEDED_DEV_ISSUER,
        &second_offer,
        &second_list,
        0,
    )
    .await
    .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn duplicate_credential_offer_id_is_rejected(pool: PgPool) {
    // 1:{0..1} cardinality from CredentialOffer to IssuedCredential:
    // an offer cannot produce two issued credentials.
    let list_id = StatusListId::generate();
    insert_status_list(&pool, &list_id, SEEDED_DEV_ISSUER).await;
    let offer_id = CredentialOfferId::generate();
    insert_credential_offer(&pool, &offer_id, SEEDED_DEV_TENANT, SEEDED_DEV_ISSUER).await;

    insert_issued_credential(
        &pool,
        &IssuedCredentialId::generate(),
        SEEDED_DEV_TENANT,
        SEEDED_DEV_ISSUER,
        &offer_id,
        &list_id,
        0,
    )
    .await
    .unwrap();

    let result = insert_issued_credential(
        &pool,
        &IssuedCredentialId::generate(),
        SEEDED_DEV_TENANT,
        SEEDED_DEV_ISSUER,
        &offer_id,
        &list_id,
        1,
    )
    .await;
    assert!(
        result.is_err(),
        "second credential reusing offer must violate UNIQUE"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn tenant_fk_is_enforced(pool: PgPool) {
    let list_id = StatusListId::generate();
    insert_status_list(&pool, &list_id, SEEDED_DEV_ISSUER).await;
    let offer_id = CredentialOfferId::generate();
    insert_credential_offer(&pool, &offer_id, SEEDED_DEV_TENANT, SEEDED_DEV_ISSUER).await;

    let result = insert_issued_credential(
        &pool,
        &IssuedCredentialId::generate(),
        TenantId::generate().bare(),
        SEEDED_DEV_ISSUER,
        &offer_id,
        &list_id,
        0,
    )
    .await;
    assert!(result.is_err(), "FK to tenants must reject unknown id");
}

#[sqlx::test(migrations = "./migrations")]
async fn issuer_fk_is_enforced(pool: PgPool) {
    let list_id = StatusListId::generate();
    insert_status_list(&pool, &list_id, SEEDED_DEV_ISSUER).await;
    let offer_id = CredentialOfferId::generate();
    insert_credential_offer(&pool, &offer_id, SEEDED_DEV_TENANT, SEEDED_DEV_ISSUER).await;

    let result = insert_issued_credential(
        &pool,
        &IssuedCredentialId::generate(),
        SEEDED_DEV_TENANT,
        "nonexistentissu",
        &offer_id,
        &list_id,
        0,
    )
    .await;
    assert!(result.is_err(), "FK to issuers must reject unknown id");
}

#[sqlx::test(migrations = "./migrations")]
async fn credential_offer_fk_is_enforced(pool: PgPool) {
    let list_id = StatusListId::generate();
    insert_status_list(&pool, &list_id, SEEDED_DEV_ISSUER).await;

    let result = insert_issued_credential(
        &pool,
        &IssuedCredentialId::generate(),
        SEEDED_DEV_TENANT,
        SEEDED_DEV_ISSUER,
        &CredentialOfferId::generate(),
        &list_id,
        0,
    )
    .await;
    assert!(
        result.is_err(),
        "FK to credential_offers must reject unknown id"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn status_list_fk_is_enforced(pool: PgPool) {
    let offer_id = CredentialOfferId::generate();
    insert_credential_offer(&pool, &offer_id, SEEDED_DEV_TENANT, SEEDED_DEV_ISSUER).await;

    let result = insert_issued_credential(
        &pool,
        &IssuedCredentialId::generate(),
        SEEDED_DEV_TENANT,
        SEEDED_DEV_ISSUER,
        &offer_id,
        &StatusListId::generate(),
        0,
    )
    .await;
    assert!(result.is_err(), "FK to status_lists must reject unknown id");
}
