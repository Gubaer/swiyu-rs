//! Tests for the `issued_credentials` table and its persistence module.
//!
//! Covers two layers:
//!
//! - **Schema-level** — UNIQUE constraints, FK enforcements, and the
//!   default state value from the migration.
//! - **Persistence functions** — `insert`, `find`, `list`, `set_state`.
//!
//! Each test runs against a freshly created Postgres database created
//! by `sqlx::test`; migrations are applied automatically. Requires
//! `DATABASE_URL` to point to a Postgres instance whose user has
//! `CREATEDB` privilege.

use chrono::{Duration, Utc};
use sqlx::PgPool;

use swiyu_issuer::domain::{
    BITSTRING_BYTES, CredentialOfferId, INTEGRITY_HASH_LEN, IssuedCredential, IssuedCredentialId,
    IssuedCredentialState, IssuerId, StatusListId, StatusListIndex, TenantId,
};
use swiyu_issuer::persistence::{PersistenceError, issued_credentials};

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

// ============================================================================
// Persistence-function tests
// ============================================================================

fn seeded_tenant_id() -> TenantId {
    TenantId::from_bare(SEEDED_DEV_TENANT).unwrap()
}

fn seeded_issuer_id() -> IssuerId {
    IssuerId::from_bare(SEEDED_DEV_ISSUER).unwrap()
}

fn make_credential(
    tenant_id: TenantId,
    issuer_id: IssuerId,
    offer_id: CredentialOfferId,
    list_id: StatusListId,
    list_index: u32,
    issued_at: chrono::DateTime<Utc>,
) -> IssuedCredential {
    IssuedCredential::new(
        tenant_id,
        issuer_id,
        offer_id,
        VCT_SAMPLE.to_string(),
        HOLDER_KEY_JKT_SAMPLE.to_string(),
        list_id,
        StatusListIndex::try_from(list_index).unwrap(),
        [0u8; INTEGRITY_HASH_LEN],
        issued_at,
        issued_at + Duration::days(365),
    )
}

#[sqlx::test(migrations = "./migrations")]
async fn insert_then_find_round_trips(pool: PgPool) {
    let list_id = StatusListId::generate();
    insert_status_list(&pool, &list_id, SEEDED_DEV_ISSUER).await;
    let offer_id = CredentialOfferId::generate();
    insert_credential_offer(&pool, &offer_id, SEEDED_DEV_TENANT, SEEDED_DEV_ISSUER).await;

    let now = Utc::now();
    let credential = make_credential(
        seeded_tenant_id(),
        seeded_issuer_id(),
        offer_id,
        list_id,
        12,
        now,
    );

    let mut conn = pool.acquire().await.unwrap();
    issued_credentials::insert(&mut conn, &credential)
        .await
        .unwrap();

    let loaded = issued_credentials::find(&mut conn, &credential.tenant_id, &credential.id)
        .await
        .unwrap()
        .expect("credential must be findable after insert");
    assert_eq!(loaded.id, credential.id);
    assert_eq!(loaded.tenant_id, credential.tenant_id);
    assert_eq!(loaded.issuer_id, credential.issuer_id);
    assert_eq!(loaded.credential_offer_id, credential.credential_offer_id);
    assert_eq!(loaded.vct, credential.vct);
    assert_eq!(loaded.holder_key_jkt, credential.holder_key_jkt);
    assert_eq!(loaded.status_list_id, credential.status_list_id);
    assert_eq!(loaded.status_list_index, credential.status_list_index);
    assert_eq!(loaded.state, IssuedCredentialState::Active);
    assert_eq!(loaded.integrity_hash, credential.integrity_hash);
}

#[sqlx::test(migrations = "./migrations")]
async fn insert_rejects_duplicate_credential_offer_id(pool: PgPool) {
    // Surface the schema's `UNIQUE (credential_offer_id)` through the
    // persistence layer's typed error.
    let list_id = StatusListId::generate();
    insert_status_list(&pool, &list_id, SEEDED_DEV_ISSUER).await;
    let offer_id = CredentialOfferId::generate();
    insert_credential_offer(&pool, &offer_id, SEEDED_DEV_TENANT, SEEDED_DEV_ISSUER).await;

    let now = Utc::now();
    let first = make_credential(
        seeded_tenant_id(),
        seeded_issuer_id(),
        offer_id.clone(),
        list_id.clone(),
        0,
        now,
    );
    let second = make_credential(
        seeded_tenant_id(),
        seeded_issuer_id(),
        offer_id,
        list_id,
        1,
        now,
    );

    let mut conn = pool.acquire().await.unwrap();
    issued_credentials::insert(&mut conn, &first).await.unwrap();
    let result = issued_credentials::insert(&mut conn, &second).await;
    assert!(matches!(
        result,
        Err(PersistenceError::UniqueViolation { .. })
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn find_returns_none_for_unknown_id(pool: PgPool) {
    let mut conn = pool.acquire().await.unwrap();
    let loaded = issued_credentials::find(
        &mut conn,
        &seeded_tenant_id(),
        &IssuedCredentialId::generate(),
    )
    .await
    .unwrap();
    assert!(loaded.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn find_is_tenant_scoped(pool: PgPool) {
    // A second tenant cannot read another tenant's credential. The
    // wrong-tenant case collapses to the same `Ok(None)` as
    // unknown-id so callers cannot probe across tenants.
    let other_tenant = TenantId::generate();
    sqlx::query("INSERT INTO tenants (id) VALUES ($1)")
        .bind(other_tenant.bare())
        .execute(&pool)
        .await
        .unwrap();

    let list_id = StatusListId::generate();
    insert_status_list(&pool, &list_id, SEEDED_DEV_ISSUER).await;
    let offer_id = CredentialOfferId::generate();
    insert_credential_offer(&pool, &offer_id, SEEDED_DEV_TENANT, SEEDED_DEV_ISSUER).await;

    let credential = make_credential(
        seeded_tenant_id(),
        seeded_issuer_id(),
        offer_id,
        list_id,
        0,
        Utc::now(),
    );
    let mut conn = pool.acquire().await.unwrap();
    issued_credentials::insert(&mut conn, &credential)
        .await
        .unwrap();

    let leaked = issued_credentials::find(&mut conn, &other_tenant, &credential.id)
        .await
        .unwrap();
    assert!(
        leaked.is_none(),
        "cross-tenant lookup must collapse to None"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn set_state_persists_each_lifecycle_state(pool: PgPool) {
    let list_id = StatusListId::generate();
    insert_status_list(&pool, &list_id, SEEDED_DEV_ISSUER).await;
    let offer_id = CredentialOfferId::generate();
    insert_credential_offer(&pool, &offer_id, SEEDED_DEV_TENANT, SEEDED_DEV_ISSUER).await;

    let credential = make_credential(
        seeded_tenant_id(),
        seeded_issuer_id(),
        offer_id,
        list_id,
        0,
        Utc::now(),
    );
    let mut conn = pool.acquire().await.unwrap();
    issued_credentials::insert(&mut conn, &credential)
        .await
        .unwrap();

    for state in [
        IssuedCredentialState::Suspended,
        IssuedCredentialState::Active,
        IssuedCredentialState::Revoked,
    ] {
        issued_credentials::set_state(&mut conn, &credential.tenant_id, &credential.id, state)
            .await
            .unwrap();
        let loaded = issued_credentials::find(&mut conn, &credential.tenant_id, &credential.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded.state, state);
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn set_state_returns_not_found_for_unknown_id(pool: PgPool) {
    let mut conn = pool.acquire().await.unwrap();
    let result = issued_credentials::set_state(
        &mut conn,
        &seeded_tenant_id(),
        &IssuedCredentialId::generate(),
        IssuedCredentialState::Revoked,
    )
    .await;
    assert!(matches!(result, Err(PersistenceError::NotFound)));
}

#[sqlx::test(migrations = "./migrations")]
async fn set_state_is_tenant_scoped(pool: PgPool) {
    // Cross-tenant set_state must report NotFound — same discipline
    // as `find`. Defence against a stolen credential id leaking
    // mutations across tenants.
    let other_tenant = TenantId::generate();
    sqlx::query("INSERT INTO tenants (id) VALUES ($1)")
        .bind(other_tenant.bare())
        .execute(&pool)
        .await
        .unwrap();

    let list_id = StatusListId::generate();
    insert_status_list(&pool, &list_id, SEEDED_DEV_ISSUER).await;
    let offer_id = CredentialOfferId::generate();
    insert_credential_offer(&pool, &offer_id, SEEDED_DEV_TENANT, SEEDED_DEV_ISSUER).await;

    let credential = make_credential(
        seeded_tenant_id(),
        seeded_issuer_id(),
        offer_id,
        list_id,
        0,
        Utc::now(),
    );
    let mut conn = pool.acquire().await.unwrap();
    issued_credentials::insert(&mut conn, &credential)
        .await
        .unwrap();

    let result = issued_credentials::set_state(
        &mut conn,
        &other_tenant,
        &credential.id,
        IssuedCredentialState::Revoked,
    )
    .await;
    assert!(matches!(result, Err(PersistenceError::NotFound)));

    // The original tenant's row must remain unchanged.
    let loaded = issued_credentials::find(&mut conn, &credential.tenant_id, &credential.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.state, IssuedCredentialState::Active);
}

#[sqlx::test(migrations = "./migrations")]
async fn list_returns_rows_newest_first(pool: PgPool) {
    let list_id = StatusListId::generate();
    insert_status_list(&pool, &list_id, SEEDED_DEV_ISSUER).await;

    let mut conn = pool.acquire().await.unwrap();
    let now = Utc::now();
    for offset_minutes in 0..3 {
        let offer_id = CredentialOfferId::generate();
        insert_credential_offer(&pool, &offer_id, SEEDED_DEV_TENANT, SEEDED_DEV_ISSUER).await;
        let credential = make_credential(
            seeded_tenant_id(),
            seeded_issuer_id(),
            offer_id,
            list_id.clone(),
            offset_minutes as u32,
            now + Duration::minutes(offset_minutes),
        );
        issued_credentials::insert(&mut conn, &credential)
            .await
            .unwrap();
    }

    let page = issued_credentials::list(
        &mut conn,
        &seeded_tenant_id(),
        issued_credentials::ListPageQuery {
            filters: issued_credentials::ListFilters::default(),
            cursor: None,
            limit: 10,
        },
    )
    .await
    .unwrap();
    assert_eq!(page.items.len(), 3);
    assert!(!page.has_more);
    let issued_ats: Vec<_> = page.items.iter().map(|c| c.issued_at).collect();
    assert!(
        issued_ats[0] > issued_ats[1] && issued_ats[1] > issued_ats[2],
        "list must return rows in issued_at DESC order: {issued_ats:?}"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn list_filters_by_state(pool: PgPool) {
    let list_id = StatusListId::generate();
    insert_status_list(&pool, &list_id, SEEDED_DEV_ISSUER).await;

    let mut conn = pool.acquire().await.unwrap();
    let now = Utc::now();
    let mut credentials = Vec::new();
    for offset_minutes in 0..3 {
        let offer_id = CredentialOfferId::generate();
        insert_credential_offer(&pool, &offer_id, SEEDED_DEV_TENANT, SEEDED_DEV_ISSUER).await;
        let credential = make_credential(
            seeded_tenant_id(),
            seeded_issuer_id(),
            offer_id,
            list_id.clone(),
            offset_minutes as u32,
            now + Duration::minutes(offset_minutes),
        );
        issued_credentials::insert(&mut conn, &credential)
            .await
            .unwrap();
        credentials.push(credential);
    }

    issued_credentials::set_state(
        &mut conn,
        &seeded_tenant_id(),
        &credentials[0].id,
        IssuedCredentialState::Revoked,
    )
    .await
    .unwrap();

    let page = issued_credentials::list(
        &mut conn,
        &seeded_tenant_id(),
        issued_credentials::ListPageQuery {
            filters: issued_credentials::ListFilters {
                state: Some(IssuedCredentialState::Revoked),
                ..Default::default()
            },
            cursor: None,
            limit: 10,
        },
    )
    .await
    .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].id, credentials[0].id);
}

#[sqlx::test(migrations = "./migrations")]
async fn list_is_tenant_scoped(pool: PgPool) {
    let other_tenant = TenantId::generate();
    sqlx::query("INSERT INTO tenants (id) VALUES ($1)")
        .bind(other_tenant.bare())
        .execute(&pool)
        .await
        .unwrap();

    let list_id = StatusListId::generate();
    insert_status_list(&pool, &list_id, SEEDED_DEV_ISSUER).await;
    let offer_id = CredentialOfferId::generate();
    insert_credential_offer(&pool, &offer_id, SEEDED_DEV_TENANT, SEEDED_DEV_ISSUER).await;

    let credential = make_credential(
        seeded_tenant_id(),
        seeded_issuer_id(),
        offer_id,
        list_id,
        0,
        Utc::now(),
    );
    let mut conn = pool.acquire().await.unwrap();
    issued_credentials::insert(&mut conn, &credential)
        .await
        .unwrap();

    let page = issued_credentials::list(
        &mut conn,
        &other_tenant,
        issued_credentials::ListPageQuery {
            filters: issued_credentials::ListFilters::default(),
            cursor: None,
            limit: 10,
        },
    )
    .await
    .unwrap();
    assert!(page.items.is_empty(), "other tenant must not see the row");
}

#[sqlx::test(migrations = "./migrations")]
async fn list_paginates_with_cursor(pool: PgPool) {
    let list_id = StatusListId::generate();
    insert_status_list(&pool, &list_id, SEEDED_DEV_ISSUER).await;

    let mut conn = pool.acquire().await.unwrap();
    let now = Utc::now();
    for offset_minutes in 0..5 {
        let offer_id = CredentialOfferId::generate();
        insert_credential_offer(&pool, &offer_id, SEEDED_DEV_TENANT, SEEDED_DEV_ISSUER).await;
        let credential = make_credential(
            seeded_tenant_id(),
            seeded_issuer_id(),
            offer_id,
            list_id.clone(),
            offset_minutes as u32,
            now + Duration::minutes(offset_minutes),
        );
        issued_credentials::insert(&mut conn, &credential)
            .await
            .unwrap();
    }

    let first = issued_credentials::list(
        &mut conn,
        &seeded_tenant_id(),
        issued_credentials::ListPageQuery {
            filters: issued_credentials::ListFilters::default(),
            cursor: None,
            limit: 2,
        },
    )
    .await
    .unwrap();
    assert_eq!(first.items.len(), 2);
    assert!(first.has_more);
    let cursor_anchor = first.items.last().unwrap();

    let second = issued_credentials::list(
        &mut conn,
        &seeded_tenant_id(),
        issued_credentials::ListPageQuery {
            filters: issued_credentials::ListFilters::default(),
            cursor: Some((cursor_anchor.issued_at, cursor_anchor.id.bare().to_string())),
            limit: 2,
        },
    )
    .await
    .unwrap();
    assert_eq!(second.items.len(), 2);
    assert!(second.has_more);

    // The two pages must not overlap.
    let first_ids: Vec<_> = first.items.iter().map(|c| c.id.clone()).collect();
    let second_ids: Vec<_> = second.items.iter().map(|c| c.id.clone()).collect();
    for id in &second_ids {
        assert!(!first_ids.contains(id));
    }
}
