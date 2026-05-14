//! Integration tests for `persistence::issuers`.
//!
//! Each test runs against a freshly created Postgres database created
//! by `sqlx::test`; migrations are applied automatically. Requires
//! `DATABASE_URL` to point to a Postgres instance whose user has
//! `CREATEDB` privilege.

use sqlx::PgPool;

use swiyu_issuer::domain::{Issuer, IssuerId, IssuerState, KeyPairId, TenantId};
use swiyu_issuer::persistence::PersistenceError;
use swiyu_issuer::persistence::issuers::{self, SwapOutcome};

use swiyu_issuer::test_support::persistence::issuers as test_issuers;
use swiyu_issuer::test_support::persistence::tenants::insert_test_tenant;

fn legacy_shaped_issuer(tenant_id: &TenantId) -> Issuer {
    Issuer {
        state: None,
        ..test_issuers::active(tenant_id)
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn legacy_shaped_row_round_trips(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer = legacy_shaped_issuer(&tenant_id);

    let mut conn = pool.acquire().await.unwrap();
    issuers::insert(&mut conn, &issuer).await.unwrap();

    let loaded = issuers::find_by_id(&mut conn, &issuer.id)
        .await
        .unwrap()
        .expect("inserted issuer should be found");

    assert_eq!(loaded.id, issuer.id);
    assert_eq!(loaded.tenant_id, issuer.tenant_id);
    assert_eq!(loaded.did, issuer.did);
    assert_eq!(loaded.state, None);
    assert_eq!(loaded.description, issuer.description);
    assert_eq!(loaded.authorized_key_id, None);
    assert_eq!(loaded.authentication_key_id, None);
    assert_eq!(loaded.assertion_key_id, None);
    assert_eq!(loaded.display_name, issuer.display_name);
}

#[sqlx::test(migrations = "./migrations")]
async fn signing_engine_shaped_row_round_trips(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer = test_issuers::active_with_keys(&tenant_id);

    let mut conn = pool.acquire().await.unwrap();
    issuers::insert(&mut conn, &issuer).await.unwrap();

    let loaded = issuers::find_by_id(&mut conn, &issuer.id)
        .await
        .unwrap()
        .expect("inserted issuer should be found");

    assert_eq!(loaded.id, issuer.id);
    assert_eq!(loaded.state, Some(IssuerState::Active));
    assert_eq!(loaded.description, issuer.description);
    assert_eq!(loaded.authorized_key_id, issuer.authorized_key_id);
    assert_eq!(loaded.authentication_key_id, issuer.authentication_key_id);
    assert_eq!(loaded.assertion_key_id, issuer.assertion_key_id);
}

#[sqlx::test(migrations = "./migrations")]
async fn legacy_row_reads_with_no_signing_keys(pool: PgPool) {
    // A "legacy"-shaped row carries state = NULL and NULL across the
    // three `*_key_id` columns. `find_by_id` must surface it as
    // `Some(Issuer)` with `Option` fields set to `None`.
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let legacy = legacy_shaped_issuer(&tenant_id);

    let mut conn = pool.acquire().await.unwrap();
    issuers::insert(&mut conn, &legacy).await.unwrap();
    let loaded = issuers::find_by_id(&mut conn, &legacy.id)
        .await
        .unwrap()
        .expect("legacy issuer should be present");

    assert_eq!(loaded.state, None);
    assert!(loaded.authorized_key_id.is_none());
    assert!(loaded.authentication_key_id.is_none());
    assert!(loaded.assertion_key_id.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn find_by_id_for_update_for_tenant_returns_active_issuer(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer = test_issuers::active_with_keys(&tenant_id);

    let mut conn = pool.acquire().await.unwrap();
    issuers::insert(&mut conn, &issuer).await.unwrap();

    let loaded = issuers::find_by_id_for_update_for_tenant(&mut conn, &tenant_id, &issuer.id)
        .await
        .unwrap()
        .expect("issuer must be visible to its owning tenant");
    assert_eq!(loaded.id, issuer.id);
    assert_eq!(loaded.state, Some(IssuerState::Active));
}

#[sqlx::test(migrations = "./migrations")]
async fn find_by_id_for_update_for_tenant_returns_none_for_cross_tenant(pool: PgPool) {
    let tenant_owner = TenantId::generate();
    let tenant_other = TenantId::generate();
    insert_test_tenant(&pool, &tenant_owner).await;
    insert_test_tenant(&pool, &tenant_other).await;
    let issuer = test_issuers::active_with_keys(&tenant_owner);

    let mut conn = pool.acquire().await.unwrap();
    issuers::insert(&mut conn, &issuer).await.unwrap();

    let result =
        issuers::find_by_id_for_update_for_tenant(&mut conn, &tenant_other, &issuer.id).await;
    assert!(matches!(result, Ok(None)));
}

#[sqlx::test(migrations = "./migrations")]
async fn find_by_id_for_update_for_tenant_returns_none_for_unknown_issuer(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let unknown = IssuerId::generate();

    let mut conn = pool.acquire().await.unwrap();
    let result = issuers::find_by_id_for_update_for_tenant(&mut conn, &tenant_id, &unknown).await;
    assert!(matches!(result, Ok(None)));
}

#[sqlx::test(migrations = "./migrations")]
async fn set_state_persists_deactivated_for_existing_row(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer = test_issuers::active_with_keys(&tenant_id);

    let mut conn = pool.acquire().await.unwrap();
    issuers::insert(&mut conn, &issuer).await.unwrap();

    issuers::set_state(&mut conn, &tenant_id, &issuer.id, IssuerState::Deactivated)
        .await
        .unwrap();

    let loaded = issuers::find_by_id(&mut conn, &issuer.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.state, Some(IssuerState::Deactivated));
}

#[sqlx::test(migrations = "./migrations")]
async fn set_state_returns_not_found_for_unknown_issuer(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let unknown = IssuerId::generate();

    let mut conn = pool.acquire().await.unwrap();
    let result =
        issuers::set_state(&mut conn, &tenant_id, &unknown, IssuerState::Deactivated).await;
    assert!(matches!(result, Err(PersistenceError::NotFound)));
}

#[sqlx::test(migrations = "./migrations")]
async fn exists_for_tenant_is_tenant_scoped(pool: PgPool) {
    let tenant_a = TenantId::generate();
    let tenant_b = TenantId::generate();
    insert_test_tenant(&pool, &tenant_a).await;
    insert_test_tenant(&pool, &tenant_b).await;
    let issuer = legacy_shaped_issuer(&tenant_a);

    let mut conn = pool.acquire().await.unwrap();
    issuers::insert(&mut conn, &issuer).await.unwrap();

    assert!(
        issuers::exists_for_tenant(&mut conn, &tenant_a, &issuer.id)
            .await
            .unwrap()
    );
    assert!(
        !issuers::exists_for_tenant(&mut conn, &tenant_b, &issuer.id)
            .await
            .unwrap()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn swap_key_triple_swaps_active_issuer(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer = test_issuers::active_with_keys(&tenant_id);

    let mut conn = pool.acquire().await.unwrap();
    issuers::insert(&mut conn, &issuer).await.unwrap();

    let new_authorized = KeyPairId::generate();
    let new_authentication = KeyPairId::generate();
    let new_assertion = KeyPairId::generate();

    let outcome = issuers::swap_key_triple(
        &mut conn,
        &tenant_id,
        &issuer.id,
        &new_authorized,
        &new_authentication,
        &new_assertion,
    )
    .await
    .unwrap();
    assert_eq!(outcome, SwapOutcome::NowSwapped);

    let loaded = issuers::find_by_id(&mut conn, &issuer.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.authorized_key_id, Some(new_authorized));
    assert_eq!(loaded.authentication_key_id, Some(new_authentication));
    assert_eq!(loaded.assertion_key_id, Some(new_assertion));
    assert_eq!(loaded.state, Some(IssuerState::Active));
}

#[sqlx::test(migrations = "./migrations")]
async fn swap_key_triple_is_idempotent_when_already_installed(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer = test_issuers::active_with_keys(&tenant_id);

    let mut conn = pool.acquire().await.unwrap();
    issuers::insert(&mut conn, &issuer).await.unwrap();

    // Re-installing the row's existing triple is a no-op that
    // reports `Already`.
    let outcome = issuers::swap_key_triple(
        &mut conn,
        &tenant_id,
        &issuer.id,
        issuer.authorized_key_id.as_ref().unwrap(),
        issuer.authentication_key_id.as_ref().unwrap(),
        issuer.assertion_key_id.as_ref().unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(outcome, SwapOutcome::Already);
}

#[sqlx::test(migrations = "./migrations")]
async fn swap_key_triple_rejects_cross_tenant_caller(pool: PgPool) {
    let tenant_owner = TenantId::generate();
    let tenant_other = TenantId::generate();
    insert_test_tenant(&pool, &tenant_owner).await;
    insert_test_tenant(&pool, &tenant_other).await;
    let issuer = test_issuers::active_with_keys(&tenant_owner);

    let mut conn = pool.acquire().await.unwrap();
    issuers::insert(&mut conn, &issuer).await.unwrap();

    let result = issuers::swap_key_triple(
        &mut conn,
        &tenant_other,
        &issuer.id,
        &KeyPairId::generate(),
        &KeyPairId::generate(),
        &KeyPairId::generate(),
    )
    .await;
    assert!(matches!(result, Err(PersistenceError::NotFound)));

    // Owner-tenant view is unaffected: keys did not change.
    let loaded = issuers::find_by_id(&mut conn, &issuer.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.authorized_key_id, issuer.authorized_key_id);
    assert_eq!(loaded.authentication_key_id, issuer.authentication_key_id);
    assert_eq!(loaded.assertion_key_id, issuer.assertion_key_id);
}

#[sqlx::test(migrations = "./migrations")]
async fn swap_key_triple_rejects_deactivated_issuer(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer = test_issuers::active_with_keys(&tenant_id);

    let mut conn = pool.acquire().await.unwrap();
    issuers::insert(&mut conn, &issuer).await.unwrap();
    issuers::set_state(&mut conn, &tenant_id, &issuer.id, IssuerState::Deactivated)
        .await
        .unwrap();

    let result = issuers::swap_key_triple(
        &mut conn,
        &tenant_id,
        &issuer.id,
        &KeyPairId::generate(),
        &KeyPairId::generate(),
        &KeyPairId::generate(),
    )
    .await;
    assert!(matches!(result, Err(PersistenceError::NotFound)));
}

#[sqlx::test(migrations = "./migrations")]
async fn swap_key_triple_rejects_legacy_state_null_row(pool: PgPool) {
    // A row with state = NULL never started in `Active` and has no
    // Authorized key for the signing step that precedes this UPDATE;
    // the rotate-keys saga must refuse to swap its keys.
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let legacy = legacy_shaped_issuer(&tenant_id);

    let mut conn = pool.acquire().await.unwrap();
    issuers::insert(&mut conn, &legacy).await.unwrap();
    let result = issuers::swap_key_triple(
        &mut conn,
        &tenant_id,
        &legacy.id,
        &KeyPairId::generate(),
        &KeyPairId::generate(),
        &KeyPairId::generate(),
    )
    .await;
    assert!(matches!(result, Err(PersistenceError::NotFound)));
}

#[sqlx::test(migrations = "./migrations")]
async fn swap_key_triple_returns_not_found_for_unknown_issuer(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let unknown = IssuerId::generate();

    let mut conn = pool.acquire().await.unwrap();
    let result = issuers::swap_key_triple(
        &mut conn,
        &tenant_id,
        &unknown,
        &KeyPairId::generate(),
        &KeyPairId::generate(),
        &KeyPairId::generate(),
    )
    .await;
    assert!(matches!(result, Err(PersistenceError::NotFound)));
}

#[sqlx::test(migrations = "./migrations")]
async fn swap_key_triple_swaps_only_one_role(pool: PgPool) {
    // The helper takes a complete triple (caller assembles it), but
    // a single-role rotation passes the unchanged ids through for
    // the other two roles. Verify the row ends up exactly as
    // requested even when only one column actually changes.
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer = test_issuers::active_with_keys(&tenant_id);

    let mut conn = pool.acquire().await.unwrap();
    issuers::insert(&mut conn, &issuer).await.unwrap();

    let new_authentication = KeyPairId::generate();

    let outcome = issuers::swap_key_triple(
        &mut conn,
        &tenant_id,
        &issuer.id,
        issuer.authorized_key_id.as_ref().unwrap(),
        &new_authentication,
        issuer.assertion_key_id.as_ref().unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(outcome, SwapOutcome::NowSwapped);

    let loaded = issuers::find_by_id(&mut conn, &issuer.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.authorized_key_id, issuer.authorized_key_id);
    assert_eq!(loaded.authentication_key_id, Some(new_authentication));
    assert_eq!(loaded.assertion_key_id, issuer.assertion_key_id);
}

#[sqlx::test(migrations = "./migrations")]
async fn fresh_issuer_has_null_current_status_list_id(pool: PgPool) {
    // Lazy-provisioning invariant: a brand-new issuer carries no
    // `current_status_list_id`. The first credential issued for this
    // issuer is what provisions the list and re-points the column.
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer = test_issuers::active_with_keys(&tenant_id);

    let mut conn = pool.acquire().await.unwrap();
    issuers::insert(&mut conn, &issuer).await.unwrap();

    let current: Option<String> =
        sqlx::query_scalar("SELECT current_status_list_id FROM issuers WHERE id = $1")
            .bind(issuer.id.bare())
            .fetch_one(&mut *conn)
            .await
            .unwrap();
    assert!(current.is_none());
}
