//! Integration tests for `persistence::issuers`.
//!
//! Each test runs against a freshly created Postgres database created
//! by `sqlx::test`; migrations are applied automatically. Requires
//! `DATABASE_URL` to point to a Postgres instance whose user has
//! `CREATEDB` privilege.

use chrono::Utc;
use sqlx::PgPool;

use swiyu_issuer::domain::{Issuer, IssuerId, IssuerState, KeyPairId, TenantId};
use swiyu_issuer::persistence::PersistenceError;
use swiyu_issuer::persistence::issuers::{self, MarkOutcome, SwapOutcome};

async fn insert_test_tenant(pool: &PgPool, tenant_id: &TenantId) {
    sqlx::query("INSERT INTO tenants (id) VALUES ($1)")
        .bind(tenant_id.bare())
        .execute(pool)
        .await
        .unwrap();
}

fn legacy_shaped_issuer(tenant_id: TenantId) -> Issuer {
    Issuer {
        id: IssuerId::generate(),
        tenant_id,
        did: "did:tdw:legacy:example.com".into(),
        state: None,
        description: None,
        authorized_key_id: None,
        authentication_key_id: None,
        assertion_key_id: None,
        signing_key_id: Some("legacy-keystore-handle".into()),
        display_name: Some("Legacy Issuer".into()),
        logo_uri: Some("https://example.com/legacy-logo.png".into()),
        locale: Some("en".into()),
        created_at: Utc::now(),
    }
}

fn signing_engine_shaped_issuer(tenant_id: TenantId) -> Issuer {
    Issuer {
        id: IssuerId::generate(),
        tenant_id,
        did: "did:tdw:new:example.com".into(),
        state: Some(IssuerState::Active),
        description: Some("Issuer authority for residence certificates".into()),
        authorized_key_id: Some(KeyPairId::generate()),
        authentication_key_id: Some(KeyPairId::generate()),
        assertion_key_id: Some(KeyPairId::generate()),
        signing_key_id: None,
        display_name: Some("Gemeinde Buchs — Einwohnerverwaltung".into()),
        logo_uri: None,
        locale: None,
        created_at: Utc::now(),
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn legacy_shaped_row_round_trips(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer = legacy_shaped_issuer(tenant_id);

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
    assert_eq!(loaded.description, None);
    assert_eq!(loaded.authorized_key_id, None);
    assert_eq!(loaded.authentication_key_id, None);
    assert_eq!(loaded.assertion_key_id, None);
    assert_eq!(
        loaded.signing_key_id.as_deref(),
        Some("legacy-keystore-handle")
    );
    assert_eq!(loaded.display_name.as_deref(), Some("Legacy Issuer"));
}

#[sqlx::test(migrations = "./migrations")]
async fn signing_engine_shaped_row_round_trips(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer = signing_engine_shaped_issuer(tenant_id);

    let mut conn = pool.acquire().await.unwrap();
    issuers::insert(&mut conn, &issuer).await.unwrap();

    let loaded = issuers::find_by_id(&mut conn, &issuer.id)
        .await
        .unwrap()
        .expect("inserted issuer should be found");

    assert_eq!(loaded.id, issuer.id);
    assert_eq!(loaded.state, Some(IssuerState::Active));
    assert_eq!(
        loaded.description.as_deref(),
        Some("Issuer authority for residence certificates")
    );
    assert_eq!(loaded.authorized_key_id, issuer.authorized_key_id);
    assert_eq!(loaded.authentication_key_id, issuer.authentication_key_id);
    assert_eq!(loaded.assertion_key_id, issuer.assertion_key_id);
    assert!(loaded.signing_key_id.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn seeded_dev_row_reads_with_legacy_shape(pool: PgPool) {
    // Migration 0004 inserts a fixture issuer with id `9hXq2vRtL8pK7f`
    // and a legacy `signing_key_id`. After the issuer-management
    // migration its row stays valid: `signing_key_id` survives, the
    // five new columns are NULL.
    let id = IssuerId::from_bare("9hXq2vRtL8pK7f").unwrap();
    let mut conn = pool.acquire().await.unwrap();
    let loaded = issuers::find_by_id(&mut conn, &id)
        .await
        .unwrap()
        .expect("seeded dev issuer should be present");

    assert_eq!(loaded.state, None);
    assert!(loaded.authorized_key_id.is_none());
    assert!(loaded.signing_key_id.is_some());
}

#[sqlx::test(migrations = "./migrations")]
async fn mark_deactivated_flips_active_issuer(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer = signing_engine_shaped_issuer(tenant_id.clone());

    let mut conn = pool.acquire().await.unwrap();
    issuers::insert(&mut conn, &issuer).await.unwrap();

    let outcome = issuers::mark_deactivated(&mut conn, &tenant_id, &issuer.id)
        .await
        .unwrap();
    assert_eq!(outcome, MarkOutcome::NowDeactivated);

    let loaded = issuers::find_by_id(&mut conn, &issuer.id)
        .await
        .unwrap()
        .expect("issuer must still exist after deactivation");
    assert_eq!(loaded.state, Some(IssuerState::Deactivated));
}

#[sqlx::test(migrations = "./migrations")]
async fn mark_deactivated_is_idempotent_on_resume(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer = signing_engine_shaped_issuer(tenant_id.clone());

    let mut conn = pool.acquire().await.unwrap();
    issuers::insert(&mut conn, &issuer).await.unwrap();

    let first = issuers::mark_deactivated(&mut conn, &tenant_id, &issuer.id)
        .await
        .unwrap();
    let second = issuers::mark_deactivated(&mut conn, &tenant_id, &issuer.id)
        .await
        .unwrap();

    assert_eq!(first, MarkOutcome::NowDeactivated);
    assert_eq!(second, MarkOutcome::Already);
}

#[sqlx::test(migrations = "./migrations")]
async fn mark_deactivated_rejects_cross_tenant_caller(pool: PgPool) {
    let tenant_owner = TenantId::generate();
    let tenant_other = TenantId::generate();
    insert_test_tenant(&pool, &tenant_owner).await;
    insert_test_tenant(&pool, &tenant_other).await;
    let issuer = signing_engine_shaped_issuer(tenant_owner.clone());

    let mut conn = pool.acquire().await.unwrap();
    issuers::insert(&mut conn, &issuer).await.unwrap();

    let result = issuers::mark_deactivated(&mut conn, &tenant_other, &issuer.id).await;
    assert!(matches!(result, Err(PersistenceError::NotFound)));

    // Owner-tenant view is unaffected.
    let loaded = issuers::find_by_id(&mut conn, &issuer.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.state, Some(IssuerState::Active));
}

#[sqlx::test(migrations = "./migrations")]
async fn mark_deactivated_returns_not_found_for_unknown_issuer(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let unknown = IssuerId::generate();

    let mut conn = pool.acquire().await.unwrap();
    let result = issuers::mark_deactivated(&mut conn, &tenant_id, &unknown).await;
    assert!(matches!(result, Err(PersistenceError::NotFound)));
}

#[sqlx::test(migrations = "./migrations")]
async fn mark_deactivated_rejects_legacy_state_null_row(pool: PgPool) {
    // The seeded dev row from migration 0004 has state = NULL. The
    // deactivate saga must refuse to flip that row, since it never
    // started in `Active` and has no Authorized key to sign a
    // deactivation entry with.
    let tenant_id = TenantId::from_bare("4Mk7yK5pQR7sN3").unwrap();
    let legacy_id = IssuerId::from_bare("9hXq2vRtL8pK7f").unwrap();

    let mut conn = pool.acquire().await.unwrap();
    let result = issuers::mark_deactivated(&mut conn, &tenant_id, &legacy_id).await;
    assert!(matches!(result, Err(PersistenceError::NotFound)));
}

#[sqlx::test(migrations = "./migrations")]
async fn exists_for_tenant_is_tenant_scoped(pool: PgPool) {
    let tenant_a = TenantId::generate();
    let tenant_b = TenantId::generate();
    insert_test_tenant(&pool, &tenant_a).await;
    insert_test_tenant(&pool, &tenant_b).await;
    let issuer = legacy_shaped_issuer(tenant_a.clone());

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
    let issuer = signing_engine_shaped_issuer(tenant_id.clone());

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
    let issuer = signing_engine_shaped_issuer(tenant_id.clone());

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
    let issuer = signing_engine_shaped_issuer(tenant_owner.clone());

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
    let issuer = signing_engine_shaped_issuer(tenant_id.clone());

    let mut conn = pool.acquire().await.unwrap();
    issuers::insert(&mut conn, &issuer).await.unwrap();
    issuers::mark_deactivated(&mut conn, &tenant_id, &issuer.id)
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
    // The seeded dev row from migration 0004 has state = NULL. The
    // rotate-keys saga must refuse to swap that row's keys, since it
    // never started in `Active` and has no Authorized key for the
    // signing step that precedes this UPDATE.
    let tenant_id = TenantId::from_bare("4Mk7yK5pQR7sN3").unwrap();
    let legacy_id = IssuerId::from_bare("9hXq2vRtL8pK7f").unwrap();

    let mut conn = pool.acquire().await.unwrap();
    let result = issuers::swap_key_triple(
        &mut conn,
        &tenant_id,
        &legacy_id,
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
    let issuer = signing_engine_shaped_issuer(tenant_id.clone());

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
