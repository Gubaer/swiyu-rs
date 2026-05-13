//! Integration tests for `persistence::credential_offers`.
//!
//! Each test runs against a freshly created Postgres database via
//! `sqlx::test`; migrations apply automatically. Requires
//! `DATABASE_URL` to point to a Postgres instance whose user has
//! `CREATEDB` privilege.

use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use sqlx::PgPool;

use swiyu_issuer::domain::{
    CredentialOffer, CredentialOfferState, Issuer, IssuerId, PreAuthCode, TenantId,
};
use swiyu_issuer::persistence::credential_offers;
use swiyu_issuer::persistence::oidc::credential_offers as oidc_credential_offers;

#[path = "common/mod.rs"]
mod common;
use common::tenants::insert_test_tenant;

async fn insert_test_issuer(pool: &PgPool, tenant_id: &TenantId) -> IssuerId {
    let issuer = Issuer {
        display_name: Some("Fixture issuer".into()),
        ..common::issuers::active_with_keys(tenant_id)
    };
    let id = issuer.id.clone();
    common::issuers::insert(pool, &issuer).await;
    id
}

/// Postgres `TIMESTAMPTZ` keeps microsecond precision. `Utc::now()`
/// produces nanoseconds, which round-trip through the database as
/// truncated values and break direct equality assertions on what the
/// caller passed in. Tests round to microseconds up front so the
/// asserted timestamp is exactly what the row will hold.
fn now_with_postgres_precision() -> DateTime<Utc> {
    let micros = Utc::now().timestamp_micros();
    DateTime::from_timestamp_micros(micros).unwrap()
}

fn pending_offer(tenant_id: &TenantId, issuer_id: &IssuerId) -> CredentialOffer {
    CredentialOffer::new(
        tenant_id.clone(),
        issuer_id.clone(),
        "https://example.com/vct/test".into(),
        json!({"first_name": "Anna"}),
        PreAuthCode::generate(),
        Utc::now() + Duration::hours(1),
    )
}

#[sqlx::test(migrations = "./migrations")]
async fn cancel_all_pending_flips_only_pending_offers(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer_id = insert_test_issuer(&pool, &tenant_id).await;

    let mut conn = pool.acquire().await.unwrap();

    let pending_a = pending_offer(&tenant_id, &issuer_id);
    let pending_b = pending_offer(&tenant_id, &issuer_id);

    let mut already_issued = pending_offer(&tenant_id, &issuer_id);
    already_issued.state = CredentialOfferState::Issued;
    already_issued.issued_at = Some(now_with_postgres_precision());
    already_issued.pre_auth_code = None;

    let mut already_cancelled = pending_offer(&tenant_id, &issuer_id);
    already_cancelled.state = CredentialOfferState::Cancelled;
    already_cancelled.cancelled_at = Some(now_with_postgres_precision());
    already_cancelled.pre_auth_code = None;

    for offer in [&pending_a, &pending_b, &already_issued, &already_cancelled] {
        credential_offers::insert(&mut conn, offer).await.unwrap();
    }

    let now = now_with_postgres_precision();
    let cancelled =
        credential_offers::cancel_all_pending_for_issuer(&mut conn, &tenant_id, &issuer_id, now)
            .await
            .unwrap();
    assert_eq!(cancelled, 2);

    let loaded_a = credential_offers::find_by_id(&mut conn, &tenant_id, &issuer_id, &pending_a.id)
        .await
        .unwrap();
    assert_eq!(loaded_a.state, CredentialOfferState::Cancelled);
    assert_eq!(loaded_a.cancelled_at, Some(now));
    assert!(loaded_a.pre_auth_code.is_none());

    let loaded_b = credential_offers::find_by_id(&mut conn, &tenant_id, &issuer_id, &pending_b.id)
        .await
        .unwrap();
    assert_eq!(loaded_b.state, CredentialOfferState::Cancelled);

    // Issued offers stay Issued.
    let loaded_issued =
        credential_offers::find_by_id(&mut conn, &tenant_id, &issuer_id, &already_issued.id)
            .await
            .unwrap();
    assert_eq!(loaded_issued.state, CredentialOfferState::Issued);
    assert_eq!(loaded_issued.issued_at, already_issued.issued_at);
    assert!(loaded_issued.pre_auth_code.is_none());

    // Cancelled offers keep their original cancelled_at — the bulk cancel
    // does not reset the timestamp on rows that are already cancelled.
    let loaded_cancelled =
        credential_offers::find_by_id(&mut conn, &tenant_id, &issuer_id, &already_cancelled.id)
            .await
            .unwrap();
    assert_eq!(loaded_cancelled.state, CredentialOfferState::Cancelled);
    assert_eq!(
        loaded_cancelled.cancelled_at,
        already_cancelled.cancelled_at
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn cancel_all_pending_is_idempotent_on_rerun(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer_id = insert_test_issuer(&pool, &tenant_id).await;

    let mut conn = pool.acquire().await.unwrap();

    let pending = pending_offer(&tenant_id, &issuer_id);
    credential_offers::insert(&mut conn, &pending)
        .await
        .unwrap();

    let now = Utc::now();
    let first =
        credential_offers::cancel_all_pending_for_issuer(&mut conn, &tenant_id, &issuer_id, now)
            .await
            .unwrap();
    let second =
        credential_offers::cancel_all_pending_for_issuer(&mut conn, &tenant_id, &issuer_id, now)
            .await
            .unwrap();

    assert_eq!(first, 1);
    assert_eq!(second, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn cancel_all_pending_returns_zero_when_no_pending_offers(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer_id = insert_test_issuer(&pool, &tenant_id).await;

    let mut conn = pool.acquire().await.unwrap();
    let cancelled = credential_offers::cancel_all_pending_for_issuer(
        &mut conn,
        &tenant_id,
        &issuer_id,
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(cancelled, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn cancel_all_pending_does_not_touch_other_tenants(pool: PgPool) {
    let tenant_owner = TenantId::generate();
    let tenant_other = TenantId::generate();
    insert_test_tenant(&pool, &tenant_owner).await;
    insert_test_tenant(&pool, &tenant_other).await;
    let issuer_owner = insert_test_issuer(&pool, &tenant_owner).await;
    let issuer_other = insert_test_issuer(&pool, &tenant_other).await;

    let mut conn = pool.acquire().await.unwrap();

    let owner_offer = pending_offer(&tenant_owner, &issuer_owner);
    let other_offer = pending_offer(&tenant_other, &issuer_other);
    credential_offers::insert(&mut conn, &owner_offer)
        .await
        .unwrap();
    credential_offers::insert(&mut conn, &other_offer)
        .await
        .unwrap();

    // Caller from `tenant_owner` deactivating issuer_owner must leave
    // tenant_other's offer alone, even though we feed in a deliberately
    // mismatched (tenant_other, issuer_owner) pair to test the AND-guard
    // — that combination matches no rows.
    let cross = credential_offers::cancel_all_pending_for_issuer(
        &mut conn,
        &tenant_other,
        &issuer_owner,
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(cross, 0);

    let loaded_owner =
        credential_offers::find_by_id(&mut conn, &tenant_owner, &issuer_owner, &owner_offer.id)
            .await
            .unwrap();
    assert_eq!(loaded_owner.state, CredentialOfferState::Pending);
    let loaded_other =
        credential_offers::find_by_id(&mut conn, &tenant_other, &issuer_other, &other_offer.id)
            .await
            .unwrap();
    assert_eq!(loaded_other.state, CredentialOfferState::Pending);
}

#[sqlx::test(migrations = "./migrations")]
async fn cancel_all_pending_does_not_touch_other_issuers(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer_target = insert_test_issuer(&pool, &tenant_id).await;
    let issuer_bystander = insert_test_issuer(&pool, &tenant_id).await;

    let mut conn = pool.acquire().await.unwrap();

    let target_offer = pending_offer(&tenant_id, &issuer_target);
    let bystander_offer = pending_offer(&tenant_id, &issuer_bystander);
    credential_offers::insert(&mut conn, &target_offer)
        .await
        .unwrap();
    credential_offers::insert(&mut conn, &bystander_offer)
        .await
        .unwrap();

    let cancelled = credential_offers::cancel_all_pending_for_issuer(
        &mut conn,
        &tenant_id,
        &issuer_target,
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(cancelled, 1);

    let loaded_target =
        credential_offers::find_by_id(&mut conn, &tenant_id, &issuer_target, &target_offer.id)
            .await
            .unwrap();
    assert_eq!(loaded_target.state, CredentialOfferState::Cancelled);

    let loaded_bystander = credential_offers::find_by_id(
        &mut conn,
        &tenant_id,
        &issuer_bystander,
        &bystander_offer.id,
    )
    .await
    .unwrap();
    assert_eq!(loaded_bystander.state, CredentialOfferState::Pending);
    assert!(loaded_bystander.pre_auth_code.is_some());
}

#[sqlx::test(migrations = "./migrations")]
async fn find_by_id_for_update_then_set_issued_state_marks_issued(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer_id = insert_test_issuer(&pool, &tenant_id).await;

    let offer = pending_offer(&tenant_id, &issuer_id);
    {
        let mut conn = pool.acquire().await.unwrap();
        credential_offers::insert(&mut conn, &offer).await.unwrap();
    }

    let now = now_with_postgres_precision();
    let mut tx = pool.begin().await.unwrap();
    let mut found =
        oidc_credential_offers::find_by_id_for_update(&mut tx, &tenant_id, &issuer_id, &offer.id)
            .await
            .unwrap();
    assert_eq!(found.state, CredentialOfferState::Pending);

    // Mirror what the handler does: drive the in-memory transition,
    // then persist via set_issued_state.
    found.try_issue(now).unwrap();
    oidc_credential_offers::set_issued_state(&mut tx, &found)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let mut conn = pool.acquire().await.unwrap();
    let loaded = credential_offers::find_by_id(&mut conn, &tenant_id, &issuer_id, &offer.id)
        .await
        .unwrap();
    assert_eq!(loaded.state, CredentialOfferState::Issued);
    assert_eq!(loaded.issued_at, Some(now));
    assert!(loaded.pre_auth_code.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn find_by_id_for_update_blocks_concurrent_writer(pool: PgPool) {
    // Two transactions both call find_by_id_for_update against the
    // same offer. The first holds the lock; the second's lock
    // request must not return until the first commits, so we drive
    // the second through a tokio timeout to prove it's blocked, then
    // release the first and confirm the second sees the new state.
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer_id = insert_test_issuer(&pool, &tenant_id).await;

    let offer = pending_offer(&tenant_id, &issuer_id);
    {
        let mut conn = pool.acquire().await.unwrap();
        credential_offers::insert(&mut conn, &offer).await.unwrap();
    }

    let now = now_with_postgres_precision();

    let mut tx_a = pool.begin().await.unwrap();
    let mut found_a =
        oidc_credential_offers::find_by_id_for_update(&mut tx_a, &tenant_id, &issuer_id, &offer.id)
            .await
            .unwrap();

    // While tx_a holds the lock, tx_b's locked SELECT must block.
    let pool_b = pool.clone();
    let tenant_id_b = tenant_id.clone();
    let issuer_id_b = issuer_id.clone();
    let offer_id_b = offer.id.clone();
    let mut tx_b_handle = tokio::spawn(async move {
        let mut tx_b = pool_b.begin().await.unwrap();
        let found_b = oidc_credential_offers::find_by_id_for_update(
            &mut tx_b,
            &tenant_id_b,
            &issuer_id_b,
            &offer_id_b,
        )
        .await
        .unwrap();
        (tx_b, found_b)
    });
    let timed_out =
        tokio::time::timeout(std::time::Duration::from_millis(200), &mut tx_b_handle).await;
    assert!(
        timed_out.is_err(),
        "second transaction must block while tx_a holds the lock"
    );

    // tx_a issues the offer and commits, releasing the lock.
    found_a.try_issue(now).unwrap();
    oidc_credential_offers::set_issued_state(&mut tx_a, &found_a)
        .await
        .unwrap();
    tx_a.commit().await.unwrap();

    // tx_b now resolves and sees the new state.
    let (_tx_b, found_b) = tx_b_handle.await.unwrap();
    assert_eq!(found_b.state, CredentialOfferState::Issued);
    assert_eq!(found_b.issued_at, Some(now));
    assert!(found_b.pre_auth_code.is_none());
}
