use chrono::Utc;
use sqlx::PgPool;
use swiyu_core::statuslist::{SWIYU_STATUS_LIST_BITS, StatusList as CoreStatusList};

use crate::domain::{
    AnySecretEncryptionEngine, DevSigningEngine, Issuer, IssuerId, KeyRole, SigningEngine,
    StatusList, StatusListId, StatusListIndex, StatusValue, TenantId,
};
use crate::persistence;
use crate::test_support::fixtures::SAMPLE_STATUS_ENTRY_ID;
use crate::test_support::oauth::insert_test_tenant_with_oauth;

use super::issuers::active;

pub fn read_slot(bitstring: &[u8], idx: StatusListIndex) -> StatusValue {
    CoreStatusList::from_raw(SWIYU_STATUS_LIST_BITS, bitstring.to_vec())
        .unwrap()
        .value_at(u64::from(idx.value()))
        .unwrap()
}

pub async fn fetch_publish_state(pool: &PgPool, list_id: &StatusListId) -> (i64, i64, i32) {
    sqlx::query_as::<_, (i64, i64, i32)>(
        "SELECT published_version, committed_version, publish_attempts \
         FROM status_lists WHERE id = $1",
    )
    .bind(list_id.bare())
    .fetch_one(pool)
    .await
    .unwrap()
}

pub async fn provision(pool: &PgPool, issuer_id: &IssuerId) -> StatusListId {
    let mut conn = pool.acquire().await.unwrap();
    persistence::status_lists::provision_for_issuer(&mut conn, issuer_id, None, None)
        .await
        .unwrap()
}

pub async fn seed_dirty_environment(
    pool: &PgPool,
    secret_engine: &AnySecretEncryptionEngine,
    registry_url: &str,
) -> (Issuer, StatusList, DevSigningEngine) {
    let tenant_id = TenantId::generate();
    insert_test_tenant_with_oauth(pool, &tenant_id, secret_engine).await;

    let engine = DevSigningEngine::new(pool.clone());
    let assertion = engine.generate_keypair(KeyRole::Assertion).await.unwrap();

    let issuer = Issuer {
        assertion_key_id: Some(assertion.id),
        ..active(&tenant_id)
    };
    let mut conn = pool.acquire().await.unwrap();
    persistence::issuers::insert(&mut conn, &issuer)
        .await
        .unwrap();
    let list_id = persistence::status_lists::provision_for_issuer(
        &mut conn,
        &issuer.id,
        Some(SAMPLE_STATUS_ENTRY_ID),
        Some(registry_url),
    )
    .await
    .unwrap();

    persistence::status_lists::write_bit(
        &mut conn,
        &list_id,
        StatusListIndex::try_from(0u32).unwrap(),
        StatusValue::Revoked,
    )
    .await
    .unwrap();
    drop(conn);

    let mut conn = pool.acquire().await.unwrap();
    let acquired = persistence::status_lists::acquire_next_dirty(
        &mut conn,
        Utc::now(),
        chrono::Duration::seconds(30),
    )
    .await
    .unwrap()
    .expect("dirty list is acquirable");

    (issuer, acquired, engine)
}
