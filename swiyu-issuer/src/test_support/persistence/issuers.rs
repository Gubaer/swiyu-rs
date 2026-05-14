use chrono::Utc;
use sqlx::PgPool;

use crate::domain::{
    DevSigningEngine, Issuer, IssuerId, IssuerState, KeyPairId, KeyRole, SigningEngine, TenantId,
};
use crate::persistence;
use crate::test_support::fixtures::{SAMPLE_DESCRIPTION, SAMPLE_DID, SAMPLE_DISPLAY_NAME};
use crate::test_support::registry::identifier::fixture_did;
use crate::test_support::time::now_micros;

pub async fn insert(pool: &PgPool, issuer: &Issuer) {
    let mut conn = pool.acquire().await.unwrap();
    persistence::issuers::insert(&mut conn, issuer)
        .await
        .unwrap();
}

pub fn active(tenant_id: &TenantId) -> Issuer {
    Issuer {
        id: IssuerId::generate(),
        tenant_id: tenant_id.clone(),
        did: SAMPLE_DID.into(),
        state: Some(IssuerState::Active),
        description: Some(SAMPLE_DESCRIPTION.into()),
        authorized_key_id: None,
        authentication_key_id: None,
        assertion_key_id: None,
        display_name: Some(SAMPLE_DISPLAY_NAME.into()),
        logo_uri: None,
        locale: None,
        created_at: Utc::now(),
    }
}

pub fn active_with_keys(tenant_id: &TenantId) -> Issuer {
    Issuer {
        authorized_key_id: Some(KeyPairId::generate()),
        authentication_key_id: Some(KeyPairId::generate()),
        assertion_key_id: Some(KeyPairId::generate()),
        ..active(tenant_id)
    }
}

pub async fn insert_active(pool: &PgPool, tenant_id: &TenantId) -> Issuer {
    let issuer = active(tenant_id);
    insert(pool, &issuer).await;
    issuer
}

pub async fn insert_active_with_keys(pool: &PgPool, tenant_id: &TenantId) -> Issuer {
    let issuer = active_with_keys(tenant_id);
    insert(pool, &issuer).await;
    issuer
}

pub async fn insert_active_with_engine_keys(
    pool: &PgPool,
    tenant_id: &TenantId,
) -> (Issuer, DevSigningEngine) {
    let engine = DevSigningEngine::new(pool.clone());
    let authorized = engine.generate_keypair(KeyRole::Authorized).await.unwrap();
    let authentication = engine
        .generate_keypair(KeyRole::Authentication)
        .await
        .unwrap();
    let assertion = engine.generate_keypair(KeyRole::Assertion).await.unwrap();

    let issuer = Issuer {
        did: fixture_did(),
        authorized_key_id: Some(authorized.id),
        authentication_key_id: Some(authentication.id),
        assertion_key_id: Some(assertion.id),
        created_at: now_micros(),
        ..active(tenant_id)
    };
    insert(pool, &issuer).await;
    (issuer, engine)
}

pub async fn insert_test_with_did(pool: &PgPool, tenant_id: &TenantId, issuer_id: &IssuerId) {
    let issuer = Issuer {
        id: issuer_id.clone(),
        did: format!("did:tdw:dev.example.com:{}", issuer_id.bare()),
        display_name: Some("Test Issuer".into()),
        ..active(tenant_id)
    };
    insert(pool, &issuer).await;
}
