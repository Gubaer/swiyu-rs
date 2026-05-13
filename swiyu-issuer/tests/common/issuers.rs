#![allow(dead_code)] // not every test module pulls in every helper

use chrono::Utc;
use sqlx::PgPool;

use swiyu_issuer::domain::{Issuer, IssuerId, IssuerState, KeyPairId, TenantId};
use swiyu_issuer::persistence;

pub const SAMPLE_DID: &str = "did:tdw:example.com:sample-issuer";
pub const SAMPLE_DISPLAY_NAME: &str = "Sample Issuer";
pub const SAMPLE_DESCRIPTION: &str = "Sample Issuer description";

pub async fn insert(pool: &PgPool, issuer: &Issuer) {
    let mut conn = pool.acquire().await.unwrap();
    persistence::issuers::insert(&mut conn, issuer)
        .await
        .unwrap();
}

/// Baseline `Issuer` fixture for tests. Returns an Active issuer with
/// no SigningEngine keys, a generic DID, and the [`SAMPLE_DISPLAY_NAME`]
/// / [`SAMPLE_DESCRIPTION`] strings. Callers override the fields they
/// actually care about via struct-update syntax:
/// `Issuer { did: "…".into(), ..common::issuers::active(t) }`.
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

/// Like [`active`], but with the SigningEngine key triple populated by
/// freshly generated [`KeyPairId`]s. Use when a test wants a fully-
/// populated active issuer but does not care about the specific key
/// identifiers (worker tests that need real engine-minted keys build
/// their own literal instead).
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

/// Insert an Active issuer with a caller-supplied `IssuerId` and a
/// derived `did:tdw:dev.example.com:{id}`. Used by tests that need to
/// match the issuer id later via a stable handle.
pub async fn insert_test_with_did(pool: &PgPool, tenant_id: &TenantId, issuer_id: &IssuerId) {
    let issuer = Issuer {
        id: issuer_id.clone(),
        did: format!("did:tdw:dev.example.com:{}", issuer_id.bare()),
        display_name: Some("Test Issuer".into()),
        ..active(tenant_id)
    };
    insert(pool, &issuer).await;
}
