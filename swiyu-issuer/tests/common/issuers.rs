#![allow(dead_code)] // not every test module pulls in every helper

use chrono::Utc;
use sqlx::PgPool;

use swiyu_issuer::domain::{Issuer, IssuerId, IssuerState, KeyPairId, TenantId};
use swiyu_issuer::persistence;

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
        did: "did:tdw:fixture:example.com".into(),
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
