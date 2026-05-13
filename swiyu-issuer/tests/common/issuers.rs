#![allow(dead_code)] // not every test module pulls in every helper

use chrono::Utc;
use sqlx::PgPool;

use swiyu_issuer::domain::{Issuer, IssuerId, IssuerState, TenantId};
use swiyu_issuer::persistence;

pub async fn insert(pool: &PgPool, issuer: &Issuer) {
    let mut conn = pool.acquire().await.unwrap();
    persistence::issuers::insert(&mut conn, issuer)
        .await
        .unwrap();
}

/// Baseline `Issuer` fixture for tests. Returns an Active issuer with
/// no SigningEngine keys, a generic DID, and no description. Callers
/// override the fields they actually care about via struct-update
/// syntax: `Issuer { did: "…".into(), ..common::issuers::active(t) }`.
pub fn active(tenant_id: &TenantId) -> Issuer {
    Issuer {
        id: IssuerId::generate(),
        tenant_id: tenant_id.clone(),
        did: "did:tdw:fixture:example.com".into(),
        state: Some(IssuerState::Active),
        description: None,
        authorized_key_id: None,
        authentication_key_id: None,
        assertion_key_id: None,
        display_name: Some("Test issuer".into()),
        logo_uri: None,
        locale: None,
        created_at: Utc::now(),
    }
}
