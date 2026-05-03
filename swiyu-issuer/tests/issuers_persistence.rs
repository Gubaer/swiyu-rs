//! Integration tests for `persistence::issuers`.
//!
//! Each test runs against a freshly created Postgres database created
//! by `sqlx::test`; migrations are applied automatically. Requires
//! `DATABASE_URL` to point to a Postgres instance whose user has
//! `CREATEDB` privilege.

use sqlx::PgPool;

use swiyu_issuer::domain::{Issuer, IssuerId, IssuerState, KeyPairId, TenantId};
use swiyu_issuer::persistence::issuers;

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
        did: "did:tdw:example.com:legacy".into(),
        state: None,
        description: None,
        authorized_key_id: None,
        authentication_key_id: None,
        assertion_key_id: None,
        signing_key_id: Some("legacy-keystore-handle".into()),
        display_name: Some("Legacy Issuer".into()),
        logo_uri: Some("https://example.com/legacy-logo.png".into()),
        locale: Some("en".into()),
    }
}

fn signing_engine_shaped_issuer(tenant_id: TenantId) -> Issuer {
    Issuer {
        id: IssuerId::generate(),
        tenant_id,
        did: "did:tdw:example.com:new".into(),
        state: Some(IssuerState::Active),
        description: Some("Issuer authority for residence certificates".into()),
        authorized_key_id: Some(KeyPairId::generate()),
        authentication_key_id: Some(KeyPairId::generate()),
        assertion_key_id: Some(KeyPairId::generate()),
        signing_key_id: None,
        display_name: Some("Gemeinde Buchs — Einwohnerverwaltung".into()),
        logo_uri: None,
        locale: None,
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
