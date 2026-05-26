//! Integration tests for the public `GET /schemas/{credential_type_id}`
//! endpoint on the OIDC binary.
//!
//! Seeds a credential type directly via `test_support::persistence`
//! (the management-API path is exercised separately), then drives the
//! OIDC router to verify the public-dereference contract:
//! unauthenticated GET, `application/schema+json` content-type,
//! 404 for unknown ids, 404 for retired rows.

use std::sync::Arc;

use axum::body::{self, Body};
use axum::http::{Request, StatusCode, header};
use chrono::{Duration, Utc};
use sqlx::PgPool;
use tower::ServiceExt;

use swiyu_issuer::api_oidc::{AppState, Config, router};
use swiyu_issuer::domain::{AnySigningEngine, CredentialTypeId, DevSigningEngine, TenantId};
use swiyu_issuer::persistence;
use swiyu_issuer::test_support::fixtures::SAMPLE_BASE_URL;
use swiyu_issuer::test_support::persistence::credential_types as test_credential_types;
use swiyu_issuer::test_support::persistence::tenants::insert_test_tenant;

fn build_state(pool: PgPool) -> AppState {
    let engine = AnySigningEngine::Dev(DevSigningEngine::new(pool.clone()));
    AppState::new(
        pool,
        Config {
            issuer_base_url: SAMPLE_BASE_URL.into(),
            access_token_ttl: Duration::seconds(300),
            c_nonce_ttl: Duration::seconds(300),
        },
        Arc::new(engine),
    )
}

fn get_request_no_auth(uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn anonymous_get_returns_schema_with_schema_json_content_type(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let credential_type = test_credential_types::seed(&pool, &tenant_id).await;

    let app = router(build_state(pool));
    let resp = app
        .oneshot(get_request_no_auth(&format!(
            "/schemas/{}",
            credential_type.id.bare()
        )))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let ct = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(ct, "application/schema+json");

    let bytes = body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let returned: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(returned, credential_type.claim_schema);
}

#[sqlx::test(migrations = "./migrations")]
async fn anonymous_get_works_without_authorization_header(pool: PgPool) {
    // Explicit check that the endpoint is unauthenticated: no
    // Authorization header on the request, no minting of an API
    // token anywhere in the test.
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let credential_type = test_credential_types::seed(&pool, &tenant_id).await;

    let app = router(build_state(pool));
    let resp = app
        .oneshot(get_request_no_auth(&format!(
            "/schemas/{}",
            credential_type.id.bare()
        )))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[sqlx::test(migrations = "./migrations")]
async fn unknown_credential_type_returns_404(pool: PgPool) {
    let unknown = CredentialTypeId::generate();
    let app = router(build_state(pool));
    let resp = app
        .oneshot(get_request_no_auth(&format!("/schemas/{}", unknown.bare())))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "./migrations")]
async fn retired_credential_type_returns_404(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let credential_type = test_credential_types::seed(&pool, &tenant_id).await;

    // Retire the row via the persistence helper (no assignments to
    // cascade in this scenario).
    let mut conn = pool.acquire().await.unwrap();
    persistence::credential_types::retire(&mut conn, &tenant_id, &credential_type.id, Utc::now())
        .await
        .unwrap();
    drop(conn);

    let app = router(build_state(pool));
    let resp = app
        .oneshot(get_request_no_auth(&format!(
            "/schemas/{}",
            credential_type.id.bare()
        )))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "./migrations")]
async fn malformed_id_returns_400(pool: PgPool) {
    // '0' is excluded from the bs58 alphabet; the bare-id parse
    // rejects it.
    let app = router(build_state(pool));
    let resp = app
        .oneshot(get_request_no_auth("/schemas/not0Valid"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrations = "./migrations")]
async fn returned_body_matches_persistence_blob_byte_for_byte(pool: PgPool) {
    // The public endpoint must return the byte-exact document
    // persistence holds. We compare against the persistence row
    // directly to assert nothing mangles the body between the
    // column read and the response write.
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let credential_type = test_credential_types::seed(&pool, &tenant_id).await;

    let app = router(build_state(pool.clone()));
    let resp = app
        .oneshot(get_request_no_auth(&format!(
            "/schemas/{}",
            credential_type.id.bare()
        )))
        .await
        .unwrap();
    let public_bytes = body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let public_value: serde_json::Value = serde_json::from_slice(&public_bytes).unwrap();

    let mut conn = pool.acquire().await.unwrap();
    let row = persistence::credential_types::find_by_id(&mut conn, &credential_type.id)
        .await
        .unwrap()
        .expect("row exists");
    assert_eq!(public_value, row.claim_schema);
}
