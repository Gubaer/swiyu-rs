//! Integration tests for `GET /api/v1/issuers/{issuer_id}`.
//!
//! Drives requests through the full management router (auth +
//! extractors + serde + handler + persistence) using
//! `tower::ServiceExt::oneshot` against a `sqlx::test`-managed pool.

use axum::http::StatusCode;
use sqlx::PgPool;
use tower::ServiceExt;

use swiyu_issuer::api_management::router;
use swiyu_issuer::domain::{ApiTokenSecret, Issuer, IssuerId, TenantId};

#[path = "common/mod.rs"]
mod common;
use common::api_tokens::mint_test_token;
use common::app_state::build_state;
use common::http::{get_request, read_body};
use common::tenants::insert_test_tenant;

#[sqlx::test(migrations = "./migrations")]
async fn happy_path_returns_target_shape_dto(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let secret = mint_test_token(&pool, &tenant_id).await;
    let issuer = common::issuers::active_with_keys(&tenant_id);
    common::issuers::insert(&pool, &issuer).await;

    let app = router(build_state(pool.clone()));
    let response = app
        .oneshot(get_request(
            &format!("/api/v1/issuers/{}", issuer.id.bare()),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = read_body(response).await;
    assert_eq!(body["id"], issuer.id.bare());
    assert_eq!(body["did"], "did:tdw:example.com:9hXq2vRtL8pK7f");
    assert_eq!(body["state"], "active");
    assert_eq!(body["description"], common::issuers::SAMPLE_DESCRIPTION);
    assert_eq!(body["display_name"], common::issuers::SAMPLE_DISPLAY_NAME);
    // tenant_id and the three SigningEngine key-pair handles are
    // deliberately not exposed on the wire.
    assert!(body.get("tenant_id").is_none());
    assert!(body.get("authorized_key_id").is_none());
    assert!(body.get("authentication_key_id").is_none());
    assert!(body.get("assertion_key_id").is_none());
    // Legacy presentation fields must not leak into the wire shape
    // either.
    assert!(body.get("logo_uri").is_none());
    assert!(body.get("locale").is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn returns_404_for_unknown_issuer(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let secret = mint_test_token(&pool, &tenant_id).await;

    let app = router(build_state(pool));
    let unknown = IssuerId::generate();
    let response = app
        .oneshot(get_request(
            &format!("/api/v1/issuers/{}", unknown.bare()),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = read_body(response).await;
    assert_eq!(body["error"], "not_found");
}

#[sqlx::test(migrations = "./migrations")]
async fn returns_404_for_cross_tenant_issuer(pool: PgPool) {
    let tenant_a = TenantId::generate();
    let tenant_b = TenantId::generate();
    insert_test_tenant(&pool, &tenant_a).await;
    insert_test_tenant(&pool, &tenant_b).await;
    // Issuer belongs to tenant_a; the bearer token is tenant_b's.
    let issuer = common::issuers::active_with_keys(&tenant_a);
    common::issuers::insert(&pool, &issuer).await;
    let secret = mint_test_token(&pool, &tenant_b).await;

    let app = router(build_state(pool));
    let response = app
        .oneshot(get_request(
            &format!("/api/v1/issuers/{}", issuer.id.bare()),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = read_body(response).await;
    assert_eq!(body["error"], "not_found");
}

#[sqlx::test(migrations = "./migrations")]
async fn returns_404_for_legacy_issuer(pool: PgPool) {
    // A row that lacks state and the SigningEngine key triple
    // represents a half-provisioned issuer; the handler hides such
    // rows from the v1 surface.
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let secret = mint_test_token(&pool, &tenant_id).await;
    let issuer = Issuer {
        did: "did:tdw:example.com:legacy".into(),
        state: None,
        ..common::issuers::active(&tenant_id)
    };
    common::issuers::insert(&pool, &issuer).await;

    let app = router(build_state(pool));
    let response = app
        .oneshot(get_request(
            &format!("/api/v1/issuers/{}", issuer.id.bare()),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = read_body(response).await;
    assert_eq!(body["error"], "not_found");
}

#[sqlx::test(migrations = "./migrations")]
async fn returns_400_for_malformed_issuer_id(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let secret = mint_test_token(&pool, &tenant_id).await;

    let app = router(build_state(pool));
    // 'O' (capital o) is outside the bs58 alphabet, so the bare
    // id fails validation in the handler.
    let response = app
        .oneshot(get_request(
            "/api/v1/issuers/notVal0d",
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = read_body(response).await;
    assert_eq!(body["error"], "invalid_input");
}

#[sqlx::test(migrations = "./migrations")]
async fn rejects_request_without_authorization(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer = common::issuers::active_with_keys(&tenant_id);
    common::issuers::insert(&pool, &issuer).await;

    let app = router(build_state(pool));
    let response = app
        .oneshot(get_request(
            &format!("/api/v1/issuers/{}", issuer.id.bare()),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "./migrations")]
async fn rejects_unknown_bearer_token(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer = common::issuers::active_with_keys(&tenant_id);
    common::issuers::insert(&pool, &issuer).await;

    let app = router(build_state(pool));
    let bogus = ApiTokenSecret::generate();
    let response = app
        .oneshot(get_request(
            &format!("/api/v1/issuers/{}", issuer.id.bare()),
            Some(&bogus.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
