//! Integration tests for `GET /api/v1/issuers/{issuer_id}`.
//!
//! Drives requests through the full management router (auth +
//! extractors + serde + handler + persistence) using
//! `tower::ServiceExt::oneshot` against a `sqlx::test`-managed pool.

use axum::body::{self, Body};
use axum::http::{Request, StatusCode, header};
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;

use swiyu_issuer::api_management::{AppState, Config, router};
use swiyu_issuer::domain::{
    ApiToken, ApiTokenSecret, Issuer, IssuerId, IssuerState, KeyPairId, TenantId,
};
use swiyu_issuer::persistence;

const TEST_BASE_URL: &str = "http://localhost:8080";

// IDs hard-coded by migration 0001 / 0004. Reproduced here so the tests
// covering the seeded-legacy filter do not need to query the DB to learn
// what they are.
const SEEDED_TENANT_BARE: &str = "4Mk7yK5pQR7sN3";
const SEEDED_ISSUER_BARE: &str = "9hXq2vRtL8pK7f";

async fn build_state(pool: PgPool) -> AppState {
    AppState::new(
        pool,
        Config {
            issuer_base_url: TEST_BASE_URL.into(),
        },
    )
    .expect("AppState builds")
}

async fn insert_test_tenant(pool: &PgPool, tenant_id: &TenantId) {
    sqlx::query("INSERT INTO tenants (id, partner_id) VALUES ($1, NULL)")
        .bind(tenant_id.bare())
        .execute(pool)
        .await
        .unwrap();
}

async fn mint_test_token(pool: &PgPool, tenant_id: &TenantId) -> ApiTokenSecret {
    let secret = ApiTokenSecret::generate();
    let token = ApiToken::new(tenant_id.clone(), "test-token".into(), secret.hash(), None);
    let mut conn = pool.acquire().await.unwrap();
    persistence::api_tokens::insert(&mut conn, &token)
        .await
        .unwrap();
    secret
}

fn target_shape_issuer(tenant_id: TenantId) -> Issuer {
    Issuer {
        id: IssuerId::generate(),
        tenant_id,
        did: "did:tdw:example.com:9hXq2vRtL8pK7f".into(),
        state: Some(IssuerState::Active),
        description: Some("Cantonal driver-licence issuer".into()),
        authorized_key_id: Some(KeyPairId::generate()),
        authentication_key_id: Some(KeyPairId::generate()),
        assertion_key_id: Some(KeyPairId::generate()),
        signing_key_id: None,
        display_name: Some("Canton Bern Verkehrsamt".into()),
        logo_uri: None,
        locale: None,
    }
}

async fn insert_issuer(pool: &PgPool, issuer: &Issuer) {
    let mut conn = pool.acquire().await.unwrap();
    persistence::issuers::insert(&mut conn, issuer)
        .await
        .unwrap();
}

fn get_request(uri: &str, bearer: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(b) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {b}"));
    }
    builder.body(Body::empty()).unwrap()
}

async fn read_body(response: axum::response::Response) -> Value {
    let bytes = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn happy_path_returns_target_shape_dto(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let secret = mint_test_token(&pool, &tenant_id).await;
    let issuer = target_shape_issuer(tenant_id.clone());
    insert_issuer(&pool, &issuer).await;

    let app = router(build_state(pool.clone()).await);
    let response = app
        .oneshot(get_request(
            &format!("/api/v1/issuers/{}", issuer.id.bare()),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = read_body(response).await;
    assert_eq!(body["id"], issuer.id.to_string());
    assert_eq!(body["did"], "did:tdw:example.com:9hXq2vRtL8pK7f");
    assert_eq!(body["state"], "active");
    assert_eq!(body["description"], "Cantonal driver-licence issuer");
    assert_eq!(body["display_name"], "Canton Bern Verkehrsamt");
    // tenant_id and the three SigningEngine key-pair handles are
    // deliberately not exposed on the wire.
    assert!(body.get("tenant_id").is_none());
    assert!(body.get("authorized_key_id").is_none());
    assert!(body.get("authentication_key_id").is_none());
    assert!(body.get("assertion_key_id").is_none());
    // Legacy fields must not leak into the wire shape either.
    assert!(body.get("signing_key_id").is_none());
    assert!(body.get("logo_uri").is_none());
    assert!(body.get("locale").is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn returns_404_for_unknown_issuer(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let secret = mint_test_token(&pool, &tenant_id).await;

    let app = router(build_state(pool).await);
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
    let issuer = target_shape_issuer(tenant_a);
    insert_issuer(&pool, &issuer).await;
    let secret = mint_test_token(&pool, &tenant_b).await;

    let app = router(build_state(pool).await);
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
async fn returns_404_for_seeded_legacy_issuer(pool: PgPool) {
    // The seeded dev issuer (migration 0001 + 0004) carries
    // signing_key_id but no state / key triple. The handler hides
    // such rows from the v1 surface.
    let seeded_tenant = TenantId::from_bare(SEEDED_TENANT_BARE).unwrap();
    let seeded_issuer = IssuerId::from_bare(SEEDED_ISSUER_BARE).unwrap();
    let secret = mint_test_token(&pool, &seeded_tenant).await;

    let app = router(build_state(pool).await);
    let response = app
        .oneshot(get_request(
            &format!("/api/v1/issuers/{}", seeded_issuer.bare()),
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

    let app = router(build_state(pool).await);
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
    let issuer = target_shape_issuer(tenant_id);
    insert_issuer(&pool, &issuer).await;

    let app = router(build_state(pool).await);
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
    let issuer = target_shape_issuer(tenant_id);
    insert_issuer(&pool, &issuer).await;

    let app = router(build_state(pool).await);
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
