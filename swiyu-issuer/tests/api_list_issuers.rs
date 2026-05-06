//! Integration tests for `GET /api/v1/issuers`.
//!
//! Drives requests through the full management router (auth +
//! extractors + serde + handler + persistence) using
//! `tower::ServiceExt::oneshot` against a `sqlx::test`-managed pool.

use axum::body::{self, Body};
use axum::http::{Request, StatusCode, header};
use chrono::{Duration, Utc};
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;

use swiyu_issuer::api_management::{AppState, Config, router};
use swiyu_issuer::domain::{
    ApiToken, ApiTokenSecret, Issuer, IssuerId, IssuerState, KeyPairId, TenantId,
};
use swiyu_issuer::persistence;

const TEST_BASE_URL: &str = "http://localhost:8080";

// IDs hard-coded by migration 0001 / 0004. Reproduced here so the
// tests covering the seeded-legacy filter do not need to query the
// DB to learn what they are.
const SEEDED_TENANT_BARE: &str = "4Mk7yK5pQR7sN3";

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

/// Inserts an issuer in the BA-facing target shape (state set,
/// legacy fields cleared) with an explicit `created_at` so list
/// ordering is deterministic.
async fn insert_target_shape_issuer(
    pool: &PgPool,
    tenant_id: &TenantId,
    display_name: &str,
    created_at: chrono::DateTime<Utc>,
) -> Issuer {
    let issuer = Issuer {
        id: IssuerId::generate(),
        tenant_id: tenant_id.clone(),
        did: format!("did:tdw:{}:example.com", IssuerId::generate().bare()),
        state: Some(IssuerState::Active),
        description: Some(format!("{display_name} description")),
        authorized_key_id: Some(KeyPairId::generate()),
        authentication_key_id: Some(KeyPairId::generate()),
        assertion_key_id: Some(KeyPairId::generate()),
        display_name: Some(display_name.into()),
        logo_uri: None,
        locale: None,
        created_at,
    };
    let mut conn = pool.acquire().await.unwrap();
    persistence::issuers::insert(&mut conn, &issuer)
        .await
        .unwrap();
    issuer
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
async fn empty_list_returns_no_items_and_no_cursor(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let secret = mint_test_token(&pool, &tenant_id).await;

    let app = router(build_state(pool).await);
    let response = app
        .oneshot(get_request("/api/v1/issuers", Some(&secret.as_wire())))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = read_body(response).await;
    assert_eq!(body["items"].as_array().unwrap().len(), 0);
    assert!(body["next_cursor"].is_null());
}

#[sqlx::test(migrations = "./migrations")]
async fn single_page_returns_target_shape_dtos(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let secret = mint_test_token(&pool, &tenant_id).await;
    let now = Utc::now();
    let older =
        insert_target_shape_issuer(&pool, &tenant_id, "Older", now - Duration::seconds(10)).await;
    let newer = insert_target_shape_issuer(&pool, &tenant_id, "Newer", now).await;

    let app = router(build_state(pool).await);
    let response = app
        .oneshot(get_request("/api/v1/issuers", Some(&secret.as_wire())))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = read_body(response).await;
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    // Newest first.
    assert_eq!(items[0]["id"], newer.id.bare());
    assert_eq!(items[0]["display_name"], "Newer");
    assert_eq!(items[0]["state"], "active");
    assert_eq!(items[1]["id"], older.id.bare());
    assert_eq!(items[1]["display_name"], "Older");
    assert!(body["next_cursor"].is_null());

    // The DTO must not leak internal fields.
    assert!(items[0].get("tenant_id").is_none());
    assert!(items[0].get("authorized_key_id").is_none());
    assert!(items[0].get("authentication_key_id").is_none());
    assert!(items[0].get("assertion_key_id").is_none());
    assert!(items[0].get("logo_uri").is_none());
    assert!(items[0].get("locale").is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn multi_page_advances_via_cursor(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let secret = mint_test_token(&pool, &tenant_id).await;

    // Three issuers with strictly decreasing display names so we can
    // assert ordering without depending on randomly generated ids.
    let now = Utc::now();
    let oldest =
        insert_target_shape_issuer(&pool, &tenant_id, "A", now - Duration::seconds(20)).await;
    let middle =
        insert_target_shape_issuer(&pool, &tenant_id, "B", now - Duration::seconds(10)).await;
    let newest = insert_target_shape_issuer(&pool, &tenant_id, "C", now).await;

    let app = router(build_state(pool).await);

    // Page 1: limit=2 → newest + middle, with a forward cursor.
    let page1_response = app
        .clone()
        .oneshot(get_request(
            "/api/v1/issuers?limit=2",
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(page1_response.status(), StatusCode::OK);
    let page1 = read_body(page1_response).await;
    let items1 = page1["items"].as_array().unwrap();
    assert_eq!(items1.len(), 2);
    assert_eq!(items1[0]["id"], newest.id.bare());
    assert_eq!(items1[1]["id"], middle.id.bare());
    let cursor = page1["next_cursor"].as_str().unwrap().to_string();

    // Page 2: same limit, cursor advances → just oldest, no further cursor.
    let page2_response = app
        .oneshot(get_request(
            &format!("/api/v1/issuers?limit=2&cursor={cursor}"),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(page2_response.status(), StatusCode::OK);
    let page2 = read_body(page2_response).await;
    let items2 = page2["items"].as_array().unwrap();
    assert_eq!(items2.len(), 1);
    assert_eq!(items2[0]["id"], oldest.id.bare());
    assert!(page2["next_cursor"].is_null());
}

#[sqlx::test(migrations = "./migrations")]
async fn cross_tenant_issuers_are_excluded(pool: PgPool) {
    let tenant_a = TenantId::generate();
    let tenant_b = TenantId::generate();
    insert_test_tenant(&pool, &tenant_a).await;
    insert_test_tenant(&pool, &tenant_b).await;
    let secret_a = mint_test_token(&pool, &tenant_a).await;

    // Tenant B has issuers; tenant A has none.
    insert_target_shape_issuer(&pool, &tenant_b, "B-1", Utc::now()).await;
    insert_target_shape_issuer(&pool, &tenant_b, "B-2", Utc::now()).await;

    let app = router(build_state(pool).await);
    let response = app
        .oneshot(get_request("/api/v1/issuers", Some(&secret_a.as_wire())))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = read_body(response).await;
    assert_eq!(body["items"].as_array().unwrap().len(), 0);
    assert!(body["next_cursor"].is_null());
}

#[sqlx::test(migrations = "./migrations")]
async fn seeded_legacy_issuer_is_filtered_out(pool: PgPool) {
    // The seeded dev tenant has exactly one row in `issuers` (the
    // legacy-shaped row from migration 0004) which carries
    // `state IS NULL`. The list endpoint must hide it the same way
    // the single-fetch endpoint 404s it.
    let seeded_tenant = TenantId::from_bare(SEEDED_TENANT_BARE).unwrap();
    let secret = mint_test_token(&pool, &seeded_tenant).await;

    let app = router(build_state(pool).await);
    let response = app
        .oneshot(get_request("/api/v1/issuers", Some(&secret.as_wire())))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = read_body(response).await;
    assert_eq!(body["items"].as_array().unwrap().len(), 0);
    assert!(body["next_cursor"].is_null());
}

#[sqlx::test(migrations = "./migrations")]
async fn rejects_out_of_range_limit(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let secret = mint_test_token(&pool, &tenant_id).await;

    let app = router(build_state(pool).await);
    let response = app
        .oneshot(get_request(
            "/api/v1/issuers?limit=0",
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = read_body(response).await;
    assert_eq!(body["error"], "invalid_input");
}

#[sqlx::test(migrations = "./migrations")]
async fn rejects_malformed_cursor(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let secret = mint_test_token(&pool, &tenant_id).await;

    let app = router(build_state(pool).await);
    // '0' is outside the bs58 alphabet.
    let response = app
        .oneshot(get_request(
            "/api/v1/issuers?cursor=0000",
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
    let app = router(build_state(pool).await);
    let response = app
        .oneshot(get_request("/api/v1/issuers", None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
