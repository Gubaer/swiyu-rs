//! Integration tests for `POST /api/v1/issuers`.
//!
//! Drives requests through the full management router (auth +
//! extractors + serde + handler + persistence) using
//! `tower::ServiceExt::oneshot` against a `sqlx::test`-managed pool.

use axum::body::{self, Body};
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;

use swiyu_issuer::api_management::{AppState, Config, router};
use swiyu_issuer::domain::{ApiToken, ApiTokenSecret, IssuerId, TaskId, TaskState, TenantId};
use swiyu_issuer::persistence;

const TEST_BASE_URL: &str = "http://localhost:8080";

async fn build_state(pool: PgPool) -> AppState {
    AppState::new(
        pool,
        Config {
            issuer_base_url: TEST_BASE_URL.into(),
        },
    )
    .expect("AppState builds")
}

#[path = "common/mod.rs"]
mod common;
use common::tenants::insert_test_tenant;

async fn mint_test_token(pool: &PgPool, tenant_id: &TenantId) -> ApiTokenSecret {
    let secret = ApiTokenSecret::generate();
    let token = ApiToken::new(tenant_id.clone(), "test-token".into(), secret.hash(), None);
    let mut conn = pool.acquire().await.unwrap();
    persistence::api_tokens::insert(&mut conn, &token)
        .await
        .unwrap();
    secret
}

fn post_request(uri: &str, bearer: Option<&str>, body: Value) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(b) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {b}"));
    }
    builder
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

async fn read_body(response: axum::response::Response) -> Value {
    let bytes = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn happy_path_returns_201_and_inserts_task(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let secret = mint_test_token(&pool, &tenant_id).await;
    let app = router(build_state(pool.clone()).await);

    let body = json!({
        "description": "Cantonal driver-licence issuer",
        "display_name": "Canton Bern Verkehrsamt",
    });
    let response = app
        .oneshot(post_request(
            "/api/v1/issuers",
            Some(&secret.as_wire()),
            body,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let body = read_body(response).await;
    let task_id_str = body["task_id"].as_str().expect("task_id is a string");
    let issuer_id_str = body["issuer_id"].as_str().expect("issuer_id is a string");

    let task_id = TaskId::from_bare(task_id_str.to_string()).expect("task_id parses as bare");
    let issuer_id =
        IssuerId::from_bare(issuer_id_str.to_string()).expect("issuer_id parses as bare");

    let mut conn = pool.acquire().await.unwrap();
    let task = persistence::operation_tasks::find_by_id(&mut conn, &tenant_id, &task_id)
        .await
        .unwrap();
    assert_eq!(task.state, TaskState::Pending);
    assert!(task.step.is_none());
    assert_eq!(task.attempts, 0);
    assert_eq!(task.result_issuer_id, Some(issuer_id));
    assert_eq!(task.input["description"], "Cantonal driver-licence issuer");
    assert_eq!(task.input["display_name"], "Canton Bern Verkehrsamt");
}

#[sqlx::test(migrations = "./migrations")]
async fn trims_whitespace_in_input_fields(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let secret = mint_test_token(&pool, &tenant_id).await;
    let app = router(build_state(pool.clone()).await);

    let body = json!({
        "description": "  Padded description \n",
        "display_name": "  Padded name  ",
    });
    let response = app
        .oneshot(post_request(
            "/api/v1/issuers",
            Some(&secret.as_wire()),
            body,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let body = read_body(response).await;
    let task_id = TaskId::from_bare(body["task_id"].as_str().unwrap().to_string()).unwrap();
    let mut conn = pool.acquire().await.unwrap();
    let task = persistence::operation_tasks::find_by_id(&mut conn, &tenant_id, &task_id)
        .await
        .unwrap();
    assert_eq!(task.input["description"], "Padded description");
    assert_eq!(task.input["display_name"], "Padded name");
}

#[sqlx::test(migrations = "./migrations")]
async fn missing_fields_apply_defaults(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let secret = mint_test_token(&pool, &tenant_id).await;
    let app = router(build_state(pool.clone()).await);

    // Empty body — both description and display_name omitted.
    let body = json!({});
    let response = app
        .oneshot(post_request(
            "/api/v1/issuers",
            Some(&secret.as_wire()),
            body,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let body = read_body(response).await;
    let task_id = TaskId::from_bare(body["task_id"].as_str().unwrap().to_string()).unwrap();
    let issuer_id_str = body["issuer_id"].as_str().unwrap();
    let issuer_id = IssuerId::from_bare(issuer_id_str.to_string()).unwrap();

    let mut conn = pool.acquire().await.unwrap();
    let task = persistence::operation_tasks::find_by_id(&mut conn, &tenant_id, &task_id)
        .await
        .unwrap();
    assert_eq!(task.input["description"], "");
    assert_eq!(
        task.input["display_name"],
        format!("Issuer {}", issuer_id.bare()),
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn blank_fields_apply_defaults(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let secret = mint_test_token(&pool, &tenant_id).await;
    let app = router(build_state(pool.clone()).await);

    // Both fields present but trim to empty — same as omitted.
    let body = json!({ "description": "  ", "display_name": "\t\n" });
    let response = app
        .oneshot(post_request(
            "/api/v1/issuers",
            Some(&secret.as_wire()),
            body,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let body = read_body(response).await;
    let task_id = TaskId::from_bare(body["task_id"].as_str().unwrap().to_string()).unwrap();
    let issuer_id = IssuerId::from_bare(body["issuer_id"].as_str().unwrap().to_string()).unwrap();

    let mut conn = pool.acquire().await.unwrap();
    let task = persistence::operation_tasks::find_by_id(&mut conn, &tenant_id, &task_id)
        .await
        .unwrap();
    assert_eq!(task.input["description"], "");
    assert_eq!(
        task.input["display_name"],
        format!("Issuer {}", issuer_id.bare()),
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn rejects_oversized_display_name(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let secret = mint_test_token(&pool, &tenant_id).await;
    let app = router(build_state(pool).await);

    let oversized = "a".repeat(256);
    let body = json!({ "description": "ok", "display_name": oversized });
    let response = app
        .oneshot(post_request(
            "/api/v1/issuers",
            Some(&secret.as_wire()),
            body,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = read_body(response).await;
    assert_eq!(body["error"], "invalid_input");
    assert!(
        body["details"].as_str().unwrap().contains("display_name"),
        "details = {body}",
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn rejects_unknown_field(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let secret = mint_test_token(&pool, &tenant_id).await;
    let app = router(build_state(pool).await);

    let body = json!({
        "description": "ok",
        "display_name": "ok",
        "did_method": "tdw:0.3",
    });
    let response = app
        .oneshot(post_request(
            "/api/v1/issuers",
            Some(&secret.as_wire()),
            body,
        ))
        .await
        .unwrap();
    // serde's deny_unknown_fields surfaces as a 422 from axum's
    // JsonRejection, not 400 — confirm we don't accept the body.
    assert_ne!(response.status(), StatusCode::CREATED);
    assert!(response.status().is_client_error());
}

#[sqlx::test(migrations = "./migrations")]
async fn rejects_request_without_authorization(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let app = router(build_state(pool).await);

    let body = json!({ "description": "ok", "display_name": "ok" });
    let response = app
        .oneshot(post_request("/api/v1/issuers", None, body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "./migrations")]
async fn rejects_unknown_bearer_token(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let app = router(build_state(pool).await);

    let bogus = ApiTokenSecret::generate();
    let body = json!({ "description": "ok", "display_name": "ok" });
    let response = app
        .oneshot(post_request(
            "/api/v1/issuers",
            Some(&bogus.as_wire()),
            body,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
