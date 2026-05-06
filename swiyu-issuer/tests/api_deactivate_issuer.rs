//! Integration tests for `POST /api/v1/issuers/{issuer_id}/deactivate`.
//!
//! Drives requests through the full management router using
//! `tower::ServiceExt::oneshot` against a `sqlx::test`-managed pool.

use axum::body::{self, Body};
use axum::http::{Request, StatusCode, header};
use chrono::Utc;
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;

use swiyu_issuer::api_management::{AppState, Config, router};
use swiyu_issuer::domain::{
    ApiToken, ApiTokenSecret, Issuer, IssuerId, IssuerState, KeyPairId, OperationTask, TaskId,
    TaskState, TaskType, TenantId,
};
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

async fn insert_active_issuer(pool: &PgPool, tenant_id: &TenantId) -> IssuerId {
    let issuer = Issuer {
        id: IssuerId::generate(),
        tenant_id: tenant_id.clone(),
        did: "did:tdw:scid:example.com:fixture-uuid".into(),
        state: Some(IssuerState::Active),
        description: Some("test issuer".into()),
        authorized_key_id: Some(KeyPairId::generate()),
        authentication_key_id: Some(KeyPairId::generate()),
        assertion_key_id: Some(KeyPairId::generate()),
        display_name: Some("Test issuer".into()),
        logo_uri: None,
        locale: None,
        created_at: Utc::now(),
    };
    let id = issuer.id.clone();
    let mut conn = pool.acquire().await.unwrap();
    persistence::issuers::insert(&mut conn, &issuer)
        .await
        .unwrap();
    id
}

async fn insert_deactivate_task(
    pool: &PgPool,
    tenant_id: &TenantId,
    issuer_id: &IssuerId,
    state: TaskState,
) -> TaskId {
    let now = Utc::now();
    let task = OperationTask {
        id: TaskId::generate(),
        tenant_id: tenant_id.clone(),
        task_type: TaskType::DeactivateIssuer,
        state,
        step: None,
        attempts: 0,
        next_attempt_at: None,
        error_code: None,
        error_message: None,
        input: json!({}),
        state_data: json!({}),
        result_issuer_id: Some(issuer_id.clone()),
        created_at: now,
        updated_at: now,
        completed_at: None,
    };
    let id = task.id.clone();
    let mut conn = pool.acquire().await.unwrap();
    persistence::operation_tasks::insert(&mut conn, &task)
        .await
        .unwrap();
    id
}

fn post_request_no_body(uri: &str, bearer: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().method("POST").uri(uri);
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
async fn fresh_deactivation_returns_201_and_inserts_task(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let secret = mint_test_token(&pool, &tenant_id).await;
    let issuer_id = insert_active_issuer(&pool, &tenant_id).await;
    let app = router(build_state(pool.clone()).await);

    let response = app
        .oneshot(post_request_no_body(
            &format!("/api/v1/issuers/{}/deactivate", issuer_id.bare()),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let body = read_body(response).await;
    assert_eq!(body["issuer_id"], issuer_id.to_string());
    let task_id_str = body["task_id"].as_str().expect("task_id is a string");
    let task_id: TaskId = task_id_str.parse().expect("task_id parses");

    let mut conn = pool.acquire().await.unwrap();
    let task = persistence::operation_tasks::find_by_id(&mut conn, &tenant_id, &task_id)
        .await
        .unwrap();
    assert_eq!(task.task_type, TaskType::DeactivateIssuer);
    assert_eq!(task.state, TaskState::Pending);
    assert!(task.step.is_none());
    assert_eq!(task.attempts, 0);
    assert_eq!(task.result_issuer_id, Some(issuer_id));
    assert_eq!(task.input, json!({}));
}

#[sqlx::test(migrations = "./migrations")]
async fn already_pending_returns_200_and_same_task_id(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let secret = mint_test_token(&pool, &tenant_id).await;
    let issuer_id = insert_active_issuer(&pool, &tenant_id).await;
    let existing_task =
        insert_deactivate_task(&pool, &tenant_id, &issuer_id, TaskState::Pending).await;
    let app = router(build_state(pool.clone()).await);

    let response = app
        .oneshot(post_request_no_body(
            &format!("/api/v1/issuers/{}/deactivate", issuer_id.bare()),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = read_body(response).await;
    assert_eq!(body["task_id"], existing_task.to_string());
    assert_eq!(body["issuer_id"], issuer_id.to_string());
}

#[sqlx::test(migrations = "./migrations")]
async fn already_in_progress_returns_200_and_same_task_id(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let secret = mint_test_token(&pool, &tenant_id).await;
    let issuer_id = insert_active_issuer(&pool, &tenant_id).await;
    let existing_task =
        insert_deactivate_task(&pool, &tenant_id, &issuer_id, TaskState::InProgress).await;
    let app = router(build_state(pool.clone()).await);

    let response = app
        .oneshot(post_request_no_body(
            &format!("/api/v1/issuers/{}/deactivate", issuer_id.bare()),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = read_body(response).await;
    assert_eq!(body["task_id"], existing_task.to_string());
}

#[sqlx::test(migrations = "./migrations")]
async fn already_deactivated_with_traceable_task_returns_200_and_completed_task_id(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let secret = mint_test_token(&pool, &tenant_id).await;
    let issuer_id = insert_active_issuer(&pool, &tenant_id).await;
    let completed_task =
        insert_deactivate_task(&pool, &tenant_id, &issuer_id, TaskState::Completed).await;

    // Flip the issuer row to Deactivated to simulate the saga having run
    // to completion.
    sqlx::query("UPDATE issuers SET state = 'deactivated' WHERE id = $1")
        .bind(issuer_id.bare())
        .execute(&pool)
        .await
        .unwrap();

    let app = router(build_state(pool.clone()).await);

    let response = app
        .oneshot(post_request_no_body(
            &format!("/api/v1/issuers/{}/deactivate", issuer_id.bare()),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = read_body(response).await;
    assert_eq!(body["task_id"], completed_task.to_string());
    assert_eq!(body["issuer_id"], issuer_id.to_string());
}

#[sqlx::test(migrations = "./migrations")]
async fn already_deactivated_without_task_returns_200_and_null_task_id(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let secret = mint_test_token(&pool, &tenant_id).await;
    let issuer_id = insert_active_issuer(&pool, &tenant_id).await;

    // Bypass the saga: directly UPDATE the issuer row to Deactivated.
    // No task row was ever inserted, so the handler should respond
    // 200 with task_id: null.
    sqlx::query("UPDATE issuers SET state = 'deactivated' WHERE id = $1")
        .bind(issuer_id.bare())
        .execute(&pool)
        .await
        .unwrap();

    let app = router(build_state(pool.clone()).await);

    let response = app
        .oneshot(post_request_no_body(
            &format!("/api/v1/issuers/{}/deactivate", issuer_id.bare()),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = read_body(response).await;
    assert_eq!(body["task_id"], Value::Null);
    assert_eq!(body["issuer_id"], issuer_id.to_string());
}

#[sqlx::test(migrations = "./migrations")]
async fn cross_tenant_issuer_returns_404(pool: PgPool) {
    let tenant_owner = TenantId::generate();
    let tenant_other = TenantId::generate();
    insert_test_tenant(&pool, &tenant_owner).await;
    insert_test_tenant(&pool, &tenant_other).await;
    let secret_other = mint_test_token(&pool, &tenant_other).await;
    let issuer_id = insert_active_issuer(&pool, &tenant_owner).await;
    let app = router(build_state(pool.clone()).await);

    let response = app
        .oneshot(post_request_no_body(
            &format!("/api/v1/issuers/{}/deactivate", issuer_id.bare()),
            Some(&secret_other.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // The owner's view of the issuer is unaffected.
    let mut conn = pool.acquire().await.unwrap();
    let state = persistence::issuers::find_by_id(&mut conn, &issuer_id)
        .await
        .unwrap()
        .unwrap()
        .state;
    assert_eq!(state, Some(IssuerState::Active));
}

#[sqlx::test(migrations = "./migrations")]
async fn unknown_issuer_returns_404(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let secret = mint_test_token(&pool, &tenant_id).await;
    let unknown = IssuerId::generate();
    let app = router(build_state(pool.clone()).await);

    let response = app
        .oneshot(post_request_no_body(
            &format!("/api/v1/issuers/{}/deactivate", unknown.bare()),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "./migrations")]
async fn legacy_state_null_issuer_returns_404(pool: PgPool) {
    // Migration 0001 seeds an issuer in tenant 4Mk7yK5pQR7sN3 with
    // state = NULL — the pre-management-flow shape. The deactivate
    // endpoint must hide that row the same way GET does.
    let legacy_tenant = TenantId::from_bare("4Mk7yK5pQR7sN3").unwrap();
    let legacy_issuer = IssuerId::from_bare("9hXq2vRtL8pK7f").unwrap();

    // Replace the seeded tenant_id binding here: insert_test_tenant
    // would clash on the PK. Mint a token for the existing tenant.
    let secret = mint_test_token(&pool, &legacy_tenant).await;
    let app = router(build_state(pool.clone()).await);

    let response = app
        .oneshot(post_request_no_body(
            &format!("/api/v1/issuers/{}/deactivate", legacy_issuer.bare()),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "./migrations")]
async fn empty_json_body_is_accepted(pool: PgPool) {
    // A client that sends `{}` instead of an empty body should also
    // get a 201. Ensure the handler does not reject the request when
    // a body is present but empty/empty-object.
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let secret = mint_test_token(&pool, &tenant_id).await;
    let issuer_id = insert_active_issuer(&pool, &tenant_id).await;
    let app = router(build_state(pool.clone()).await);

    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/issuers/{}/deactivate", issuer_id.bare()))
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", secret.as_wire()),
        )
        .body(Body::from("{}"))
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
}
