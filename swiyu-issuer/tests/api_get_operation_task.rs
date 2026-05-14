//! Integration tests for `GET /api/v1/operation-tasks/{task_id}`.
//!
//! Drives requests through the full management router (auth +
//! extractors + serde + handler + persistence) using
//! `tower::ServiceExt::oneshot` against a `sqlx::test`-managed pool.

use axum::http::StatusCode;
use chrono::Utc;
use serde_json::json;
use sqlx::PgPool;
use tower::ServiceExt;

use swiyu_issuer::api_management::router;
use swiyu_issuer::domain::{IssuerId, OperationTask, TaskId, TaskType, TenantId};
use swiyu_issuer::persistence;

use swiyu_issuer::test_support::api::tokens::mint_test_token;
use swiyu_issuer::test_support::api::{authenticated_app_state, build_state};
use swiyu_issuer::test_support::http::{get_request, read_body};
use swiyu_issuer::test_support::persistence::tenants::insert_test_tenant;

fn pending_task(tenant_id: &TenantId, result_issuer_id: Option<IssuerId>) -> OperationTask {
    OperationTask {
        input: json!({"description": "x", "display_name": "y"}),
        result_issuer_id,
        ..swiyu_issuer::test_support::persistence::operation_tasks::pending(
            tenant_id,
            TaskType::CreateIssuer,
        )
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn happy_path_returns_target_shape(pool: PgPool) {
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let issuer_id = IssuerId::generate();
    let task = pending_task(&tenant_id, Some(issuer_id.clone()));
    swiyu_issuer::test_support::persistence::operation_tasks::insert(&pool, &task).await;

    let app = router(state);
    let response = app
        .oneshot(get_request(
            &format!("/api/v1/operation-tasks/{}", task.id.bare()),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = read_body(response).await;
    assert_eq!(body["id"], task.id.bare());
    assert_eq!(body["task_type"], "create_issuer");
    assert_eq!(body["state"], "pending");
    assert!(body["step"].is_null());
    assert_eq!(body["attempts"], 0);
    assert!(body["next_attempt_at"].is_null());
    assert!(body["error_code"].is_null());
    assert!(body["error_message"].is_null());
    assert!(body["created_at"].is_string());
    assert!(body["updated_at"].is_string());
    assert!(body["completed_at"].is_null());

    // Internal-only fields must not leak. result_issuer_id is omitted
    // because the BA already received the issuer_id in the response
    // to POST /api/v1/issuers.
    assert!(body.get("tenant_id").is_none());
    assert!(body.get("input").is_none());
    assert!(body.get("state_data").is_none());
    assert!(body.get("result_issuer_id").is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn completed_task_surfaces_terminal_state_and_completed_at(pool: PgPool) {
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let issuer_id = IssuerId::generate();
    let mut task = pending_task(&tenant_id, Some(issuer_id.clone()));
    swiyu_issuer::test_support::persistence::operation_tasks::insert(&pool, &task).await;

    // Drive the task to Completed by mirroring the in-memory mutation
    // `OperationTask::try_complete` performs in the worker, then
    // persisting via `set_terminal_state`.
    let mut conn = pool.acquire().await.unwrap();
    let now = Utc::now();
    task.state = swiyu_issuer::domain::TaskState::Completed;
    task.error_code = None;
    task.error_message = None;
    task.next_attempt_at = None;
    task.updated_at = now;
    task.completed_at = Some(now);
    persistence::operation_tasks::set_terminal_state(&mut conn, &task)
        .await
        .unwrap();
    drop(conn);

    let app = router(state);
    let response = app
        .oneshot(get_request(
            &format!("/api/v1/operation-tasks/{}", task.id.bare()),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = read_body(response).await;
    assert_eq!(body["state"], "completed");
    assert!(body["completed_at"].is_string());
    // result_issuer_id is intentionally not echoed; the BA already
    // has the issuer_id from the POST /api/v1/issuers response.
    assert!(body.get("result_issuer_id").is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn returns_404_for_unknown_task(pool: PgPool) {
    let (state, _tenant_id, secret) = authenticated_app_state(&pool).await;

    let app = router(state);
    let unknown = TaskId::generate();
    let response = app
        .oneshot(get_request(
            &format!("/api/v1/operation-tasks/{}", unknown.bare()),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = read_body(response).await;
    assert_eq!(body["error"], "not_found");
}

#[sqlx::test(migrations = "./migrations")]
async fn returns_404_for_cross_tenant_task(pool: PgPool) {
    let tenant_a = TenantId::generate();
    let tenant_b = TenantId::generate();
    insert_test_tenant(&pool, &tenant_a).await;
    insert_test_tenant(&pool, &tenant_b).await;
    // Task belongs to tenant_a; the bearer token is tenant_b's.
    let task = pending_task(&tenant_a, Some(IssuerId::generate()));
    swiyu_issuer::test_support::persistence::operation_tasks::insert(&pool, &task).await;
    let secret = mint_test_token(&pool, &tenant_b).await;

    let app = router(build_state(pool));
    let response = app
        .oneshot(get_request(
            &format!("/api/v1/operation-tasks/{}", task.id.bare()),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = read_body(response).await;
    assert_eq!(body["error"], "not_found");
}

#[sqlx::test(migrations = "./migrations")]
async fn returns_400_for_malformed_task_id(pool: PgPool) {
    let (state, _tenant_id, secret) = authenticated_app_state(&pool).await;

    let app = router(state);
    // 'O' (capital o) is outside the bs58 alphabet.
    let response = app
        .oneshot(get_request(
            "/api/v1/operation-tasks/notVal0d",
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
    let task = pending_task(&tenant_id, Some(IssuerId::generate()));
    swiyu_issuer::test_support::persistence::operation_tasks::insert(&pool, &task).await;

    let app = router(build_state(pool));
    let response = app
        .oneshot(get_request(
            &format!("/api/v1/operation-tasks/{}", task.id.bare()),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
