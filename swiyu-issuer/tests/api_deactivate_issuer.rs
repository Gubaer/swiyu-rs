//! Integration tests for `POST /api/v1/issuers/{issuer_id}/deactivate`.
//!
//! Drives requests through the full management router using
//! `tower::ServiceExt::oneshot` against a `sqlx::test`-managed pool.

use axum::http::StatusCode;
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;

use swiyu_issuer::api_management::router;
use swiyu_issuer::domain::{
    Issuer, IssuerId, IssuerState, OperationTask, TaskId, TaskState, TaskType, TenantId,
};
use swiyu_issuer::persistence;

#[path = "common/mod.rs"]
mod common;
use common::api_tokens::mint_test_token;
use common::app_state::build_state;
use common::http::{post_request_empty, post_request_json, read_body};
use common::tenants::insert_test_tenant;

async fn insert_active_issuer(pool: &PgPool, tenant_id: &TenantId) -> IssuerId {
    let issuer = Issuer {
        did: "did:tdw:scid:example.com:fixture-uuid".into(),
        ..common::issuers::active_with_keys(tenant_id)
    };
    let id = issuer.id.clone();
    common::issuers::insert(pool, &issuer).await;
    id
}

async fn insert_deactivate_task(
    pool: &PgPool,
    tenant_id: &TenantId,
    issuer_id: &IssuerId,
    state: TaskState,
) -> TaskId {
    let task = OperationTask {
        state,
        result_issuer_id: Some(issuer_id.clone()),
        ..common::operation_tasks::pending(tenant_id, TaskType::DeactivateIssuer)
    };
    let id = task.id.clone();
    common::operation_tasks::insert(pool, &task).await;
    id
}

#[sqlx::test(migrations = "./migrations")]
async fn fresh_deactivation_returns_201_and_inserts_task(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let secret = mint_test_token(&pool, &tenant_id).await;
    let issuer_id = insert_active_issuer(&pool, &tenant_id).await;
    let app = router(build_state(pool.clone()));

    let response = app
        .oneshot(post_request_empty(
            &format!("/api/v1/issuers/{}/deactivate", issuer_id.bare()),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let body = read_body(response).await;
    assert_eq!(body["issuer_id"], issuer_id.bare());
    let task_id_str = body["task_id"].as_str().expect("task_id is a string");
    let task_id =
        TaskId::from_bare(task_id_str.to_string()).expect("task_id parses as bare base58");

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
    let app = router(build_state(pool.clone()));

    let response = app
        .oneshot(post_request_empty(
            &format!("/api/v1/issuers/{}/deactivate", issuer_id.bare()),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = read_body(response).await;
    assert_eq!(body["task_id"], existing_task.bare());
    assert_eq!(body["issuer_id"], issuer_id.bare());
}

#[sqlx::test(migrations = "./migrations")]
async fn already_in_progress_returns_200_and_same_task_id(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let secret = mint_test_token(&pool, &tenant_id).await;
    let issuer_id = insert_active_issuer(&pool, &tenant_id).await;
    let existing_task =
        insert_deactivate_task(&pool, &tenant_id, &issuer_id, TaskState::InProgress).await;
    let app = router(build_state(pool.clone()));

    let response = app
        .oneshot(post_request_empty(
            &format!("/api/v1/issuers/{}/deactivate", issuer_id.bare()),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = read_body(response).await;
    assert_eq!(body["task_id"], existing_task.bare());
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

    let app = router(build_state(pool.clone()));

    let response = app
        .oneshot(post_request_empty(
            &format!("/api/v1/issuers/{}/deactivate", issuer_id.bare()),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = read_body(response).await;
    assert_eq!(body["task_id"], completed_task.bare());
    assert_eq!(body["issuer_id"], issuer_id.bare());
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

    let app = router(build_state(pool.clone()));

    let response = app
        .oneshot(post_request_empty(
            &format!("/api/v1/issuers/{}/deactivate", issuer_id.bare()),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = read_body(response).await;
    assert_eq!(body["task_id"], Value::Null);
    assert_eq!(body["issuer_id"], issuer_id.bare());
}

#[sqlx::test(migrations = "./migrations")]
async fn cross_tenant_issuer_returns_404(pool: PgPool) {
    let tenant_owner = TenantId::generate();
    let tenant_other = TenantId::generate();
    insert_test_tenant(&pool, &tenant_owner).await;
    insert_test_tenant(&pool, &tenant_other).await;
    let secret_other = mint_test_token(&pool, &tenant_other).await;
    let issuer_id = insert_active_issuer(&pool, &tenant_owner).await;
    let app = router(build_state(pool.clone()));

    let response = app
        .oneshot(post_request_empty(
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
    let app = router(build_state(pool.clone()));

    let response = app
        .oneshot(post_request_empty(
            &format!("/api/v1/issuers/{}/deactivate", unknown.bare()),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "./migrations")]
async fn legacy_state_null_issuer_returns_404(pool: PgPool) {
    // A row that carries `state IS NULL` represents the
    // pre-management-flow shape; the deactivate endpoint must hide it
    // the same way GET does.
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let secret = mint_test_token(&pool, &tenant_id).await;
    let legacy = Issuer {
        did: "did:tdw:example.com:legacy".into(),
        state: None,
        ..common::issuers::active(&tenant_id)
    };
    common::issuers::insert(&pool, &legacy).await;

    let app = router(build_state(pool.clone()));
    let response = app
        .oneshot(post_request_empty(
            &format!("/api/v1/issuers/{}/deactivate", legacy.id.bare()),
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
    let app = router(build_state(pool.clone()));

    let response = app
        .oneshot(post_request_json(
            &format!("/api/v1/issuers/{}/deactivate", issuer_id.bare()),
            Some(&secret.as_wire()),
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
}
