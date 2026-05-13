//! Integration tests for `POST /api/v1/issuers/{issuer_id}/rotate-keys`.
//!
//! Drives requests through the full management router using
//! `tower::ServiceExt::oneshot` against a `sqlx::test`-managed pool.

use axum::http::StatusCode;
use serde_json::json;
use sqlx::PgPool;
use tower::ServiceExt;

use swiyu_issuer::api_management::router;
use swiyu_issuer::domain::{
    Issuer, IssuerId, OperationTask, TaskId, TaskState, TaskType, TenantId,
};
use swiyu_issuer::persistence;

#[path = "common/mod.rs"]
mod common;
use common::api_tokens::mint_test_token;
use common::app_state::build_state;
use common::http::{post_request_json, read_body};
use common::tenants::insert_test_tenant;

async fn insert_active_issuer(pool: &PgPool, tenant_id: &TenantId) -> IssuerId {
    let issuer = Issuer {
        did: "did:tdw:scid:example.com:fixture-uuid".into(),
        description: Some("test issuer".into()),
        ..common::issuers::active_with_keys(tenant_id)
    };
    let id = issuer.id.clone();
    common::issuers::insert(pool, &issuer).await;
    id
}

async fn insert_rotate_task(
    pool: &PgPool,
    tenant_id: &TenantId,
    issuer_id: &IssuerId,
    state: TaskState,
) -> TaskId {
    let task = OperationTask {
        state,
        input: json!({"roles": ["authorized"]}),
        result_issuer_id: Some(issuer_id.clone()),
        ..common::operation_tasks::pending(tenant_id, TaskType::RotateKeys)
    };
    let id = task.id.clone();
    common::operation_tasks::insert(pool, &task).await;
    id
}

#[sqlx::test(migrations = "./migrations")]
async fn fresh_rotation_returns_201_and_inserts_task(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let secret = mint_test_token(&pool, &tenant_id).await;
    let issuer_id = insert_active_issuer(&pool, &tenant_id).await;
    let app = router(build_state(pool.clone()));

    let response = app
        .oneshot(post_request_json(
            &format!("/api/v1/issuers/{}/rotate-keys", issuer_id.bare()),
            Some(&secret.as_wire()),
            json!({"roles": ["authorized"]}),
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
    assert_eq!(task.task_type, TaskType::RotateKeys);
    assert_eq!(task.state, TaskState::Pending);
    assert!(task.step.is_none());
    assert_eq!(task.attempts, 0);
    assert_eq!(task.result_issuer_id, Some(issuer_id));
    assert_eq!(task.input, json!({"roles": ["authorized"]}));
}

#[sqlx::test(migrations = "./migrations")]
async fn all_sentinel_expands_server_side(pool: PgPool) {
    // Wire `["all"]` becomes the explicit three-role set in the
    // persisted task input. The sentinel does not survive the
    // boundary.
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let secret = mint_test_token(&pool, &tenant_id).await;
    let issuer_id = insert_active_issuer(&pool, &tenant_id).await;
    let app = router(build_state(pool.clone()));

    let response = app
        .oneshot(post_request_json(
            &format!("/api/v1/issuers/{}/rotate-keys", issuer_id.bare()),
            Some(&secret.as_wire()),
            json!({"roles": ["all"]}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let body = read_body(response).await;
    let task_id_str = body["task_id"].as_str().unwrap();
    let task_id = TaskId::from_bare(task_id_str.to_string()).unwrap();

    let mut conn = pool.acquire().await.unwrap();
    let task = persistence::operation_tasks::find_by_id(&mut conn, &tenant_id, &task_id)
        .await
        .unwrap();
    assert_eq!(
        task.input,
        json!({"roles": ["authorized", "authentication", "assertion"]}),
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn in_flight_task_returns_200_and_same_task_id(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let secret = mint_test_token(&pool, &tenant_id).await;
    let issuer_id = insert_active_issuer(&pool, &tenant_id).await;
    let existing_task = insert_rotate_task(&pool, &tenant_id, &issuer_id, TaskState::Pending).await;
    let app = router(build_state(pool.clone()));

    let response = app
        .oneshot(post_request_json(
            &format!("/api/v1/issuers/{}/rotate-keys", issuer_id.bare()),
            Some(&secret.as_wire()),
            json!({"roles": ["authorized"]}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = read_body(response).await;
    assert_eq!(body["task_id"], existing_task.bare());
    assert_eq!(body["issuer_id"], issuer_id.bare());
}

#[sqlx::test(migrations = "./migrations")]
async fn prior_completed_task_falls_through_to_fresh_201(pool: PgPool) {
    // Rotation is repeatable: a prior completed task does NOT
    // block a new submission.
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let secret = mint_test_token(&pool, &tenant_id).await;
    let issuer_id = insert_active_issuer(&pool, &tenant_id).await;
    let prior_task = insert_rotate_task(&pool, &tenant_id, &issuer_id, TaskState::Completed).await;
    let app = router(build_state(pool.clone()));

    let response = app
        .oneshot(post_request_json(
            &format!("/api/v1/issuers/{}/rotate-keys", issuer_id.bare()),
            Some(&secret.as_wire()),
            json!({"roles": ["authorized"]}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let body = read_body(response).await;
    let task_id_str = body["task_id"].as_str().unwrap();
    let new_task_id = TaskId::from_bare(task_id_str.to_string()).unwrap();
    assert_ne!(new_task_id, prior_task);
}

#[sqlx::test(migrations = "./migrations")]
async fn deactivated_issuer_returns_409(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let secret = mint_test_token(&pool, &tenant_id).await;
    let issuer_id = insert_active_issuer(&pool, &tenant_id).await;

    sqlx::query("UPDATE issuers SET state = 'deactivated' WHERE id = $1")
        .bind(issuer_id.bare())
        .execute(&pool)
        .await
        .unwrap();

    let app = router(build_state(pool.clone()));

    let response = app
        .oneshot(post_request_json(
            &format!("/api/v1/issuers/{}/rotate-keys", issuer_id.bare()),
            Some(&secret.as_wire()),
            json!({"roles": ["authorized"]}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);

    let body = read_body(response).await;
    assert_eq!(body["error"], "conflict");
}

#[sqlx::test(migrations = "./migrations")]
async fn empty_roles_returns_400(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let secret = mint_test_token(&pool, &tenant_id).await;
    let issuer_id = insert_active_issuer(&pool, &tenant_id).await;
    let app = router(build_state(pool.clone()));

    let response = app
        .oneshot(post_request_json(
            &format!("/api/v1/issuers/{}/rotate-keys", issuer_id.bare()),
            Some(&secret.as_wire()),
            json!({"roles": []}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrations = "./migrations")]
async fn unknown_role_returns_400(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let secret = mint_test_token(&pool, &tenant_id).await;
    let issuer_id = insert_active_issuer(&pool, &tenant_id).await;
    let app = router(build_state(pool.clone()));

    let response = app
        .oneshot(post_request_json(
            &format!("/api/v1/issuers/{}/rotate-keys", issuer_id.bare()),
            Some(&secret.as_wire()),
            json!({"roles": ["administrator"]}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrations = "./migrations")]
async fn all_mixed_with_concrete_role_returns_400(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let secret = mint_test_token(&pool, &tenant_id).await;
    let issuer_id = insert_active_issuer(&pool, &tenant_id).await;
    let app = router(build_state(pool.clone()));

    let response = app
        .oneshot(post_request_json(
            &format!("/api/v1/issuers/{}/rotate-keys", issuer_id.bare()),
            Some(&secret.as_wire()),
            json!({"roles": ["all", "authorized"]}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
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
        .oneshot(post_request_json(
            &format!("/api/v1/issuers/{}/rotate-keys", issuer_id.bare()),
            Some(&secret_other.as_wire()),
            json!({"roles": ["authorized"]}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "./migrations")]
async fn unknown_issuer_returns_404(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let secret = mint_test_token(&pool, &tenant_id).await;
    let unknown = IssuerId::generate();
    let app = router(build_state(pool.clone()));

    let response = app
        .oneshot(post_request_json(
            &format!("/api/v1/issuers/{}/rotate-keys", unknown.bare()),
            Some(&secret.as_wire()),
            json!({"roles": ["authorized"]}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "./migrations")]
async fn legacy_state_null_issuer_returns_404(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let secret = mint_test_token(&pool, &tenant_id).await;
    let legacy = Issuer {
        did: "did:tdw:example.com:legacy".into(),
        state: None,
        display_name: None,
        ..common::issuers::active(&tenant_id)
    };
    common::issuers::insert(&pool, &legacy).await;

    let app = router(build_state(pool.clone()));
    let response = app
        .oneshot(post_request_json(
            &format!("/api/v1/issuers/{}/rotate-keys", legacy.id.bare()),
            Some(&secret.as_wire()),
            json!({"roles": ["authorized"]}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
