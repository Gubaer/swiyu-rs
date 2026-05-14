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

use swiyu_issuer::test_support::api::tokens::mint_test_token;
use swiyu_issuer::test_support::api::{authenticated_app_state, build_state};
use swiyu_issuer::test_support::http::{post_request_empty, post_request_json, read_body};
use swiyu_issuer::test_support::persistence::tenants::insert_test_tenant;

async fn insert_deactivate_task(
    pool: &PgPool,
    tenant_id: &TenantId,
    issuer_id: &IssuerId,
    state: TaskState,
) -> TaskId {
    let task = OperationTask {
        state,
        result_issuer_id: Some(issuer_id.clone()),
        ..swiyu_issuer::test_support::persistence::operation_tasks::pending(
            tenant_id,
            TaskType::DeactivateIssuer,
        )
    };
    let id = task.id.clone();
    swiyu_issuer::test_support::persistence::operation_tasks::insert(pool, &task).await;
    id
}

#[sqlx::test(migrations = "./migrations")]
async fn fresh_deactivation_returns_201_and_inserts_task(pool: PgPool) {
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let issuer_id = swiyu_issuer::test_support::persistence::issuers::insert_active_with_keys(
        &pool, &tenant_id,
    )
    .await
    .id;
    let app = router(state);

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
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let issuer_id = swiyu_issuer::test_support::persistence::issuers::insert_active_with_keys(
        &pool, &tenant_id,
    )
    .await
    .id;
    let existing_task =
        insert_deactivate_task(&pool, &tenant_id, &issuer_id, TaskState::Pending).await;
    let app = router(state);

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
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let issuer_id = swiyu_issuer::test_support::persistence::issuers::insert_active_with_keys(
        &pool, &tenant_id,
    )
    .await
    .id;
    let existing_task =
        insert_deactivate_task(&pool, &tenant_id, &issuer_id, TaskState::InProgress).await;
    let app = router(state);

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
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let issuer_id = swiyu_issuer::test_support::persistence::issuers::insert_active_with_keys(
        &pool, &tenant_id,
    )
    .await
    .id;
    let completed_task =
        insert_deactivate_task(&pool, &tenant_id, &issuer_id, TaskState::Completed).await;

    // Flip the issuer row to Deactivated to simulate the saga having run
    // to completion.
    sqlx::query("UPDATE issuers SET state = 'deactivated' WHERE id = $1")
        .bind(issuer_id.bare())
        .execute(&pool)
        .await
        .unwrap();

    let app = router(state);

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
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let issuer_id = swiyu_issuer::test_support::persistence::issuers::insert_active_with_keys(
        &pool, &tenant_id,
    )
    .await
    .id;

    // Bypass the saga: directly UPDATE the issuer row to Deactivated.
    // No task row was ever inserted, so the handler should respond
    // 200 with task_id: null.
    sqlx::query("UPDATE issuers SET state = 'deactivated' WHERE id = $1")
        .bind(issuer_id.bare())
        .execute(&pool)
        .await
        .unwrap();

    let app = router(state);

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
    let issuer_id = swiyu_issuer::test_support::persistence::issuers::insert_active_with_keys(
        &pool,
        &tenant_owner,
    )
    .await
    .id;
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
    let (state, _tenant_id, secret) = authenticated_app_state(&pool).await;
    let unknown = IssuerId::generate();
    let app = router(state);

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
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let legacy = Issuer {
        did: "did:tdw:example.com:legacy".into(),
        state: None,
        ..swiyu_issuer::test_support::persistence::issuers::active(&tenant_id)
    };
    swiyu_issuer::test_support::persistence::issuers::insert(&pool, &legacy).await;

    let app = router(state);
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
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let issuer_id = swiyu_issuer::test_support::persistence::issuers::insert_active_with_keys(
        &pool, &tenant_id,
    )
    .await
    .id;
    let app = router(state);

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
