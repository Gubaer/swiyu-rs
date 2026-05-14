//! Integration tests for `POST /api/v1/issuers`.
//!
//! Drives requests through the full management router (auth +
//! extractors + serde + handler + persistence) using
//! `tower::ServiceExt::oneshot` against a `sqlx::test`-managed pool.

use axum::http::StatusCode;
use serde_json::json;
use sqlx::PgPool;
use tower::ServiceExt;

use swiyu_issuer::api_management::router;
use swiyu_issuer::domain::{ApiTokenSecret, IssuerId, TaskId, TaskState};
use swiyu_issuer::persistence;

use swiyu_issuer::test_support::api::authenticated_app_state;
use swiyu_issuer::test_support::http::{post_request_json, read_body};

#[sqlx::test(migrations = "./migrations")]
async fn happy_path_returns_201_and_inserts_task(pool: PgPool) {
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let app = router(state);

    let body = json!({
        "description": swiyu_issuer::test_support::fixtures::SAMPLE_DESCRIPTION,
        "display_name": swiyu_issuer::test_support::fixtures::SAMPLE_DISPLAY_NAME,
    });
    let response = app
        .oneshot(post_request_json(
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
    assert_eq!(
        task.input["description"],
        swiyu_issuer::test_support::fixtures::SAMPLE_DESCRIPTION
    );
    assert_eq!(
        task.input["display_name"],
        swiyu_issuer::test_support::fixtures::SAMPLE_DISPLAY_NAME
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn trims_whitespace_in_input_fields(pool: PgPool) {
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let app = router(state);

    let body = json!({
        "description": "  Padded description \n",
        "display_name": "  Padded name  ",
    });
    let response = app
        .oneshot(post_request_json(
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
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let app = router(state);

    // Empty body — both description and display_name omitted.
    let body = json!({});
    let response = app
        .oneshot(post_request_json(
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
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let app = router(state);

    // Both fields present but trim to empty — same as omitted.
    let body = json!({ "description": "  ", "display_name": "\t\n" });
    let response = app
        .oneshot(post_request_json(
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
    let (state, _tenant_id, secret) = authenticated_app_state(&pool).await;
    let app = router(state);

    let oversized = "a".repeat(256);
    let body = json!({ "description": "ok", "display_name": oversized });
    let response = app
        .oneshot(post_request_json(
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
async fn rejects_oversized_description(pool: PgPool) {
    let (state, _tenant_id, secret) = authenticated_app_state(&pool).await;
    let app = router(state);

    let oversized = "a".repeat(256);
    let body = json!({ "description": oversized, "display_name": "ok" });
    let response = app
        .oneshot(post_request_json(
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
        body["details"].as_str().unwrap().contains("description"),
        "details = {body}",
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn rejects_unknown_field(pool: PgPool) {
    let (state, _tenant_id, secret) = authenticated_app_state(&pool).await;
    let app = router(state);

    let body = json!({
        "description": "ok",
        "display_name": "ok",
        "did_method": "tdw:0.3",
    });
    let response = app
        .oneshot(post_request_json(
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
    let (state, _tenant_id, _secret) = authenticated_app_state(&pool).await;
    let app = router(state);

    let body = json!({ "description": "ok", "display_name": "ok" });
    let response = app
        .oneshot(post_request_json("/api/v1/issuers", None, body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "./migrations")]
async fn rejects_unknown_bearer_token(pool: PgPool) {
    let (state, _tenant_id, _secret) = authenticated_app_state(&pool).await;
    let app = router(state);

    let bogus = ApiTokenSecret::generate();
    let body = json!({ "description": "ok", "display_name": "ok" });
    let response = app
        .oneshot(post_request_json(
            "/api/v1/issuers",
            Some(&bogus.as_wire()),
            body,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
