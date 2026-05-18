//! Integration tests for the credential-type ↔ issuer assignment
//! endpoints (`POST`/`DELETE` on the pair and `GET` on the list).
//!
//! Each test drives requests through the full management router
//! against a `sqlx::test`-managed pool and asserts both the HTTP
//! response and the persistence side-effect.

use axum::http::StatusCode;
use serde_json::json;
use sqlx::PgPool;
use tower::ServiceExt;

use swiyu_issuer::api_management::router;
use swiyu_issuer::domain::{CredentialTypeId, IssuerId};
use swiyu_issuer::persistence;

use swiyu_issuer::test_support::api::authenticated_app_state;
use swiyu_issuer::test_support::http::{
    delete_request, get_request, post_request_empty, post_request_json, read_body,
};
use swiyu_issuer::test_support::persistence::issuers as test_issuers;

fn valid_create_body() -> serde_json::Value {
    json!({
        "vct": "urn:example:proof-of-residency",
        "claim_schema": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": { "first_name": { "type": "string" } },
            "required": ["first_name"]
        },
        "default_validity_seconds": 31_536_000_u64,
        "revocation_mode": "revocable_and_suspendable"
    })
}

async fn create_credential_type(
    state: swiyu_issuer::api_management::AppState,
    secret: &swiyu_issuer::domain::ApiTokenSecret,
) -> String {
    let resp = router(state)
        .oneshot(post_request_json(
            "/api/v1/credential-types",
            Some(&secret.as_wire()),
            valid_create_body(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    read_body(resp).await["credential_type_id"]
        .as_str()
        .unwrap()
        .to_string()
}

#[sqlx::test(migrations = "./migrations")]
async fn assign_happy_path_returns_201_and_inserts_row(pool: PgPool) {
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let issuer = test_issuers::insert_active(&pool, &tenant_id).await;
    let type_id_str = create_credential_type(state.clone(), &secret).await;

    let resp = router(state)
        .oneshot(post_request_empty(
            &format!(
                "/api/v1/issuers/{}/credential-types/{type_id_str}",
                issuer.id.bare()
            ),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = read_body(resp).await;
    assert_eq!(body["issuer_id"], issuer.id.bare());
    assert_eq!(body["credential_type_id"], type_id_str);

    // The link row exists.
    let type_id = CredentialTypeId::from_bare(type_id_str).unwrap();
    let mut conn = pool.acquire().await.unwrap();
    assert!(
        persistence::issuer_credential_types::is_assigned(&mut conn, &issuer.id, &type_id)
            .await
            .unwrap()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn assign_is_idempotent_and_returns_200_on_duplicate(pool: PgPool) {
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let issuer = test_issuers::insert_active(&pool, &tenant_id).await;
    let type_id_str = create_credential_type(state.clone(), &secret).await;
    let path = format!(
        "/api/v1/issuers/{}/credential-types/{type_id_str}",
        issuer.id.bare()
    );

    let first = router(state.clone())
        .oneshot(post_request_empty(&path, Some(&secret.as_wire())))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);

    let second = router(state)
        .oneshot(post_request_empty(&path, Some(&secret.as_wire())))
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::OK);
}

#[sqlx::test(migrations = "./migrations")]
async fn assign_returns_404_for_unknown_issuer(pool: PgPool) {
    let (state, _tenant_id, secret) = authenticated_app_state(&pool).await;
    let type_id_str = create_credential_type(state.clone(), &secret).await;
    let unknown_issuer = IssuerId::generate();

    let resp = router(state)
        .oneshot(post_request_empty(
            &format!(
                "/api/v1/issuers/{}/credential-types/{type_id_str}",
                unknown_issuer.bare()
            ),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "./migrations")]
async fn assign_returns_404_for_unknown_credential_type(pool: PgPool) {
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let issuer = test_issuers::insert_active(&pool, &tenant_id).await;
    let unknown_type = CredentialTypeId::generate();

    let resp = router(state)
        .oneshot(post_request_empty(
            &format!(
                "/api/v1/issuers/{}/credential-types/{}",
                issuer.id.bare(),
                unknown_type.bare()
            ),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "./migrations")]
async fn assign_returns_404_cross_tenant_issuer_side(pool: PgPool) {
    // Tenant A owns the issuer; Tenant B owns the credential type.
    // Either caller must see 404 — the pair is not jointly owned.
    let (state_a, tenant_a, secret_a) = authenticated_app_state(&pool).await;
    let (state_b, _tenant_b, secret_b) = authenticated_app_state(&pool).await;

    let issuer = test_issuers::insert_active(&pool, &tenant_a).await;
    let type_id_str = create_credential_type(state_b, &secret_b).await;

    let resp = router(state_a)
        .oneshot(post_request_empty(
            &format!(
                "/api/v1/issuers/{}/credential-types/{type_id_str}",
                issuer.id.bare()
            ),
            Some(&secret_a.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "./migrations")]
async fn unassign_removes_existing_assignment(pool: PgPool) {
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let issuer = test_issuers::insert_active(&pool, &tenant_id).await;
    let type_id_str = create_credential_type(state.clone(), &secret).await;
    let path = format!(
        "/api/v1/issuers/{}/credential-types/{type_id_str}",
        issuer.id.bare()
    );

    let assign_resp = router(state.clone())
        .oneshot(post_request_empty(&path, Some(&secret.as_wire())))
        .await
        .unwrap();
    assert_eq!(assign_resp.status(), StatusCode::CREATED);

    let unassign_resp = router(state)
        .oneshot(delete_request(&path, Some(&secret.as_wire())))
        .await
        .unwrap();
    assert_eq!(unassign_resp.status(), StatusCode::NO_CONTENT);

    let type_id = CredentialTypeId::from_bare(type_id_str).unwrap();
    let mut conn = pool.acquire().await.unwrap();
    assert!(
        !persistence::issuer_credential_types::is_assigned(&mut conn, &issuer.id, &type_id)
            .await
            .unwrap()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn unassign_is_idempotent_on_absent_assignment(pool: PgPool) {
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let issuer = test_issuers::insert_active(&pool, &tenant_id).await;
    let type_id_str = create_credential_type(state.clone(), &secret).await;

    // No assign call: the row doesn't exist. Delete should still 204.
    let resp = router(state)
        .oneshot(delete_request(
            &format!(
                "/api/v1/issuers/{}/credential-types/{type_id_str}",
                issuer.id.bare()
            ),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[sqlx::test(migrations = "./migrations")]
async fn unassign_returns_404_cross_tenant(pool: PgPool) {
    let (state_a, tenant_a, secret_a) = authenticated_app_state(&pool).await;
    let (state_b, _tenant_b, secret_b) = authenticated_app_state(&pool).await;
    let issuer = test_issuers::insert_active(&pool, &tenant_a).await;
    let type_id_str = create_credential_type(state_b, &secret_b).await;

    // Tenant A's caller tries to unassign across the gap; 404.
    let resp = router(state_a)
        .oneshot(delete_request(
            &format!(
                "/api/v1/issuers/{}/credential-types/{type_id_str}",
                issuer.id.bare()
            ),
            Some(&secret_a.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "./migrations")]
async fn list_assignments_returns_assigned_credential_types(pool: PgPool) {
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let issuer = test_issuers::insert_active(&pool, &tenant_id).await;
    let type_id_str = create_credential_type(state.clone(), &secret).await;
    let path = format!(
        "/api/v1/issuers/{}/credential-types/{type_id_str}",
        issuer.id.bare()
    );
    let assign = router(state.clone())
        .oneshot(post_request_empty(&path, Some(&secret.as_wire())))
        .await
        .unwrap();
    assert_eq!(assign.status(), StatusCode::CREATED);

    let resp = router(state)
        .oneshot(get_request(
            &format!("/api/v1/issuers/{}/credential-types", issuer.id.bare()),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_body(resp).await;
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["credential_type_id"], type_id_str);
    assert_eq!(items[0]["vct"], "urn:example:proof-of-residency");
}

#[sqlx::test(migrations = "./migrations")]
async fn list_assignments_returns_empty_when_none_assigned(pool: PgPool) {
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let issuer = test_issuers::insert_active(&pool, &tenant_id).await;

    let resp = router(state)
        .oneshot(get_request(
            &format!("/api/v1/issuers/{}/credential-types", issuer.id.bare()),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_body(resp).await;
    assert!(body["items"].as_array().unwrap().is_empty());
}

#[sqlx::test(migrations = "./migrations")]
async fn list_assignments_returns_404_for_unknown_issuer(pool: PgPool) {
    let (state, _tenant_id, secret) = authenticated_app_state(&pool).await;
    let unknown = IssuerId::generate();

    let resp = router(state)
        .oneshot(get_request(
            &format!("/api/v1/issuers/{}/credential-types", unknown.bare()),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "./migrations")]
async fn list_assignments_returns_404_cross_tenant(pool: PgPool) {
    let (_state_a, tenant_a, _secret_a) = authenticated_app_state(&pool).await;
    let (state_b, _tenant_b, secret_b) = authenticated_app_state(&pool).await;
    let issuer = test_issuers::insert_active(&pool, &tenant_a).await;

    let resp = router(state_b)
        .oneshot(get_request(
            &format!("/api/v1/issuers/{}/credential-types", issuer.id.bare()),
            Some(&secret_b.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
