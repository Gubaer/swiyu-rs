//! Integration tests for `/api/v1/credential-types` CRUD.
//!
//! Drives requests through the full management router using
//! `tower::ServiceExt::oneshot` against a `sqlx::test`-managed pool.
//! Each test seeds a tenant + API token via `authenticated_app_state`
//! and exercises one slice of the CRUD surface.

use axum::http::StatusCode;
use serde_json::json;
use sqlx::PgPool;
use tower::ServiceExt;

use swiyu_issuer::api_management::router;
use swiyu_issuer::domain::{CredentialTypeId, IssuerCredentialTypeAssignment};
use swiyu_issuer::persistence;

use swiyu_issuer::test_support::api::authenticated_app_state;
use swiyu_issuer::test_support::http::{
    get_request, patch_request_json, post_request_empty, post_request_json, read_body,
};
use swiyu_issuer::test_support::persistence::issuers as test_issuers;

fn valid_create_body() -> serde_json::Value {
    json!({
        "vct": "urn:example:proof-of-residency",
        "claim_schema": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "first_name": { "type": "string" },
                "last_name":  { "type": "string" }
            },
            "required": ["first_name", "last_name"]
        },
        "claims": {},
        "display": [],
        "internal_description": "Sample credential type",
        "default_validity_seconds": 31_536_000_u64,
        "revocation_mode": "revocable_and_suspendable"
    })
}

#[sqlx::test(migrations = "./migrations")]
async fn create_happy_path_returns_201_and_persists_row(pool: PgPool) {
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let app = router(state);

    let response = app
        .oneshot(post_request_json(
            "/api/v1/credential-types",
            Some(&secret.as_wire()),
            valid_create_body(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let body = read_body(response).await;
    let id_str = body["credential_type_id"]
        .as_str()
        .expect("credential_type_id is a string");
    let id = CredentialTypeId::from_bare(id_str.to_string()).expect("id parses");

    let mut conn = pool.acquire().await.unwrap();
    let row = persistence::credential_types::find_by_id_for_tenant(&mut conn, &tenant_id, &id)
        .await
        .unwrap()
        .expect("row persisted");
    assert_eq!(row.vct, "urn:example:proof-of-residency");
    assert_eq!(
        row.default_validity_duration,
        chrono::Duration::seconds(31_536_000)
    );
    assert!(row.retired_at.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn create_rejects_invalid_schema(pool: PgPool) {
    let (state, _tenant_id, secret) = authenticated_app_state(&pool).await;
    let app = router(state);

    let mut body = valid_create_body();
    // `type: 42` is a structural error JSON Schema rejects at compile.
    body["claim_schema"] = json!({ "type": 42 });

    let response = app
        .oneshot(post_request_json(
            "/api/v1/credential-types",
            Some(&secret.as_wire()),
            body,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = read_body(response).await;
    assert_eq!(body["error"], "invalid_input");
    assert!(body["details"].as_str().unwrap().contains("claim_schema"));
}

#[sqlx::test(migrations = "./migrations")]
async fn create_rejects_unknown_revocation_mode(pool: PgPool) {
    let (state, _tenant_id, secret) = authenticated_app_state(&pool).await;
    let app = router(state);

    let mut body = valid_create_body();
    body["revocation_mode"] = json!("nope");
    let response = app
        .oneshot(post_request_json(
            "/api/v1/credential-types",
            Some(&secret.as_wire()),
            body,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrations = "./migrations")]
async fn create_rejects_zero_validity(pool: PgPool) {
    let (state, _tenant_id, secret) = authenticated_app_state(&pool).await;
    let app = router(state);

    let mut body = valid_create_body();
    body["default_validity_seconds"] = json!(0);
    let response = app
        .oneshot(post_request_json(
            "/api/v1/credential-types",
            Some(&secret.as_wire()),
            body,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrations = "./migrations")]
async fn create_duplicate_vct_within_tenant_returns_409(pool: PgPool) {
    let (state, _tenant_id, secret) = authenticated_app_state(&pool).await;
    let app = router(state.clone());

    let first = app
        .oneshot(post_request_json(
            "/api/v1/credential-types",
            Some(&secret.as_wire()),
            valid_create_body(),
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);

    let app = router(state);
    let second = app
        .oneshot(post_request_json(
            "/api/v1/credential-types",
            Some(&secret.as_wire()),
            valid_create_body(),
        ))
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::CONFLICT);
}

#[sqlx::test(migrations = "./migrations")]
async fn get_returns_404_for_unknown_id(pool: PgPool) {
    let (state, _tenant_id, secret) = authenticated_app_state(&pool).await;
    let app = router(state);

    let unknown = CredentialTypeId::generate();
    let uri = format!("/api/v1/credential-types/{}", unknown.bare());
    let response = app
        .oneshot(get_request(&uri, Some(&secret.as_wire())))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "./migrations")]
async fn get_returns_404_cross_tenant(pool: PgPool) {
    // tenant_a creates a credential type; tenant_b cannot see it.
    let (state_a, _tenant_a, secret_a) = authenticated_app_state(&pool).await;
    let (state_b, _tenant_b, secret_b) = authenticated_app_state(&pool).await;

    let create = router(state_a)
        .oneshot(post_request_json(
            "/api/v1/credential-types",
            Some(&secret_a.as_wire()),
            valid_create_body(),
        ))
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::CREATED);
    let id = read_body(create).await["credential_type_id"]
        .as_str()
        .unwrap()
        .to_string();

    let response = router(state_b)
        .oneshot(get_request(
            &format!("/api/v1/credential-types/{id}"),
            Some(&secret_b.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "./migrations")]
async fn list_returns_tenant_scoped_page(pool: PgPool) {
    let (state, _tenant_id, secret) = authenticated_app_state(&pool).await;
    let app = router(state.clone());

    let response = app
        .oneshot(post_request_json(
            "/api/v1/credential-types",
            Some(&secret.as_wire()),
            valid_create_body(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let app = router(state);
    let response = app
        .oneshot(get_request(
            "/api/v1/credential-types",
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = read_body(response).await;
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["vct"], "urn:example:proof-of-residency");
    assert!(body["next_cursor"].is_null());
}

#[sqlx::test(migrations = "./migrations")]
async fn list_excludes_retired_by_default(pool: PgPool) {
    let (state, _tenant_id, secret) = authenticated_app_state(&pool).await;
    let app = router(state.clone());

    let create_resp = app
        .oneshot(post_request_json(
            "/api/v1/credential-types",
            Some(&secret.as_wire()),
            valid_create_body(),
        ))
        .await
        .unwrap();
    let id = read_body(create_resp).await["credential_type_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Retire it.
    let app = router(state.clone());
    let retire_resp = app
        .oneshot(post_request_empty(
            &format!("/api/v1/credential-types/{id}/retire"),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(retire_resp.status(), StatusCode::OK);

    // Default list excludes retired.
    let app = router(state.clone());
    let resp = app
        .oneshot(get_request(
            "/api/v1/credential-types",
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    let body = read_body(resp).await;
    assert!(body["items"].as_array().unwrap().is_empty());

    // ?retired=true includes it.
    let app = router(state);
    let resp = app
        .oneshot(get_request(
            "/api/v1/credential-types?retired=true",
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    let body = read_body(resp).await;
    assert_eq!(body["items"].as_array().unwrap().len(), 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn patch_updates_subset_of_structured_fields(pool: PgPool) {
    let (state, _tenant_id, secret) = authenticated_app_state(&pool).await;
    let app = router(state.clone());

    let create_resp = app
        .oneshot(post_request_json(
            "/api/v1/credential-types",
            Some(&secret.as_wire()),
            valid_create_body(),
        ))
        .await
        .unwrap();
    let id = read_body(create_resp).await["credential_type_id"]
        .as_str()
        .unwrap()
        .to_string();

    let app = router(state);
    let patch_body = json!({
        "internal_description": "Updated description",
        "revocation_mode": "revocable"
    });
    let resp = app
        .oneshot(patch_request_json(
            &format!("/api/v1/credential-types/{id}"),
            Some(&secret.as_wire()),
            patch_body,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_body(resp).await;
    assert_eq!(body["internal_description"], "Updated description");
    assert_eq!(body["revocation_mode"], "revocable");
    // Unchanged fields keep their value.
    assert_eq!(body["vct"], "urn:example:proof-of-residency");
}

#[sqlx::test(migrations = "./migrations")]
async fn patch_returns_404_for_unknown_id(pool: PgPool) {
    let (state, _tenant_id, secret) = authenticated_app_state(&pool).await;
    let app = router(state);

    let unknown = CredentialTypeId::generate();
    let resp = app
        .oneshot(patch_request_json(
            &format!("/api/v1/credential-types/{}", unknown.bare()),
            Some(&secret.as_wire()),
            json!({ "revocation_mode": "revocable" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "./migrations")]
async fn retire_stamps_retired_at_and_cascades_assignments(pool: PgPool) {
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let issuer = test_issuers::insert_active(&pool, &tenant_id).await;

    let app = router(state.clone());
    let create_resp = app
        .oneshot(post_request_json(
            "/api/v1/credential-types",
            Some(&secret.as_wire()),
            valid_create_body(),
        ))
        .await
        .unwrap();
    let id_str = read_body(create_resp).await["credential_type_id"]
        .as_str()
        .unwrap()
        .to_string();
    let id = CredentialTypeId::from_bare(id_str.clone()).unwrap();

    // Seed an assignment row directly via persistence — no management API
    // for credential-type ↔ issuer assignment exists yet.
    let mut conn = pool.acquire().await.unwrap();
    persistence::issuer_credential_types::assign(
        &mut conn,
        &IssuerCredentialTypeAssignment::new(issuer.id.clone(), id.clone(), tenant_id.clone()),
    )
    .await
    .unwrap();

    let app = router(state.clone());
    let resp = app
        .oneshot(post_request_empty(
            &format!("/api/v1/credential-types/{id_str}/retire"),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // The cascade DELETE removed the assignment row.
    let remaining = persistence::issuer_credential_types::list_by_credential_type(&mut conn, &id)
        .await
        .unwrap();
    assert!(remaining.is_empty());

    // Get reports retired_at set.
    let app = router(state);
    let resp = app
        .oneshot(get_request(
            &format!("/api/v1/credential-types/{id_str}"),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_body(resp).await;
    assert!(!body["retired_at"].is_null());
}

#[sqlx::test(migrations = "./migrations")]
async fn retire_returns_404_for_unknown_id(pool: PgPool) {
    let (state, _tenant_id, secret) = authenticated_app_state(&pool).await;
    let app = router(state);

    let unknown = CredentialTypeId::generate();
    let resp = app
        .oneshot(post_request_empty(
            &format!("/api/v1/credential-types/{}/retire", unknown.bare()),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "./migrations")]
async fn create_rejects_request_without_authorization(pool: PgPool) {
    let (state, _tenant_id, _secret) = authenticated_app_state(&pool).await;
    let app = router(state);

    let resp = app
        .oneshot(post_request_json(
            "/api/v1/credential-types",
            None,
            valid_create_body(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
