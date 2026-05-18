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
    get_request, patch_request_json, post_request_empty, post_request_json, put_request_json,
    read_body,
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

async fn create_and_return_id(
    state: swiyu_issuer::api_management::AppState,
    secret: &swiyu_issuer::domain::ApiTokenSecret,
) -> String {
    let app = router(state);
    let resp = app
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
async fn put_schema_happy_path_bumps_fetched_at(pool: PgPool) {
    let (state, _tenant_id, secret) = authenticated_app_state(&pool).await;
    let id = create_and_return_id(state.clone(), &secret).await;

    let new_schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": { "age": { "type": "integer" } },
        "required": ["age"]
    });

    let app = router(state);
    let resp = app
        .oneshot(put_request_json(
            &format!("/api/v1/credential-types/{id}/schema"),
            Some(&secret.as_wire()),
            new_schema,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_body(resp).await;
    // The credential-type metadata now carries a non-null
    // claim_schema_fetched_at — the create call leaves it null.
    assert!(!body["claim_schema_fetched_at"].is_null());
}

#[sqlx::test(migrations = "./migrations")]
async fn put_schema_rejects_invalid_schema(pool: PgPool) {
    let (state, _tenant_id, secret) = authenticated_app_state(&pool).await;
    let id = create_and_return_id(state.clone(), &secret).await;

    // `type: 42` doesn't compile.
    let app = router(state);
    let resp = app
        .oneshot(put_request_json(
            &format!("/api/v1/credential-types/{id}/schema"),
            Some(&secret.as_wire()),
            json!({ "type": 42 }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = read_body(resp).await;
    assert_eq!(body["error"], "invalid_input");
    assert!(body["details"].as_str().unwrap().contains("claim_schema"));
}

#[sqlx::test(migrations = "./migrations")]
async fn put_then_get_schema_round_trips_byte_identical(pool: PgPool) {
    let (state, _tenant_id, secret) = authenticated_app_state(&pool).await;
    let id = create_and_return_id(state.clone(), &secret).await;

    let new_schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": { "age": { "type": "integer" } },
        "required": ["age"]
    });

    let put_resp = router(state.clone())
        .oneshot(put_request_json(
            &format!("/api/v1/credential-types/{id}/schema"),
            Some(&secret.as_wire()),
            new_schema.clone(),
        ))
        .await
        .unwrap();
    assert_eq!(put_resp.status(), StatusCode::OK);

    let get_resp = router(state)
        .oneshot(get_request(
            &format!("/api/v1/credential-types/{id}/schema"),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(get_resp.status(), StatusCode::OK);
    // Content-Type must be schema+json so downstream tooling treats
    // the body as a JSON Schema rather than plain JSON.
    let ct = get_resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(ct, "application/schema+json");

    let bytes = axum::body::to_bytes(get_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(parsed, new_schema);
}

#[sqlx::test(migrations = "./migrations")]
async fn get_schema_returns_404_cross_tenant(pool: PgPool) {
    let (state_a, _t_a, secret_a) = authenticated_app_state(&pool).await;
    let (state_b, _t_b, secret_b) = authenticated_app_state(&pool).await;

    let id = create_and_return_id(state_a, &secret_a).await;

    let resp = router(state_b)
        .oneshot(get_request(
            &format!("/api/v1/credential-types/{id}/schema"),
            Some(&secret_b.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "./migrations")]
async fn put_schema_returns_404_cross_tenant(pool: PgPool) {
    let (state_a, _t_a, secret_a) = authenticated_app_state(&pool).await;
    let (state_b, _t_b, secret_b) = authenticated_app_state(&pool).await;

    let id = create_and_return_id(state_a, &secret_a).await;

    let new_schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object"
    });
    let resp = router(state_b)
        .oneshot(put_request_json(
            &format!("/api/v1/credential-types/{id}/schema"),
            Some(&secret_b.as_wire()),
            new_schema,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "./migrations")]
async fn put_display_round_trips_through_get(pool: PgPool) {
    let (state, _tenant_id, secret) = authenticated_app_state(&pool).await;
    let id = create_and_return_id(state.clone(), &secret).await;

    let new_display = json!([
        { "name": "Proof of residency", "locale": "en-US" },
        { "name": "Wohnsitznachweis",   "locale": "de-CH" }
    ]);

    let put = router(state.clone())
        .oneshot(put_request_json(
            &format!("/api/v1/credential-types/{id}/display"),
            Some(&secret.as_wire()),
            new_display.clone(),
        ))
        .await
        .unwrap();
    assert_eq!(put.status(), StatusCode::OK);

    let get = router(state)
        .oneshot(get_request(
            &format!("/api/v1/credential-types/{id}/display"),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(get.status(), StatusCode::OK);
    let body = read_body(get).await;
    assert_eq!(body, new_display);
}

#[sqlx::test(migrations = "./migrations")]
async fn put_display_rejects_object(pool: PgPool) {
    let (state, _tenant_id, secret) = authenticated_app_state(&pool).await;
    let id = create_and_return_id(state.clone(), &secret).await;

    let resp = router(state)
        .oneshot(put_request_json(
            &format!("/api/v1/credential-types/{id}/display"),
            Some(&secret.as_wire()),
            json!({ "wrong": "shape" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrations = "./migrations")]
async fn put_claims_round_trips_through_get(pool: PgPool) {
    let (state, _tenant_id, secret) = authenticated_app_state(&pool).await;
    let id = create_and_return_id(state.clone(), &secret).await;

    let new_claims = json!({
        "first_name": { "display": [{ "name": "First name", "locale": "en-US" }] }
    });

    let put = router(state.clone())
        .oneshot(put_request_json(
            &format!("/api/v1/credential-types/{id}/claims"),
            Some(&secret.as_wire()),
            new_claims.clone(),
        ))
        .await
        .unwrap();
    assert_eq!(put.status(), StatusCode::OK);

    let get = router(state)
        .oneshot(get_request(
            &format!("/api/v1/credential-types/{id}/claims"),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(get.status(), StatusCode::OK);
    let body = read_body(get).await;
    assert_eq!(body, new_claims);
}

#[sqlx::test(migrations = "./migrations")]
async fn put_claims_rejects_array(pool: PgPool) {
    let (state, _tenant_id, secret) = authenticated_app_state(&pool).await;
    let id = create_and_return_id(state.clone(), &secret).await;

    let resp = router(state)
        .oneshot(put_request_json(
            &format!("/api/v1/credential-types/{id}/claims"),
            Some(&secret.as_wire()),
            json!([]),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
