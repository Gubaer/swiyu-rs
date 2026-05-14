//! Integration tests for the issued-credential lifecycle handlers
//! (`POST /api/v1/issuers/{issuer_id}/credentials/{credential_id}/{suspend|unsuspend|revoke}`).
//!
//! Drives requests through the full management router (auth +
//! extractors + serde + handler + persistence) using
//! `tower::ServiceExt::oneshot` against a `sqlx::test`-managed pool.
//! Each test inserts a synthetic credential row + a fresh status list
//! and asserts both the HTTP response and the resulting DB state
//! (lifecycle column, status-list bitstring slot, committed_version).

use axum::http::StatusCode;
use sqlx::PgPool;
use tower::ServiceExt;

use swiyu_issuer::api_management::router;
use swiyu_issuer::domain::{
    BITSTRING_BYTES, IssuedCredential, IssuedCredentialState, StatusListId, StatusValue, TenantId,
};

use swiyu_issuer::test_support::api::tokens::mint_test_token;
use swiyu_issuer::test_support::api::{authenticated_app_state, build_state};
use swiyu_issuer::test_support::http::{post_request_empty, read_body};
use swiyu_issuer::test_support::persistence::issued_credentials::CredentialSeed;
use swiyu_issuer::test_support::persistence::tenants::insert_test_tenant;

async fn fetch_state(pool: &PgPool, credential: &IssuedCredential) -> String {
    sqlx::query_scalar("SELECT state FROM issued_credentials WHERE id = $1")
        .bind(credential.id.bare())
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn fetch_status_bit(pool: &PgPool, credential: &IssuedCredential) -> StatusValue {
    let bitstring: Vec<u8> = sqlx::query_scalar("SELECT bitstring FROM status_lists WHERE id = $1")
        .bind(credential.status_list_id.bare())
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(bitstring.len(), BITSTRING_BYTES);
    swiyu_issuer::test_support::persistence::status_lists::read_slot(
        &bitstring,
        credential.status_list_index,
    )
}

async fn fetch_committed_version(pool: &PgPool, list_id: &StatusListId) -> i64 {
    sqlx::query_scalar("SELECT committed_version FROM status_lists WHERE id = $1")
        .bind(list_id.bare())
        .fetch_one(pool)
        .await
        .unwrap()
}

fn lifecycle_uri(credential: &IssuedCredential, action: &str) -> String {
    format!(
        "/api/v1/issuers/{}/credentials/{}/{}",
        credential.issuer_id.bare(),
        credential.id.bare(),
        action
    )
}

#[sqlx::test(migrations = "./migrations")]
async fn suspend_active_flips_state_and_status_bit(pool: PgPool) {
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let issuer =
        swiyu_issuer::test_support::persistence::issuers::insert_active(&pool, &tenant_id).await;
    let list_id =
        swiyu_issuer::test_support::persistence::status_lists::provision(&pool, &issuer.id).await;
    let credential = CredentialSeed::new(&pool, &issuer, &list_id, 0)
        .insert()
        .await;
    let baseline_version = fetch_committed_version(&pool, &list_id).await;

    let app = router(state);
    let response = app
        .oneshot(post_request_empty(
            &lifecycle_uri(&credential, "suspend"),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = read_body(response).await;
    assert_eq!(body["state"], "suspended");
    assert_eq!(body["expired"], false);
    assert_eq!(body["status_list_index"], 0);

    assert_eq!(fetch_state(&pool, &credential).await, "suspended");
    assert_eq!(
        fetch_status_bit(&pool, &credential).await,
        StatusValue::Suspended
    );
    assert_eq!(
        fetch_committed_version(&pool, &list_id).await,
        baseline_version + 1
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn unsuspend_restores_active_and_clears_status_bit(pool: PgPool) {
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let issuer =
        swiyu_issuer::test_support::persistence::issuers::insert_active(&pool, &tenant_id).await;
    let list_id =
        swiyu_issuer::test_support::persistence::status_lists::provision(&pool, &issuer.id).await;
    let credential = CredentialSeed::new(&pool, &issuer, &list_id, 0)
        .state(IssuedCredentialState::Suspended)
        .status_bit(StatusValue::Suspended)
        .insert()
        .await;

    let app = router(state);
    let response = app
        .oneshot(post_request_empty(
            &lifecycle_uri(&credential, "unsuspend"),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = read_body(response).await;
    assert_eq!(body["state"], "active");

    assert_eq!(fetch_state(&pool, &credential).await, "active");
    assert_eq!(
        fetch_status_bit(&pool, &credential).await,
        StatusValue::Valid
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn revoke_active_flips_state_and_status_bit(pool: PgPool) {
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let issuer =
        swiyu_issuer::test_support::persistence::issuers::insert_active(&pool, &tenant_id).await;
    let list_id =
        swiyu_issuer::test_support::persistence::status_lists::provision(&pool, &issuer.id).await;
    let credential = CredentialSeed::new(&pool, &issuer, &list_id, 0)
        .insert()
        .await;

    let app = router(state);
    let response = app
        .oneshot(post_request_empty(
            &lifecycle_uri(&credential, "revoke"),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = read_body(response).await;
    assert_eq!(body["state"], "revoked");

    assert_eq!(fetch_state(&pool, &credential).await, "revoked");
    assert_eq!(
        fetch_status_bit(&pool, &credential).await,
        StatusValue::Revoked
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn revoke_suspended_succeeds(pool: PgPool) {
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let issuer =
        swiyu_issuer::test_support::persistence::issuers::insert_active(&pool, &tenant_id).await;
    let list_id =
        swiyu_issuer::test_support::persistence::status_lists::provision(&pool, &issuer.id).await;
    let credential = CredentialSeed::new(&pool, &issuer, &list_id, 0)
        .state(IssuedCredentialState::Suspended)
        .status_bit(StatusValue::Suspended)
        .insert()
        .await;

    let app = router(state);
    let response = app
        .oneshot(post_request_empty(
            &lifecycle_uri(&credential, "revoke"),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(fetch_state(&pool, &credential).await, "revoked");
}

#[sqlx::test(migrations = "./migrations")]
async fn suspend_already_suspended_returns_409(pool: PgPool) {
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let issuer =
        swiyu_issuer::test_support::persistence::issuers::insert_active(&pool, &tenant_id).await;
    let list_id =
        swiyu_issuer::test_support::persistence::status_lists::provision(&pool, &issuer.id).await;
    let credential = CredentialSeed::new(&pool, &issuer, &list_id, 0)
        .state(IssuedCredentialState::Suspended)
        .status_bit(StatusValue::Suspended)
        .insert()
        .await;

    let app = router(state);
    let response = app
        .oneshot(post_request_empty(
            &lifecycle_uri(&credential, "suspend"),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = read_body(response).await;
    assert_eq!(body["error"], "conflict");
    // State + bit unchanged.
    assert_eq!(fetch_state(&pool, &credential).await, "suspended");
}

#[sqlx::test(migrations = "./migrations")]
async fn unsuspend_active_returns_409(pool: PgPool) {
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let issuer =
        swiyu_issuer::test_support::persistence::issuers::insert_active(&pool, &tenant_id).await;
    let list_id =
        swiyu_issuer::test_support::persistence::status_lists::provision(&pool, &issuer.id).await;
    let credential = CredentialSeed::new(&pool, &issuer, &list_id, 0)
        .insert()
        .await;

    let app = router(state);
    let response = app
        .oneshot(post_request_empty(
            &lifecycle_uri(&credential, "unsuspend"),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[sqlx::test(migrations = "./migrations")]
async fn revoke_already_revoked_returns_409(pool: PgPool) {
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let issuer =
        swiyu_issuer::test_support::persistence::issuers::insert_active(&pool, &tenant_id).await;
    let list_id =
        swiyu_issuer::test_support::persistence::status_lists::provision(&pool, &issuer.id).await;
    let credential = CredentialSeed::new(&pool, &issuer, &list_id, 0)
        .state(IssuedCredentialState::Revoked)
        .status_bit(StatusValue::Revoked)
        .insert()
        .await;

    let app = router(state);
    let response = app
        .oneshot(post_request_empty(
            &lifecycle_uri(&credential, "revoke"),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[sqlx::test(migrations = "./migrations")]
async fn lifecycle_op_against_other_tenant_returns_404(pool: PgPool) {
    // Tenant A owns the credential. Tenant B's bearer must see 404,
    // not 409 — same probe-prevention discipline as `find`.
    let tenant_a = TenantId::generate();
    insert_test_tenant(&pool, &tenant_a).await;
    let issuer =
        swiyu_issuer::test_support::persistence::issuers::insert_active(&pool, &tenant_a).await;
    let list_id =
        swiyu_issuer::test_support::persistence::status_lists::provision(&pool, &issuer.id).await;
    let credential = CredentialSeed::new(&pool, &issuer, &list_id, 0)
        .insert()
        .await;

    let tenant_b = TenantId::generate();
    insert_test_tenant(&pool, &tenant_b).await;
    let secret_b = mint_test_token(&pool, &tenant_b).await;

    let app = router(build_state(pool.clone()));
    let response = app
        .oneshot(post_request_empty(
            &lifecycle_uri(&credential, "suspend"),
            Some(&secret_b.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    // Tenant A's row stays Active; the cross-tenant call must not
    // reach set_state.
    assert_eq!(fetch_state(&pool, &credential).await, "active");
}

#[sqlx::test(migrations = "./migrations")]
async fn unknown_credential_returns_404(pool: PgPool) {
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let issuer =
        swiyu_issuer::test_support::persistence::issuers::insert_active(&pool, &tenant_id).await;

    let app = router(state);
    let unknown = swiyu_issuer::domain::IssuedCredentialId::generate();
    let response = app
        .oneshot(post_request_empty(
            &format!(
                "/api/v1/issuers/{}/credentials/{}/suspend",
                issuer.id.bare(),
                unknown.bare()
            ),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "./migrations")]
async fn lifecycle_op_with_wrong_issuer_returns_404(pool: PgPool) {
    // The credential exists for the tenant but under issuer A; the
    // request names issuer B (also owned by the tenant). Must
    // collapse to NotFound without applying the transition.
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let issuer_a =
        swiyu_issuer::test_support::persistence::issuers::insert_active(&pool, &tenant_id).await;
    let issuer_b =
        swiyu_issuer::test_support::persistence::issuers::insert_active(&pool, &tenant_id).await;
    let list_id =
        swiyu_issuer::test_support::persistence::status_lists::provision(&pool, &issuer_a.id).await;
    let credential = CredentialSeed::new(&pool, &issuer_a, &list_id, 0)
        .insert()
        .await;

    let app = router(state);
    let response = app
        .oneshot(post_request_empty(
            &format!(
                "/api/v1/issuers/{}/credentials/{}/suspend",
                issuer_b.id.bare(),
                credential.id.bare()
            ),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    // The original row stays Active; the cross-issuer call must not
    // reach set_state.
    assert_eq!(fetch_state(&pool, &credential).await, "active");
}

#[sqlx::test(migrations = "./migrations")]
async fn missing_bearer_returns_401(pool: PgPool) {
    let app = router(build_state(pool));
    let issuer_id = swiyu_issuer::domain::IssuerId::generate();
    let unknown = swiyu_issuer::domain::IssuedCredentialId::generate();
    let response = app
        .oneshot(post_request_empty(
            &format!(
                "/api/v1/issuers/{}/credentials/{}/suspend",
                issuer_id.bare(),
                unknown.bare()
            ),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "./migrations")]
async fn malformed_credential_id_returns_400(pool: PgPool) {
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let issuer =
        swiyu_issuer::test_support::persistence::issuers::insert_active(&pool, &tenant_id).await;

    let app = router(state);
    let response = app
        .oneshot(post_request_empty(
            &format!(
                "/api/v1/issuers/{}/credentials/notValid0/suspend",
                issuer.id.bare()
            ),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = read_body(response).await;
    assert_eq!(body["error"], "invalid_input");
}

#[sqlx::test(migrations = "./migrations")]
async fn malformed_issuer_id_returns_400(pool: PgPool) {
    let (state, _tenant_id, secret) = authenticated_app_state(&pool).await;

    let app = router(state);
    let response = app
        .oneshot(post_request_empty(
            "/api/v1/issuers/notValid0/credentials/9hXq2vRtL8pK7f/suspend",
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
