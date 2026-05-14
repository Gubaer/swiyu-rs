//! Integration tests for the issued-credential GET endpoints
//! (`GET /api/v1/issuers/{issuer_id}/credentials/{credential_id}`
//! and `GET /api/v1/issuers/{issuer_id}/credentials?…`).
//!
//! Drives requests through the full management router (auth +
//! extractors + serde + handler + persistence) using
//! `tower::ServiceExt::oneshot` against a `sqlx::test`-managed pool.
//! Each test seeds synthetic credentials via the persistence helpers
//! (no OIDC handler involved) and asserts the HTTP shape, the
//! filtering behaviour, and the pagination contract.

use axum::http::StatusCode;
use chrono::{Duration, Utc};
use sqlx::PgPool;
use tower::ServiceExt;

use swiyu_issuer::api_management::router;
use swiyu_issuer::domain::{
    CredentialOffer, INTEGRITY_HASH_LEN, IssuedCredential, IssuedCredentialState, Issuer, IssuerId,
    PreAuthCode, StatusListId, StatusListIndex, TenantId,
};
use swiyu_issuer::persistence;

use swiyu_issuer::test_support::api::tokens::mint_test_token;
use swiyu_issuer::test_support::api::{authenticated_app_state, build_state};
use swiyu_issuer::test_support::fixtures::SAMPLE_HOLDER_KEY_JKT;
use swiyu_issuer::test_support::http::{get_request, read_body};
use swiyu_issuer::test_support::persistence::tenants::insert_test_tenant;

async fn seed_offer(pool: &PgPool, issuer: &Issuer, vct: &str) -> CredentialOffer {
    let offer = CredentialOffer::new(
        issuer.tenant_id.clone(),
        issuer.id.clone(),
        vct.into(),
        serde_json::json!({}),
        PreAuthCode::generate(),
        Utc::now() + Duration::minutes(5),
    );
    swiyu_issuer::test_support::persistence::credential_offers::insert(pool, &offer).await;
    offer
}

#[allow(clippy::too_many_arguments)]
async fn seed_credential(
    pool: &PgPool,
    issuer: &Issuer,
    list_id: &StatusListId,
    list_index: u32,
    vct: &str,
    state: IssuedCredentialState,
    issued_at: chrono::DateTime<Utc>,
) -> IssuedCredential {
    let offer = seed_offer(pool, issuer, vct).await;
    let credential = IssuedCredential::new(
        issuer.tenant_id.clone(),
        issuer.id.clone(),
        offer.id,
        vct.into(),
        SAMPLE_HOLDER_KEY_JKT.into(),
        list_id.clone(),
        StatusListIndex::try_from(list_index).unwrap(),
        [0u8; INTEGRITY_HASH_LEN],
        issued_at,
        issued_at + Duration::days(365),
    );
    let mut conn = pool.acquire().await.unwrap();
    persistence::issued_credentials::insert(&mut conn, &credential)
        .await
        .unwrap();
    if state != IssuedCredentialState::Active {
        persistence::issued_credentials::set_state(
            &mut conn,
            &credential.tenant_id,
            &credential.id,
            state,
        )
        .await
        .unwrap();
    }
    IssuedCredential {
        state,
        ..credential
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn get_returns_credential_with_full_shape(pool: PgPool) {
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let issuer =
        swiyu_issuer::test_support::persistence::issuers::insert_active(&pool, &tenant_id).await;
    let list_id =
        swiyu_issuer::test_support::persistence::status_lists::provision(&pool, &issuer.id).await;
    let credential = seed_credential(
        &pool,
        &issuer,
        &list_id,
        7,
        "vc-test",
        IssuedCredentialState::Active,
        Utc::now(),
    )
    .await;

    let app = router(state);
    let response = app
        .oneshot(get_request(
            &format!(
                "/api/v1/issuers/{}/credentials/{}",
                issuer.id.bare(),
                credential.id.bare()
            ),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = read_body(response).await;
    assert_eq!(body["id"], credential.id.bare());
    assert_eq!(body["issuer_id"], issuer.id.bare());
    assert_eq!(body["vct"], "vc-test");
    assert_eq!(body["state"], "active");
    assert_eq!(body["expired"], false);
    assert_eq!(body["status_list_id"], list_id.bare());
    assert_eq!(body["status_list_index"], 7);
    assert!(body["issued_at"].is_string());
    assert!(body["expires_at"].is_string());
}

#[sqlx::test(migrations = "./migrations")]
async fn get_marks_past_expires_at_as_expired(pool: PgPool) {
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let issuer =
        swiyu_issuer::test_support::persistence::issuers::insert_active(&pool, &tenant_id).await;
    let list_id =
        swiyu_issuer::test_support::persistence::status_lists::provision(&pool, &issuer.id).await;

    // Insert directly so we can backdate `expires_at` past now.
    let offer = seed_offer(&pool, &issuer, "vc-test").await;
    let now = Utc::now();
    let past_issued_at = now - Duration::days(400);
    let credential = IssuedCredential::new(
        tenant_id.clone(),
        issuer.id.clone(),
        offer.id,
        "vc-test".into(),
        SAMPLE_HOLDER_KEY_JKT.into(),
        list_id,
        StatusListIndex::try_from(0u32).unwrap(),
        [0u8; INTEGRITY_HASH_LEN],
        past_issued_at,
        past_issued_at + Duration::days(30),
    );
    let mut conn = pool.acquire().await.unwrap();
    persistence::issued_credentials::insert(&mut conn, &credential)
        .await
        .unwrap();

    let app = router(state);
    let response = app
        .oneshot(get_request(
            &format!(
                "/api/v1/issuers/{}/credentials/{}",
                issuer.id.bare(),
                credential.id.bare()
            ),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = read_body(response).await;
    assert_eq!(body["state"], "active");
    assert_eq!(
        body["expired"], true,
        "credential past expires_at must report expired=true"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn get_returns_404_for_unknown_id(pool: PgPool) {
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let issuer =
        swiyu_issuer::test_support::persistence::issuers::insert_active(&pool, &tenant_id).await;
    let unknown = swiyu_issuer::domain::IssuedCredentialId::generate();

    let app = router(state);
    let response = app
        .oneshot(get_request(
            &format!(
                "/api/v1/issuers/{}/credentials/{}",
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
async fn get_with_wrong_issuer_returns_404(pool: PgPool) {
    // The credential exists for the tenant but under issuer A; the
    // request names issuer B (also owned by the tenant). Must
    // collapse to NotFound.
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let issuer_a =
        swiyu_issuer::test_support::persistence::issuers::insert_active(&pool, &tenant_id).await;
    let issuer_b =
        swiyu_issuer::test_support::persistence::issuers::insert_active(&pool, &tenant_id).await;
    let list_id =
        swiyu_issuer::test_support::persistence::status_lists::provision(&pool, &issuer_a.id).await;
    let credential = seed_credential(
        &pool,
        &issuer_a,
        &list_id,
        0,
        "vc-test",
        IssuedCredentialState::Active,
        Utc::now(),
    )
    .await;

    let app = router(state);
    let response = app
        .oneshot(get_request(
            &format!(
                "/api/v1/issuers/{}/credentials/{}",
                issuer_b.id.bare(),
                credential.id.bare()
            ),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "./migrations")]
async fn get_is_tenant_scoped(pool: PgPool) {
    let tenant_a = TenantId::generate();
    insert_test_tenant(&pool, &tenant_a).await;
    let issuer =
        swiyu_issuer::test_support::persistence::issuers::insert_active(&pool, &tenant_a).await;
    let list_id =
        swiyu_issuer::test_support::persistence::status_lists::provision(&pool, &issuer.id).await;
    let credential = seed_credential(
        &pool,
        &issuer,
        &list_id,
        0,
        "vc-test",
        IssuedCredentialState::Active,
        Utc::now(),
    )
    .await;

    let tenant_b = TenantId::generate();
    insert_test_tenant(&pool, &tenant_b).await;
    let secret_b = mint_test_token(&pool, &tenant_b).await;

    let app = router(build_state(pool.clone()));
    let response = app
        .oneshot(get_request(
            &format!(
                "/api/v1/issuers/{}/credentials/{}",
                issuer.id.bare(),
                credential.id.bare()
            ),
            Some(&secret_b.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "./migrations")]
async fn get_missing_bearer_returns_401(pool: PgPool) {
    let app = router(build_state(pool));
    let issuer_id = IssuerId::generate();
    let unknown = swiyu_issuer::domain::IssuedCredentialId::generate();
    let response = app
        .oneshot(get_request(
            &format!(
                "/api/v1/issuers/{}/credentials/{}",
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
async fn list_returns_credentials_newest_first(pool: PgPool) {
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let issuer =
        swiyu_issuer::test_support::persistence::issuers::insert_active(&pool, &tenant_id).await;
    let list_id =
        swiyu_issuer::test_support::persistence::status_lists::provision(&pool, &issuer.id).await;

    let now = Utc::now();
    let mut credential_ids = Vec::new();
    for offset_minutes in 0..3 {
        let credential = seed_credential(
            &pool,
            &issuer,
            &list_id,
            offset_minutes as u32,
            "vc-test",
            IssuedCredentialState::Active,
            now + Duration::minutes(offset_minutes),
        )
        .await;
        credential_ids.push(credential.id.bare().to_string());
    }

    let app = router(state);
    let response = app
        .oneshot(get_request(
            &format!("/api/v1/issuers/{}/credentials", issuer.id.bare()),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = read_body(response).await;
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 3);
    // Newest first → reverse insertion order.
    assert_eq!(items[0]["id"], credential_ids[2]);
    assert_eq!(items[1]["id"], credential_ids[1]);
    assert_eq!(items[2]["id"], credential_ids[0]);
    assert!(body["next_cursor"].is_null());
}

#[sqlx::test(migrations = "./migrations")]
async fn list_returns_only_url_issuers_credentials(pool: PgPool) {
    // The URL pins which issuer's credentials the list returns. A
    // request for issuer A's credentials must not include rows
    // belonging to issuer B, even when both issuers are owned by
    // the same tenant.
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let issuer_a =
        swiyu_issuer::test_support::persistence::issuers::insert_active(&pool, &tenant_id).await;
    let issuer_b =
        swiyu_issuer::test_support::persistence::issuers::insert_active(&pool, &tenant_id).await;
    let list_a =
        swiyu_issuer::test_support::persistence::status_lists::provision(&pool, &issuer_a.id).await;
    let list_b =
        swiyu_issuer::test_support::persistence::status_lists::provision(&pool, &issuer_b.id).await;
    let cred_a = seed_credential(
        &pool,
        &issuer_a,
        &list_a,
        0,
        "vc-test",
        IssuedCredentialState::Active,
        Utc::now(),
    )
    .await;
    seed_credential(
        &pool,
        &issuer_b,
        &list_b,
        0,
        "vc-test",
        IssuedCredentialState::Active,
        Utc::now(),
    )
    .await;

    let app = router(state);
    let response = app
        .oneshot(get_request(
            &format!("/api/v1/issuers/{}/credentials", issuer_a.id.bare()),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = read_body(response).await;
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], cred_a.id.bare());
}

#[sqlx::test(migrations = "./migrations")]
async fn list_filters_by_state(pool: PgPool) {
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let issuer =
        swiyu_issuer::test_support::persistence::issuers::insert_active(&pool, &tenant_id).await;
    let list_id =
        swiyu_issuer::test_support::persistence::status_lists::provision(&pool, &issuer.id).await;
    let active = seed_credential(
        &pool,
        &issuer,
        &list_id,
        0,
        "vc-test",
        IssuedCredentialState::Active,
        Utc::now(),
    )
    .await;
    let revoked = seed_credential(
        &pool,
        &issuer,
        &list_id,
        1,
        "vc-test",
        IssuedCredentialState::Revoked,
        Utc::now() + Duration::seconds(1),
    )
    .await;

    let app = router(state);
    let response = app
        .oneshot(get_request(
            &format!(
                "/api/v1/issuers/{}/credentials?state=revoked",
                issuer.id.bare()
            ),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = read_body(response).await;
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], revoked.id.bare());
    assert_ne!(items[0]["id"], active.id.bare());
}

#[sqlx::test(migrations = "./migrations")]
async fn list_filters_by_vct(pool: PgPool) {
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let issuer =
        swiyu_issuer::test_support::persistence::issuers::insert_active(&pool, &tenant_id).await;
    let list_id =
        swiyu_issuer::test_support::persistence::status_lists::provision(&pool, &issuer.id).await;
    seed_credential(
        &pool,
        &issuer,
        &list_id,
        0,
        "vc-residence",
        IssuedCredentialState::Active,
        Utc::now(),
    )
    .await;
    let other = seed_credential(
        &pool,
        &issuer,
        &list_id,
        1,
        "vc-other",
        IssuedCredentialState::Active,
        Utc::now() + Duration::seconds(1),
    )
    .await;

    let app = router(state);
    let response = app
        .oneshot(get_request(
            &format!(
                "/api/v1/issuers/{}/credentials?vct=vc-other",
                issuer.id.bare()
            ),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = read_body(response).await;
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], other.id.bare());
}

#[sqlx::test(migrations = "./migrations")]
async fn list_paginates_with_cursor(pool: PgPool) {
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let issuer =
        swiyu_issuer::test_support::persistence::issuers::insert_active(&pool, &tenant_id).await;
    let list_id =
        swiyu_issuer::test_support::persistence::status_lists::provision(&pool, &issuer.id).await;

    let now = Utc::now();
    for offset_minutes in 0..5 {
        seed_credential(
            &pool,
            &issuer,
            &list_id,
            offset_minutes as u32,
            "vc-test",
            IssuedCredentialState::Active,
            now + Duration::minutes(offset_minutes),
        )
        .await;
    }

    let app = router(state);
    let first = app
        .clone()
        .oneshot(get_request(
            &format!("/api/v1/issuers/{}/credentials?limit=2", issuer.id.bare()),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let first_body = read_body(first).await;
    assert_eq!(first_body["items"].as_array().unwrap().len(), 2);
    let cursor = first_body["next_cursor"]
        .as_str()
        .expect("next_cursor must be present mid-pagination")
        .to_string();

    let second = app
        .oneshot(get_request(
            &format!(
                "/api/v1/issuers/{}/credentials?limit=2&cursor={cursor}",
                issuer.id.bare()
            ),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::OK);
    let second_body = read_body(second).await;
    let second_items = second_body["items"].as_array().unwrap();
    assert_eq!(second_items.len(), 2);

    // The two pages must not overlap.
    let first_ids: Vec<&str> = first_body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["id"].as_str().unwrap())
        .collect();
    for item in second_items {
        assert!(!first_ids.contains(&item["id"].as_str().unwrap()));
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn list_for_other_tenants_issuer_returns_404(pool: PgPool) {
    // Tenant B's bearer requesting a list under tenant A's issuer
    // gets a 404 — the URL names an issuer they do not own.
    let tenant_a = TenantId::generate();
    insert_test_tenant(&pool, &tenant_a).await;
    let issuer =
        swiyu_issuer::test_support::persistence::issuers::insert_active(&pool, &tenant_a).await;
    let list_id =
        swiyu_issuer::test_support::persistence::status_lists::provision(&pool, &issuer.id).await;
    seed_credential(
        &pool,
        &issuer,
        &list_id,
        0,
        "vc-test",
        IssuedCredentialState::Active,
        Utc::now(),
    )
    .await;

    let tenant_b = TenantId::generate();
    insert_test_tenant(&pool, &tenant_b).await;
    let secret_b = mint_test_token(&pool, &tenant_b).await;

    let app = router(build_state(pool.clone()));
    let response = app
        .oneshot(get_request(
            &format!("/api/v1/issuers/{}/credentials", issuer.id.bare()),
            Some(&secret_b.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "./migrations")]
async fn list_for_unknown_issuer_returns_404(pool: PgPool) {
    let (state, _tenant_id, secret) = authenticated_app_state(&pool).await;
    let unknown_issuer = IssuerId::generate();

    let app = router(state);
    let response = app
        .oneshot(get_request(
            &format!("/api/v1/issuers/{}/credentials", unknown_issuer.bare()),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "./migrations")]
async fn list_rejects_invalid_state_filter(pool: PgPool) {
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let issuer =
        swiyu_issuer::test_support::persistence::issuers::insert_active(&pool, &tenant_id).await;

    let app = router(state);
    let response = app
        .oneshot(get_request(
            &format!(
                "/api/v1/issuers/{}/credentials?state=expired",
                issuer.id.bare()
            ),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrations = "./migrations")]
async fn list_rejects_out_of_range_limit(pool: PgPool) {
    let (state, tenant_id, secret) = authenticated_app_state(&pool).await;
    let issuer =
        swiyu_issuer::test_support::persistence::issuers::insert_active(&pool, &tenant_id).await;

    let app = router(state);
    let response = app
        .oneshot(get_request(
            &format!("/api/v1/issuers/{}/credentials?limit=0", issuer.id.bare()),
            Some(&secret.as_wire()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
