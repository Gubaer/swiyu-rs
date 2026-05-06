//! Integration tests for `POST /i/{issuer_id}/credential`.
//!
//! Drives requests through the full OIDC router (extractors + serde +
//! handler + persistence + DevSigningEngine) using
//! `tower::ServiceExt::oneshot` against a `sqlx::test`-managed pool.
//! The signing engine is real (DevSigningEngine), so the issued JWS
//! carries a genuine ES256 signature over the assertion key the
//! handler resolved from the issuer row.

use std::sync::Arc;

use axum::body::{self, Body};
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;

use swiyu_issuer::api_oidc::{AppState, Config, router};
use swiyu_issuer::domain::{
    AccessTokenSecret, AnySigningEngine, CredentialOffer, DevSigningEngine, Issuer, IssuerId,
    IssuerState, KeyRole, NonceSecret, PreAuthCode, SigningEngine, TenantId,
};
use swiyu_issuer::persistence;

const TEST_BASE_URL: &str = "http://issuer.example.com";
const FIXTURE_DID: &str =
    "did:tdw:scid-placeholder:reg.example.com:fce949f2-32c4-4915-8b60-0ee2f705231d";

fn build_state(pool: PgPool) -> AppState {
    let engine = AnySigningEngine::Dev(DevSigningEngine::new(pool.clone()));
    AppState::new(
        pool,
        Config {
            issuer_base_url: TEST_BASE_URL.into(),
            access_token_ttl: Duration::seconds(300),
            c_nonce_ttl: Duration::seconds(300),
        },
        Arc::new(engine),
    )
}

async fn insert_test_tenant(pool: &PgPool, tenant_id: &TenantId) {
    sqlx::query("INSERT INTO tenants (id, partner_id) VALUES ($1, NULL)")
        .bind(tenant_id.bare())
        .execute(pool)
        .await
        .unwrap();
}

async fn insert_issuer(pool: &PgPool, issuer: &Issuer) {
    let mut conn = pool.acquire().await.unwrap();
    persistence::issuers::insert(&mut conn, issuer)
        .await
        .unwrap();
}

/// Constructs a fully-onboarded issuer with a real assertion key
/// stored in the DevSigningEngine's table — the shape produced by
/// the create_issuer worker flow.
async fn create_onboarded_issuer(pool: &PgPool, tenant_id: &TenantId) -> Issuer {
    let engine = DevSigningEngine::new(pool.clone());
    let assertion = engine.generate_keypair(KeyRole::Assertion).await.unwrap();

    let issuer = Issuer {
        id: IssuerId::generate(),
        tenant_id: tenant_id.clone(),
        did: FIXTURE_DID.into(),
        state: Some(IssuerState::Active),
        description: Some("integration-test issuer".into()),
        authorized_key_id: None,
        authentication_key_id: None,
        assertion_key_id: Some(assertion.id),
        display_name: Some("Test Issuer".into()),
        logo_uri: None,
        locale: None,
        created_at: Utc::now(),
    };
    insert_issuer(pool, &issuer).await;
    issuer
}

async fn create_pending_offer(pool: &PgPool, issuer: &Issuer, claims: Value) -> CredentialOffer {
    let offer = CredentialOffer::new(
        issuer.tenant_id.clone(),
        issuer.id.clone(),
        "vc-test".into(),
        claims,
        PreAuthCode::generate(),
        Utc::now() + Duration::minutes(5),
    );
    let mut conn = pool.acquire().await.unwrap();
    persistence::credential_offers::insert(&mut conn, &offer)
        .await
        .unwrap();
    offer
}

async fn mint_oidc_access_token(
    pool: &PgPool,
    issuer: &Issuer,
    offer: &CredentialOffer,
) -> AccessTokenSecret {
    let secret = AccessTokenSecret::generate();
    let mut conn = pool.acquire().await.unwrap();
    persistence::oidc::access_tokens::insert(
        &mut conn,
        &issuer.tenant_id,
        &issuer.id,
        &offer.id,
        &secret.hash(),
        Utc::now() + Duration::minutes(5),
    )
    .await
    .unwrap();
    secret
}

async fn mint_nonce(pool: &PgPool, issuer: &Issuer, offer: &CredentialOffer) -> NonceSecret {
    let secret = NonceSecret::generate();
    let mut conn = pool.acquire().await.unwrap();
    persistence::oidc::nonces::insert(
        &mut conn,
        &issuer.tenant_id,
        &issuer.id,
        &offer.id,
        &secret.hash(),
        Utc::now() + Duration::minutes(5),
    )
    .await
    .unwrap();
    secret
}

/// Builds a wallet proof JWT shaped to satisfy `parse_wallet_proof`.
/// The credential handler does not verify the signature at v0.1.x,
/// so the third segment can be arbitrary.
fn build_proof_jwt(audience: &str, nonce: &str) -> String {
    let header = json!({
        "alg": "ES256",
        "typ": "openid4vci-proof+jwt",
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": "fixture-x",
            "y": "fixture-y",
        },
    });
    let payload = json!({
        "aud": audience,
        "iat": Utc::now().timestamp(),
        "nonce": nonce,
    });
    let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
    let s = URL_SAFE_NO_PAD.encode(b"fixture-signature");
    format!("{h}.{p}.{s}")
}

fn post_credential(issuer_id: &IssuerId, bearer: &str, body: Value) -> Request<Body> {
    let uri = format!("/i/{}/credential", issuer_id.bare());
    Request::builder()
        .method("POST")
        .uri(&uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

async fn read_body_value(response: axum::response::Response) -> Value {
    let bytes = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn credential_request_body(vct: &str, proof_jwt: &str) -> Value {
    json!({
        "format": "vc+sd-jwt",
        "vct": vct,
        "proof": {
            "proof_type": "jwt",
            "jwt": proof_jwt,
        },
    })
}

#[sqlx::test(migrations = "./migrations")]
async fn happy_path_returns_es256_signed_credential(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer = create_onboarded_issuer(&pool, &tenant_id).await;
    let offer = create_pending_offer(&pool, &issuer, json!({"name": "Alice", "age": 30})).await;
    let access_token = mint_oidc_access_token(&pool, &issuer, &offer).await;
    let nonce = mint_nonce(&pool, &issuer, &offer).await;

    let app = router(build_state(pool.clone()));
    let aud = format!("{TEST_BASE_URL}/i/{}", issuer.id.bare());
    let proof_jwt = build_proof_jwt(&aud, nonce.as_str());

    let response = app
        .oneshot(post_credential(
            &issuer.id,
            access_token.as_str(),
            credential_request_body("vc-test", &proof_jwt),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_body_value(response).await;
    let credential = body["credential"].as_str().expect("credential string");
    assert!(credential.ends_with('~'), "SD-JWT VC ends with `~`");

    let core = credential.trim_end_matches('~');
    let parts: Vec<&str> = core.split('.').collect();
    assert_eq!(parts.len(), 3, "JWS has three segments");

    let header_json: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
    assert_eq!(header_json["alg"], "ES256");
    assert_eq!(header_json["typ"], "vc+sd-jwt");
    assert_eq!(
        header_json["kid"],
        format!("{}#assertion-key-01", issuer.did)
    );

    let payload_json: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    assert_eq!(payload_json["iss"], issuer.did);
    assert_eq!(payload_json["vct"], "vc-test");
    assert_eq!(payload_json["name"], "Alice");
    assert_eq!(payload_json["age"], 30);

    // P-256 signatures in JWS are raw R||S — fixed 64 bytes.
    let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
    assert_eq!(sig_bytes.len(), 64, "ES256 JWS signature is 64 bytes");
}

#[sqlx::test(migrations = "./migrations")]
async fn issuer_without_assertion_key_returns_invalid_request(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;

    // Mirror the seeded dev row's shape: no SigningEngine keys.
    let issuer = Issuer {
        id: IssuerId::generate(),
        tenant_id: tenant_id.clone(),
        did: FIXTURE_DID.into(),
        state: None,
        description: None,
        authorized_key_id: None,
        authentication_key_id: None,
        assertion_key_id: None,
        display_name: None,
        logo_uri: None,
        locale: None,
        created_at: Utc::now(),
    };
    insert_issuer(&pool, &issuer).await;

    let offer = create_pending_offer(&pool, &issuer, json!({})).await;
    let access_token = mint_oidc_access_token(&pool, &issuer, &offer).await;
    let nonce = mint_nonce(&pool, &issuer, &offer).await;

    let app = router(build_state(pool.clone()));
    let aud = format!("{TEST_BASE_URL}/i/{}", issuer.id.bare());
    let proof_jwt = build_proof_jwt(&aud, nonce.as_str());

    let response = app
        .oneshot(post_credential(
            &issuer.id,
            access_token.as_str(),
            credential_request_body("vc-test", &proof_jwt),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = read_body_value(response).await;
    assert_eq!(body["error"], "invalid_request");
}

#[sqlx::test(migrations = "./migrations")]
async fn unknown_bearer_returns_invalid_token(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer = create_onboarded_issuer(&pool, &tenant_id).await;
    // No access token row inserted — the bearer is unknown.

    let app = router(build_state(pool.clone()));
    let aud = format!("{TEST_BASE_URL}/i/{}", issuer.id.bare());
    let proof_jwt = build_proof_jwt(&aud, "any-nonce");

    let response = app
        .oneshot(post_credential(
            &issuer.id,
            "unknown-bearer-value",
            credential_request_body("vc-test", &proof_jwt),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = read_body_value(response).await;
    assert_eq!(body["error"], "invalid_token");
}

#[sqlx::test(migrations = "./migrations")]
async fn vct_mismatch_with_offer_is_invalid_credential_request(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer = create_onboarded_issuer(&pool, &tenant_id).await;
    let offer = create_pending_offer(&pool, &issuer, json!({})).await;
    let access_token = mint_oidc_access_token(&pool, &issuer, &offer).await;
    let nonce = mint_nonce(&pool, &issuer, &offer).await;

    let app = router(build_state(pool.clone()));
    let aud = format!("{TEST_BASE_URL}/i/{}", issuer.id.bare());
    let proof_jwt = build_proof_jwt(&aud, nonce.as_str());

    let response = app
        .oneshot(post_credential(
            &issuer.id,
            access_token.as_str(),
            credential_request_body("vc-other", &proof_jwt),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = read_body_value(response).await;
    assert_eq!(body["error"], "invalid_credential_request");
}
