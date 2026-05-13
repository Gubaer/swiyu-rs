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
    KeyRole, NonceSecret, PreAuthCode, SigningEngine, TenantId,
};
use swiyu_issuer::persistence;

const TEST_BASE_URL: &str = "http://issuer.example.com";
const FIXTURE_DID: &str =
    "did:tdw:scid-placeholder:reg.example.com:fce949f2-32c4-4915-8b60-0ee2f705231d";
const FIXTURE_STATUS_REGISTRY_ENTRY_ID: &str = "11111111-2222-3333-4444-555555555555";
const FIXTURE_STATUS_REGISTRY_URL: &str =
    "https://registry.example.invalid/api/v1/statuslist/11111111-2222-3333-4444-555555555555.jwt";

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

#[path = "common/mod.rs"]
mod common;
use common::tenants::insert_test_tenant;

/// Constructs a fully-onboarded issuer: a real assertion key stored
/// in the DevSigningEngine's table, plus a status_lists row carrying
/// fixture registry coordinates (entry id + public URL). Mirrors the
/// shape produced by the create_issuer worker once both
/// `create_status_list_entry` and `provision_status_list` have run.
async fn create_onboarded_issuer(pool: &PgPool, tenant_id: &TenantId) -> Issuer {
    let engine = DevSigningEngine::new(pool.clone());
    let assertion = engine.generate_keypair(KeyRole::Assertion).await.unwrap();

    let issuer = Issuer {
        did: FIXTURE_DID.into(),
        assertion_key_id: Some(assertion.id),
        ..common::issuers::active(tenant_id)
    };
    common::issuers::insert(pool, &issuer).await;
    provision_test_status_list(pool, &issuer).await;
    issuer
}

/// Inserts a `status_lists` row for `issuer` with fixture registry
/// coordinates and re-points `issuers.current_status_list_id` at it.
async fn provision_test_status_list(pool: &PgPool, issuer: &Issuer) {
    let mut conn = pool.acquire().await.unwrap();
    persistence::status_lists::provision_for_issuer(
        &mut conn,
        &issuer.id,
        Some(FIXTURE_STATUS_REGISTRY_ENTRY_ID),
        Some(FIXTURE_STATUS_REGISTRY_URL),
    )
    .await
    .unwrap();
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
    common::credential_offers::insert(pool, &offer).await;
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

/// Builds a wallet proof JWT signed with a fresh Ed25519 keypair.
/// The header carries the matching `jwk`; the JWS verifies cleanly
/// against `verify_wallet_proof_signature` in the credential handler.
fn build_proof_jwt(audience: &str, nonce: &str) -> String {
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let x_b64 = URL_SAFE_NO_PAD.encode(verifying_key.to_bytes());

    let header = json!({
        "alg": "EdDSA",
        "typ": "openid4vci-proof+jwt",
        "jwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x_b64,
        },
    });
    let payload = json!({
        "aud": audience,
        "iat": Utc::now().timestamp(),
        "nonce": nonce,
    });
    let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
    let signing_input = format!("{h}.{p}");
    let signature = signing_key.sign(signing_input.as_bytes());
    let s = URL_SAFE_NO_PAD.encode(signature.to_bytes());
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
        did: FIXTURE_DID.into(),
        state: None,
        ..common::issuers::active(&tenant_id)
    };
    common::issuers::insert(&pool, &issuer).await;

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
async fn issuance_inserts_issued_credential_row(pool: PgPool) {
    // Drives /credential end-to-end and asserts that the
    // local issuer-side trace landed: an `issued_credentials`
    // row exists for the offer with the expected `(status_list,
    // index, vct, state, integrity_hash)` shape.
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer = create_onboarded_issuer(&pool, &tenant_id).await;
    let offer = create_pending_offer(&pool, &issuer, json!({"name": "Alice"})).await;
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
    let credential = body["credential"].as_str().unwrap().to_string();

    let stored: (String, String, i32, String, String, Vec<u8>) = sqlx::query_as(
        "SELECT vct, state, status_list_index, status_list_id, credential_offer_id, integrity_hash \
         FROM issued_credentials WHERE credential_offer_id = $1",
    )
    .bind(offer.id.bare())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stored.0, "vc-test");
    assert_eq!(stored.1, "active");
    assert_eq!(stored.2, 0, "first issuance must allocate index 0");
    assert_eq!(stored.4, offer.id.bare());
    use sha2::{Digest, Sha256};
    let expected_hash: Vec<u8> = Sha256::digest(credential.as_bytes()).to_vec();
    assert_eq!(stored.5, expected_hash);
}

#[sqlx::test(migrations = "./migrations")]
async fn issuance_bumps_allocated_count_and_committed_version(pool: PgPool) {
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
            credential_request_body("vc-test", &proof_jwt),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let (allocated_count, committed_version): (i32, i64) = sqlx::query_as(
        "SELECT s.allocated_count, s.committed_version \
         FROM status_lists s \
         JOIN issuers i ON i.current_status_list_id = s.id \
         WHERE i.id = $1",
    )
    .bind(issuer.id.bare())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(allocated_count, 1);
    assert_eq!(committed_version, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn issuance_fails_when_issuer_has_no_status_list(pool: PgPool) {
    // An issuer that has not yet completed the create_issuer worker's
    // provision_status_list step has no current_status_list_id. The
    // handler refuses to issue rather than lazily provisioning a
    // list — a fresh list would still need a registry round-trip to
    // obtain its public URL, which does not belong in the issuance
    // hot path.
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;

    // Build the issuer manually so that no status_list is provisioned
    // alongside it (i.e. skip `create_onboarded_issuer`).
    let engine = DevSigningEngine::new(pool.clone());
    let assertion = engine.generate_keypair(KeyRole::Assertion).await.unwrap();
    let issuer = Issuer {
        did: FIXTURE_DID.into(),
        assertion_key_id: Some(assertion.id),
        ..common::issuers::active(&tenant_id)
    };
    common::issuers::insert(&pool, &issuer).await;

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

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = read_body_value(response).await;
    assert_eq!(body["error"], "server_error");
}

#[sqlx::test(migrations = "./migrations")]
async fn credential_payload_carries_status_claim(pool: PgPool) {
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
            credential_request_body("vc-test", &proof_jwt),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = read_body_value(response).await;
    let credential = body["credential"].as_str().unwrap();

    let core = credential.trim_end_matches('~');
    let parts: Vec<&str> = core.split('.').collect();
    let payload: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();

    let status = &payload["status"]["status_list"];
    assert_eq!(status["idx"], 0);
    let uri = status["uri"].as_str().expect("status_list.uri is a string");
    assert_eq!(
        uri, FIXTURE_STATUS_REGISTRY_URL,
        "status uri must be the persisted registry_url verbatim",
    );
    assert!(
        payload["exp"].as_i64().is_some(),
        "credential payload must carry an exp claim"
    );
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
