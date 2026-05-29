//! Integration tests for CORS on the OIDC router.
//!
//! The OIDC endpoints are wallet-facing and called from browsers, so
//! the router carries a `tower_http` CORS layer. These tests drive the
//! router via `tower::ServiceExt::oneshot` and assert the preflight and
//! actual-request headers — in particular that the `Authorization`
//! header is allowed (the Fetch `*` wildcard does not cover it) and
//! that an explicit origin allowlist rejects unlisted origins. No
//! handler is reached on a preflight, but `AppState` still needs a
//! pool, so the tests run under `sqlx::test`.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use chrono::Duration;
use sqlx::PgPool;
use tower::ServiceExt;

use swiyu_issuer::api_oidc::{AppState, Config, CorsAllowedOrigins, router};
use swiyu_issuer::domain::{AnySigningEngine, DevSigningEngine};

const SAMPLE_BASE_URL: &str = "http://localhost:8080";
const WALLET_ORIGIN: &str = "https://wallet.example";

fn build_state(pool: PgPool, cors_allowed_origins: CorsAllowedOrigins) -> AppState {
    let engine = AnySigningEngine::Dev(DevSigningEngine::new(pool.clone()));
    AppState::new(
        pool,
        Config {
            issuer_base_url: SAMPLE_BASE_URL.into(),
            access_token_ttl: Duration::seconds(300),
            c_nonce_ttl: Duration::seconds(300),
            cors_allowed_origins,
        },
        Arc::new(engine),
    )
}

fn preflight(origin: &str, method: &str, request_headers: &str) -> Request<Body> {
    Request::builder()
        .method(Method::OPTIONS)
        .uri("/i/9hXq2vRtL8pK7f/credential")
        .header(header::ORIGIN, origin)
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, method)
        .header(header::ACCESS_CONTROL_REQUEST_HEADERS, request_headers)
        .body(Body::empty())
        .unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn preflight_allows_authorization_header_for_any_origin(pool: PgPool) {
    let app = router(build_state(pool, CorsAllowedOrigins::Any));

    let response = app
        .oneshot(preflight(
            WALLET_ORIGIN,
            "POST",
            "authorization,content-type",
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers();
    assert_eq!(
        headers
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|v| v.to_str().ok()),
        Some("*"),
    );
    let allowed_headers = headers
        .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    assert!(
        allowed_headers.contains("authorization"),
        "authorization must be allowed, got: {allowed_headers}"
    );
    let allowed_methods = headers
        .get(header::ACCESS_CONTROL_ALLOW_METHODS)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        allowed_methods.contains("POST"),
        "POST must be allowed, got: {allowed_methods}"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn actual_request_carries_allow_origin_header(pool: PgPool) {
    let app = router(build_state(pool, CorsAllowedOrigins::Any));

    let request = Request::builder()
        .method(Method::GET)
        .uri("/healthz")
        .header(header::ORIGIN, WALLET_ORIGIN)
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|v| v.to_str().ok()),
        Some("*"),
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn allowlist_echoes_listed_origin_and_omits_others(pool: PgPool) {
    let allowed = CorsAllowedOrigins::List(vec![WALLET_ORIGIN.parse().unwrap()]);
    let app = router(build_state(pool, allowed));

    let listed = app
        .clone()
        .oneshot(preflight(WALLET_ORIGIN, "POST", "authorization"))
        .await
        .unwrap();
    assert_eq!(
        listed
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|v| v.to_str().ok()),
        Some(WALLET_ORIGIN),
    );

    let unlisted = app
        .oneshot(preflight("https://evil.example", "POST", "authorization"))
        .await
        .unwrap();
    assert!(
        unlisted
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none(),
        "unlisted origin must not receive an allow-origin header"
    );
}
