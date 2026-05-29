use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use chrono::Duration;
use swiyu_issuer::api_oidc::{AppState, Config, CorsAllowedOrigins, router};
use swiyu_issuer::config::resolve_oidc_public_url;
use swiyu_issuer::domain::{
    AnySecretEncryptionEngine, build_secret_encryption_engine_from_env,
    build_signing_engine_from_env,
};
use swiyu_issuer::persistence;
use tokio::net::TcpListener;
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    tracing::info!("swiyu-issuer-oidcapi starting");

    let database_url = env::var("DATABASE_URL").map_err(|_| "DATABASE_URL must be set")?;
    let bind_addr: SocketAddr = env::var("BIND_ADDR_OIDC")
        .unwrap_or_else(|_| "0.0.0.0:8081".to_string())
        .parse()?;
    // The base the wallet sees: it goes into the offer body's
    // `credential_issuer` and the metadata endpoints, so it must name
    // this OIDC server, not the management API.
    let issuer_base_url = resolve_oidc_public_url(
        env::var("ISSUER_OIDC_HTTP_URL").ok(),
        env::var("ISSUER_BASE_URL").ok(),
    );
    let access_token_ttl = read_duration_env(
        "ACCESS_TOKEN_TTL_SECONDS",
        Config::DEFAULT_ACCESS_TOKEN_TTL_SECONDS,
    )?;
    let c_nonce_ttl =
        read_duration_env("C_NONCE_TTL_SECONDS", Config::DEFAULT_C_NONCE_TTL_SECONDS)?;
    let cors_allowed_origins = read_cors_allowed_origins_env()?;

    let pool = persistence::connect(&database_url).await?;
    persistence::run_migrations(&pool).await?;

    let engine = Arc::new(build_signing_engine_from_env(pool.clone())?);
    // Built at startup so SECRET_ENCRYPTION_* misconfiguration fails fast.
    // No consumer holds the engine yet — tenant repository wiring lands later.
    let _secret_encryption_engine: Arc<AnySecretEncryptionEngine> =
        Arc::new(build_secret_encryption_engine_from_env()?);

    let state = AppState::new(
        pool,
        Config {
            issuer_base_url,
            access_token_ttl,
            c_nonce_ttl,
            cors_allowed_origins,
        },
        engine,
    );
    let app = router(state);

    let listener = TcpListener::bind(bind_addr).await?;
    tracing::info!(%bind_addr, "swiyu-issuer-oidcapi listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

fn read_duration_env(
    key: &str,
    default_seconds: i64,
) -> Result<Duration, Box<dyn std::error::Error>> {
    let seconds = match env::var(key) {
        Ok(s) => s
            .parse::<i64>()
            .map_err(|err| format!("{key} must be an integer number of seconds: {err}"))?,
        Err(_) => default_seconds,
    };
    if seconds <= 0 {
        return Err(format!("{key} must be positive, got {seconds}").into());
    }
    Ok(Duration::seconds(seconds))
}

/// Parses `OIDC_CORS_ALLOWED_ORIGINS` into the browser-origin policy
/// for the OIDC endpoints. Unset or `*` allows any origin (the dev
/// default); otherwise the value is a comma-separated allowlist of
/// exact origins (e.g. `https://wallet.example,https://demo.example`).
/// A malformed entry fails fast at startup.
fn read_cors_allowed_origins_env() -> Result<CorsAllowedOrigins, Box<dyn std::error::Error>> {
    let raw = match env::var("OIDC_CORS_ALLOWED_ORIGINS") {
        Ok(value) => value,
        Err(_) => return Ok(CorsAllowedOrigins::Any),
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "*" {
        return Ok(CorsAllowedOrigins::Any);
    }
    let mut origins = Vec::new();
    for entry in trimmed.split(',') {
        let origin = entry.trim();
        if origin.is_empty() {
            continue;
        }
        let value = origin.parse().map_err(|err| {
            format!("OIDC_CORS_ALLOWED_ORIGINS entry {origin:?} is not a valid origin: {err}")
        })?;
        origins.push(value);
    }
    if origins.is_empty() {
        return Ok(CorsAllowedOrigins::Any);
    }
    Ok(CorsAllowedOrigins::List(origins))
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("install ctrl_c handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received");
}
