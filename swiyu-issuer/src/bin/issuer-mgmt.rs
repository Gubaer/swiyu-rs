use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use chrono::Duration;
use rand_core::OsRng;
use reqwest::Client;
use swiyu_issuer::api_management::{AppState, Config, router};
use swiyu_issuer::domain::{
    AnySecretEncryptionEngine, ProviderRegistry, build_secret_encryption_engine_from_env,
    build_signing_engine_from_env,
};
use swiyu_issuer::persistence;
use swiyu_issuer::worker::{StatusListPublisher, Worker};
use swiyu_registries::identifier::IdentifierRegistryClient;
use swiyu_registries::status::StatusRegistryClient;
use tokio::net::TcpListener;
use tokio::signal;
use tokio_util::sync::CancellationToken;

/// Default fraction of `expires_in` after which the OAuth2 access token
/// is pre-emptively refreshed. 0.75 means refresh once 75% of the
/// lifetime has elapsed (i.e. while ~25% remains).
const DEFAULT_TOKEN_REFRESH_FRACTION: f64 = 0.75;
/// Default HTTP timeout (seconds) for the OAuth2 token endpoint.
const DEFAULT_TOKEN_HTTP_TIMEOUT_SECS: u64 = 15;
/// Default `expires_in` to assume when computing the safety margin
/// before any successful grant has produced a real value. The SWIYU
/// authorization server returns access tokens with a 1-hour lifetime.
const DEFAULT_TOKEN_LIFETIME_SECS: i64 = 3600;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    serve().await
}

async fn serve() -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("issuer-mgmt starting");

    let database_url = env::var("DATABASE_URL").map_err(|_| "DATABASE_URL must be set")?;
    let bind_addr: SocketAddr = env::var("BIND_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
        .parse()?;
    let issuer_base_url =
        env::var("ISSUER_BASE_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());
    let registry_url = env::var("SWIYU_IDENTIFIER_REGISTRY_URL")
        .map_err(|_| "SWIYU_IDENTIFIER_REGISTRY_URL must be set")?;
    let status_registry_url = env::var("SWIYU_STATUS_REGISTRY_URL")
        .map_err(|_| "SWIYU_STATUS_REGISTRY_URL must be set")?;
    let token_url = env::var("SWIYU_TOKEN_URL").map_err(|_| "SWIYU_TOKEN_URL must be set")?;
    let token_refresh_fraction =
        parse_token_refresh_fraction(env::var("SWIYU_TOKEN_REFRESH_FRACTION").ok().as_deref())?;
    let token_http_timeout =
        parse_token_http_timeout(env::var("SWIYU_TOKEN_HTTP_TIMEOUT_SECS").ok().as_deref())?;

    let pool = persistence::connect(&database_url).await?;
    persistence::run_migrations(&pool).await?;

    let state = AppState::new(pool.clone(), Config { issuer_base_url })?;
    let app = router(state);

    let registry_client = IdentifierRegistryClient::new(registry_url)?;
    let status_registry_for_worker = StatusRegistryClient::new(status_registry_url.clone())?;
    let status_registry_for_publisher = StatusRegistryClient::new(status_registry_url)?;
    let signing_engine_for_worker = build_signing_engine_from_env(pool.clone())?;
    let signing_engine_for_publisher = build_signing_engine_from_env(pool.clone())?;
    // Built at startup so SECRET_ENCRYPTION_* misconfiguration fails fast.
    // No consumer holds the engine yet — tenant repository wiring lands later.
    let _secret_encryption_engine: Arc<AnySecretEncryptionEngine> =
        Arc::new(build_secret_encryption_engine_from_env()?);
    // The safety margin is the fraction of the assumed token lifetime
    // *not yet elapsed* when we still consider the token fresh. With a
    // default 1-hour lifetime and a 0.75 refresh fraction, the margin
    // is 25% of the lifetime — i.e. 15 minutes.
    let safety_margin = Duration::seconds(
        (DEFAULT_TOKEN_LIFETIME_SECS as f64 * (1.0 - token_refresh_fraction)) as i64,
    );
    let token_http_client = Client::builder().timeout(token_http_timeout).build()?;
    let providers = Arc::new(ProviderRegistry::new(
        pool.clone(),
        token_http_client,
        token_url,
        safety_margin,
    ));
    let worker = Worker::new(
        pool.clone(),
        registry_client,
        signing_engine_for_worker,
        status_registry_for_worker,
        Arc::clone(&providers),
        Box::new(OsRng),
    );
    let publisher = StatusListPublisher::new(
        pool.clone(),
        signing_engine_for_publisher,
        status_registry_for_publisher,
        providers,
        Box::new(OsRng),
    );

    // Single CancellationToken drives axum's graceful shutdown plus
    // the operation-task worker and the status-list publisher.
    // ctrl_c / SIGTERM trips it once; all three consumers observe the
    // cancellation and drain in parallel.
    let token = CancellationToken::new();

    let signal_token = token.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        signal_token.cancel();
    });

    let worker_token = token.clone();
    let worker_handle = tokio::spawn(worker.run(worker_token));
    let publisher_token = token.clone();
    let publisher_handle = tokio::spawn(publisher.run(publisher_token));

    let listener = TcpListener::bind(bind_addr).await?;
    tracing::info!(%bind_addr, "issuer-mgmt listening");
    let axum_token = token.clone();
    axum::serve(listener, app)
        .with_graceful_shutdown(async move { axum_token.cancelled().await })
        .await?;

    if let Err(e) = worker_handle.await {
        tracing::error!(error = ?e, "worker task ended with error");
    }
    if let Err(e) = publisher_handle.await {
        tracing::error!(error = ?e, "status-list publisher task ended with error");
    }

    Ok(())
}

/// Validates `SWIYU_TOKEN_REFRESH_FRACTION` against the safe range
/// `[0.5, 0.95]`. A value below 0.5 refreshes too aggressively
/// (wasted token-endpoint traffic); above 0.95 leaves no headroom for
/// a refresh round-trip before the access token elapses. Failure is
/// surfaced at startup rather than silently clamped.
fn parse_token_refresh_fraction(raw: Option<&str>) -> Result<f64, String> {
    let Some(s) = raw else {
        return Ok(DEFAULT_TOKEN_REFRESH_FRACTION);
    };
    let value: f64 = s
        .parse()
        .map_err(|err| format!("SWIYU_TOKEN_REFRESH_FRACTION is not a number: {err}"))?;
    if !(0.5..=0.95).contains(&value) {
        return Err(format!(
            "SWIYU_TOKEN_REFRESH_FRACTION must be in [0.5, 0.95], got {value}"
        ));
    }
    Ok(value)
}

fn parse_token_http_timeout(raw: Option<&str>) -> Result<StdDuration, String> {
    let Some(s) = raw else {
        return Ok(StdDuration::from_secs(DEFAULT_TOKEN_HTTP_TIMEOUT_SECS));
    };
    let secs: u64 = s
        .parse()
        .map_err(|err| format!("SWIYU_TOKEN_HTTP_TIMEOUT_SECS is not an integer: {err}"))?;
    if secs == 0 {
        return Err("SWIYU_TOKEN_HTTP_TIMEOUT_SECS must be greater than 0".into());
    }
    Ok(StdDuration::from_secs(secs))
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
