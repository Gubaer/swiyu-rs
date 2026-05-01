use std::env;
use std::net::SocketAddr;

use chrono::Duration;
use swiyu_issuer::api_oidc::{AppState, Config, Signer, router};
use swiyu_issuer::persistence;
use tokio::net::TcpListener;
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    tracing::info!("issuer-oidc starting");

    let database_url = env::var("DATABASE_URL").map_err(|_| "DATABASE_URL must be set")?;
    let bind_addr: SocketAddr = env::var("BIND_ADDR_OIDC")
        .unwrap_or_else(|_| "0.0.0.0:8081".to_string())
        .parse()?;
    let issuer_base_url =
        env::var("ISSUER_BASE_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());
    let access_token_ttl = read_duration_env(
        "ACCESS_TOKEN_TTL_SECONDS",
        Config::DEFAULT_ACCESS_TOKEN_TTL_SECONDS,
    )?;
    let c_nonce_ttl =
        read_duration_env("C_NONCE_TTL_SECONDS", Config::DEFAULT_C_NONCE_TTL_SECONDS)?;

    let pool = persistence::connect(&database_url).await?;
    persistence::run_migrations(&pool).await?;

    // FIXTURE KEY WARNING: every issuer-oidc restart mints a fresh
    // Ed25519 keypair held in process memory only. Signed credentials
    // are wire-shape compatible but cryptographically meaningless
    // across restarts. The follow-up "wire swiyu-didtool keystore"
    // slice replaces this with the real assertion key from the issuer
    // row's `signing_key_id` column. Do not promote past alpha
    // until that lands.
    tracing::warn!(
        "issuer-oidc is using an EPHEMERAL FIXTURE signing key. \
         Signed credentials will not verify across restarts and the \
         issuer's DID document does not advertise the public key. \
         Replace before any non-alpha deployment."
    );
    let signer = Signer::new_ephemeral_for_dev();

    let state = AppState::new(
        pool,
        Config {
            issuer_base_url,
            access_token_ttl,
            c_nonce_ttl,
        },
        signer,
    );
    let app = router(state);

    let listener = TcpListener::bind(bind_addr).await?;
    tracing::info!(%bind_addr, "issuer-oidc listening");
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
