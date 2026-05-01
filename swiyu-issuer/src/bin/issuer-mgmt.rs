use std::env;
use std::net::SocketAddr;

use swiyu_issuer::api_management::{AppState, Config, router};
use swiyu_issuer::persistence;
use tokio::net::TcpListener;
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    tracing::info!("issuer-mgmt starting");

    let database_url = env::var("DATABASE_URL").map_err(|_| "DATABASE_URL must be set")?;
    let bind_addr: SocketAddr = env::var("BIND_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
        .parse()?;
    let issuer_base_url =
        env::var("ISSUER_BASE_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());
    let default_tenant_id =
        env::var("DEFAULT_TENANT_ID").unwrap_or_else(|_| "4Mk7yK5pQR7sN3".to_string());

    let pool = persistence::connect(&database_url).await?;
    persistence::run_migrations(&pool).await?;

    let state = AppState::new(
        pool,
        Config {
            default_tenant_id,
            issuer_base_url,
        },
    )?;
    let app = router(state);

    let listener = TcpListener::bind(bind_addr).await?;
    tracing::info!(%bind_addr, "issuer-mgmt listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
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
