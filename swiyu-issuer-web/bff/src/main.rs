mod config;
mod error;
mod routes;
mod upstream;

use std::net::SocketAddr;
use std::sync::Arc;

use swiyu_registries::identifier::IdentifierRegistryClient;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::routes::AppState;
use crate::upstream::MgmtApiClient;

#[derive(Debug, thiserror::Error)]
enum StartupError {
    #[error("config error: {0}")]
    Config(#[from] config::ConfigError),
    #[error("upstream client construction failed: {0}")]
    Upstream(#[from] upstream::ClientError),
    #[error("identifier registry client construction failed: {0}")]
    Registry(#[from] swiyu_registries::common::RegistryError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[tokio::main]
async fn main() -> Result<(), StartupError> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = Config::from_env()?;
    let mgmt_api = MgmtApiClient::new(&config.mgmtapi_url, &config.mgmtapi_token)?;
    let identifier_registry =
        IdentifierRegistryClient::new(config.identifier_registry_url.clone())?;
    let port = config.bff_port;
    let state = AppState {
        config: Arc::new(config),
        mgmt_api,
        identifier_registry: Arc::new(identifier_registry),
    };

    // Bind all interfaces: in the single-container deployment the BFF must
    // be reachable from outside the container, not just loopback.
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "swiyu-issuer-web-bff listening");

    axum::serve(listener, routes::router(state)).await?;
    Ok(())
}
