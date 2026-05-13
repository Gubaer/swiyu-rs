#![allow(dead_code)] // not every test module pulls in this helper

use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;
use wiremock::MockServer;

use swiyu_issuer::domain::{DevSigningEngine, ProviderRegistry};
use swiyu_issuer::worker::Worker;
use swiyu_issuer::worker::test_support::MockStatusRegistry;
use swiyu_registries::identifier::IdentifierRegistryClient;

use super::rng::ConstantRng;

pub fn build_real(
    pool: PgPool,
    registry_server: &MockServer,
    providers: Arc<ProviderRegistry>,
) -> Worker<IdentifierRegistryClient, DevSigningEngine, MockStatusRegistry> {
    Worker::new(
        pool.clone(),
        super::identifier_registry::build_client(registry_server),
        DevSigningEngine::new(pool),
        super::status_registry::with_one_ok(),
        providers,
        Box::new(ConstantRng(0)),
    )
    .with_poll_interval(Duration::from_millis(20))
}
