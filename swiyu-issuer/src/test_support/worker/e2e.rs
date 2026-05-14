use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;
use swiyu_registries::identifier::IdentifierRegistryClient;
use wiremock::MockServer;

use crate::domain::{DevSigningEngine, ProviderRegistry};
use crate::test_support::registry::identifier::build_client;
use crate::test_support::registry::status::with_one_ok;
use crate::worker::Worker;

use super::{ConstantRng, MockStatusRegistry};

pub fn build_real(
    pool: PgPool,
    registry_server: &MockServer,
    providers: Arc<ProviderRegistry>,
) -> Worker<IdentifierRegistryClient, DevSigningEngine, MockStatusRegistry> {
    Worker::new(
        pool.clone(),
        build_client(registry_server),
        DevSigningEngine::new(pool),
        with_one_ok(),
        providers,
        Box::new(ConstantRng(0)),
    )
    .with_poll_interval(Duration::from_millis(20))
}
