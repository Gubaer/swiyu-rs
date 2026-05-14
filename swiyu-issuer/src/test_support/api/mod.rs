use sqlx::PgPool;

use crate::api_management::{AppState, Config};
use crate::domain::{ApiTokenSecret, TenantId};
use crate::test_support::api::tokens::mint_test_token;
use crate::test_support::fixtures::SAMPLE_BASE_URL;
use crate::test_support::persistence::tenants::insert_test_tenant;

pub mod tokens;

pub fn build_state(pool: PgPool) -> AppState {
    AppState::new(
        pool,
        Config {
            issuer_base_url: SAMPLE_BASE_URL.into(),
        },
    )
    .expect("AppState builds")
}

/// Bootstraps the three things every management-API integration test
/// needs: a fresh tenant, a minted API token for that tenant, and an
/// `AppState` wired to the same pool. The caller still owns `pool`
/// (clone is internal) so follow-up DB queries against the seeded
/// state work without further plumbing.
pub async fn authenticated_app_state(pool: &PgPool) -> (AppState, TenantId, ApiTokenSecret) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(pool, &tenant_id).await;
    let secret = mint_test_token(pool, &tenant_id).await;
    let state = build_state(pool.clone());
    (state, tenant_id, secret)
}
