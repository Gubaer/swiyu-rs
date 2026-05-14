use sqlx::PgPool;

use crate::api_management::{AppState, Config};
use crate::test_support::fixtures::SAMPLE_BASE_URL;

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
