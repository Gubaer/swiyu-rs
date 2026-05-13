#![allow(dead_code)] // not every test module pulls in this helper

use sqlx::PgPool;

use swiyu_issuer::api_management::{AppState, Config};

pub const TEST_BASE_URL: &str = "http://localhost:8080";

pub fn build_state(pool: PgPool) -> AppState {
    AppState::new(
        pool,
        Config {
            issuer_base_url: TEST_BASE_URL.into(),
        },
    )
    .expect("AppState builds")
}
