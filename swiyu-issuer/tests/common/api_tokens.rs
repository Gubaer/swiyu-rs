#![allow(dead_code)] // not every test module pulls in this helper

use sqlx::PgPool;

use swiyu_issuer::domain::{ApiToken, ApiTokenSecret, TenantId};
use swiyu_issuer::persistence;

pub async fn mint_test_token(pool: &PgPool, tenant_id: &TenantId) -> ApiTokenSecret {
    let secret = ApiTokenSecret::generate();
    let token = ApiToken::new(tenant_id.clone(), "test-token".into(), secret.hash(), None);
    let mut conn = pool.acquire().await.unwrap();
    persistence::api_tokens::insert(&mut conn, &token)
        .await
        .unwrap();
    secret
}
