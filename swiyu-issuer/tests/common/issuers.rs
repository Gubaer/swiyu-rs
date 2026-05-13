#![allow(dead_code)] // not every test module pulls in this helper

use sqlx::PgPool;

use swiyu_issuer::domain::Issuer;
use swiyu_issuer::persistence;

pub async fn insert(pool: &PgPool, issuer: &Issuer) {
    let mut conn = pool.acquire().await.unwrap();
    persistence::issuers::insert(&mut conn, issuer)
        .await
        .unwrap();
}
