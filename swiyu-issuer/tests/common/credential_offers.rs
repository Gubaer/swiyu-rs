#![allow(dead_code)] // not every test module pulls in this helper

use sqlx::PgPool;

use swiyu_issuer::domain::CredentialOffer;
use swiyu_issuer::persistence;

pub async fn insert(pool: &PgPool, offer: &CredentialOffer) {
    let mut conn = pool.acquire().await.unwrap();
    persistence::credential_offers::insert(&mut conn, offer)
        .await
        .unwrap();
}
