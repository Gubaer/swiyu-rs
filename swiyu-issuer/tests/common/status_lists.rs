#![allow(dead_code)] // not every test module pulls in this helper

use sqlx::PgPool;

use swiyu_issuer::domain::{IssuerId, StatusListId};
use swiyu_issuer::persistence;

pub async fn provision(pool: &PgPool, issuer_id: &IssuerId) -> StatusListId {
    let mut conn = pool.acquire().await.unwrap();
    persistence::status_lists::provision_for_issuer(&mut conn, issuer_id, None, None)
        .await
        .unwrap()
}
