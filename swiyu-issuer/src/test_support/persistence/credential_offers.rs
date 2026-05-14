use chrono::{Duration, Utc};
use serde_json::json;
use sqlx::PgPool;

use crate::domain::{CredentialOffer, IssuerId, PreAuthCode, TenantId};
use crate::persistence;

pub async fn insert(pool: &PgPool, offer: &CredentialOffer) {
    let mut conn = pool.acquire().await.unwrap();
    persistence::credential_offers::insert(&mut conn, offer)
        .await
        .unwrap();
}

pub fn pending(tenant_id: &TenantId, issuer_id: &IssuerId) -> CredentialOffer {
    CredentialOffer::new(
        tenant_id.clone(),
        issuer_id.clone(),
        "https://example.com/vct/test".into(),
        json!({"first_name": "Anna"}),
        PreAuthCode::generate(),
        Utc::now() + Duration::hours(1),
    )
}
