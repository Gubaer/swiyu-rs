use chrono::Duration;
use serde_json::{Value, json};
use sqlx::PgPool;

use crate::domain::{CredentialType, RevocationMode, TenantId};
use crate::persistence;

pub fn sample_claim_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "first_name": { "type": "string" },
            "last_name":  { "type": "string" }
        },
        "required": ["first_name", "last_name"]
    })
}

pub fn sample(tenant_id: &TenantId) -> CredentialType {
    CredentialType::new(
        tenant_id.clone(),
        "urn:dummy:dummy-credential".into(),
        json!([]),
        Some("Test credential type".into()),
        sample_claim_schema(),
        json!({}),
        Duration::days(365),
        RevocationMode::RevocableAndSuspendable,
    )
}

pub async fn insert(pool: &PgPool, credential_type: &CredentialType) {
    let mut conn = pool.acquire().await.unwrap();
    persistence::credential_types::insert(&mut conn, credential_type)
        .await
        .unwrap();
}

pub async fn seed(pool: &PgPool, tenant_id: &TenantId) -> CredentialType {
    let credential_type = sample(tenant_id);
    insert(pool, &credential_type).await;
    credential_type
}
