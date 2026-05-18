use chrono::Duration;
use serde_json::Value;
use sqlx::PgPool;

use crate::domain::{CredentialType, RevocationMode, TenantId};
use crate::persistence;

// Shared with the dev-bootstrap seed via bundled files so the row
// the test fixture writes matches the one a real dev tenant carries
// on disk.
const SAMPLE_CLAIM_SCHEMA_JSON: &str =
    include_str!("../../../schemas/urn_dummy_dummy-credential.schema.json");
const SAMPLE_DISPLAY_JSON: &str =
    include_str!("../../../schemas/urn_dummy_dummy-credential.display.json");
const SAMPLE_CLAIMS_JSON: &str =
    include_str!("../../../schemas/urn_dummy_dummy-credential.claims.json");

pub fn sample_claim_schema() -> Value {
    serde_json::from_str(SAMPLE_CLAIM_SCHEMA_JSON)
        .expect("bundled dummy claim schema must be valid JSON")
}

pub fn sample_display() -> Value {
    serde_json::from_str(SAMPLE_DISPLAY_JSON).expect("bundled dummy display must be valid JSON")
}

pub fn sample_claims() -> Value {
    serde_json::from_str(SAMPLE_CLAIMS_JSON).expect("bundled dummy claims must be valid JSON")
}

pub fn sample(tenant_id: &TenantId) -> CredentialType {
    CredentialType::new(
        tenant_id.clone(),
        "urn:dummy:dummy-credential".into(),
        sample_display(),
        Some("Test credential type".into()),
        sample_claim_schema(),
        sample_claims(),
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
