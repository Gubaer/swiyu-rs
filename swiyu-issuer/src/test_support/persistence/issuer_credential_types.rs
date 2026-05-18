use sqlx::PgPool;

use crate::domain::{CredentialTypeId, IssuerCredentialTypeAssignment, IssuerId, TenantId};
use crate::persistence;
use crate::persistence::issuer_credential_types::AssignOutcome;

pub fn sample(
    issuer_id: &IssuerId,
    credential_type_id: &CredentialTypeId,
    tenant_id: &TenantId,
) -> IssuerCredentialTypeAssignment {
    IssuerCredentialTypeAssignment::new(
        issuer_id.clone(),
        credential_type_id.clone(),
        tenant_id.clone(),
    )
}

pub async fn seed(
    pool: &PgPool,
    issuer_id: &IssuerId,
    credential_type_id: &CredentialTypeId,
    tenant_id: &TenantId,
) -> IssuerCredentialTypeAssignment {
    let assignment = sample(issuer_id, credential_type_id, tenant_id);
    let mut conn = pool.acquire().await.unwrap();
    let outcome = persistence::issuer_credential_types::assign(&mut conn, &assignment)
        .await
        .unwrap();
    assert_eq!(outcome, AssignOutcome::NowAssigned);
    assignment
}
