use chrono::{DateTime, Utc};

use super::ids::{CredentialTypeId, IssuerId, TenantId};

/// Link row connecting an issuer to a credential type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerCredentialTypeAssignment {
    /// The issuer offering the credential type.
    pub issuer_id: IssuerId,
    /// The credential type offered by the issuer.
    pub credential_type_id: CredentialTypeId,
    /// Denormalised onto the row so per-tenant scans don't have to
    /// join back through `issuers`.
    pub tenant_id: TenantId,
    /// Set at construction time.
    pub assigned_at: DateTime<Utc>,
}

impl IssuerCredentialTypeAssignment {
    pub fn new(
        issuer_id: IssuerId,
        credential_type_id: CredentialTypeId,
        tenant_id: TenantId,
    ) -> Self {
        Self {
            issuer_id,
            credential_type_id,
            tenant_id,
            assigned_at: Utc::now(),
        }
    }
}
