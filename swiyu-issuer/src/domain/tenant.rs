use super::ids::TenantId;

/// An organisation operating issuers within swiyu-issuer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tenant {
    pub id: TenantId,
    /// SWIYU Identifier Registry partner identifier (a UUID). Required by
    /// the `allocate_did` step; a missing value fails the `CreateIssuer`
    /// task immediately.
    pub partner_id: Option<String>,
}
