use super::ids::TenantId;

/// An organisation operating issuers within swiyu-issuer.
///
/// `partner_id` is the SWIYU Identifier Registry partner identifier
/// (a UUID). The worker's `allocate_did` step reads it on every
/// `CreateIssuer` task; a tenant without one fails the task Terminal
/// with `tenant_missing_partner_id`. The seeded dev tenant ships
/// with the all-zero placeholder UUID and must be re-onboarded
/// before any real registry call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tenant {
    pub id: TenantId,
    pub partner_id: Option<String>,
}
