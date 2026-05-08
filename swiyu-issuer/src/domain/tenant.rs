use secrecy::SecretString;

use super::ids::TenantId;

/// An organisation operating issuers within swiyu-issuer.
///
/// Does not derive `PartialEq` / `Eq` because it carries `SecretString`
/// secrets, which `secrecy` deliberately does not let you compare via the
/// standard derives — a non-constant-time comparison of secret material is
/// a security smell. No code currently compares two `Tenant` values for
/// equality (asserts on `tenant.id` are sufficient), so dropping the
/// derives costs nothing.
#[derive(Debug, Clone)]
pub struct Tenant {
    pub id: TenantId,
    /// SWIYU Identifier Registry partner identifier (a UUID). Required by
    /// the `allocate_did` step; a missing value fails the `CreateIssuer`
    /// task immediately.
    pub partner_id: Option<String>,
    /// SWIYU OAuth2 client id ("customer key") for this tenant. NULL for
    /// tenants that do not call SWIYU registries.
    pub oauth_client_id: Option<String>,
    /// SWIYU OAuth2 client secret ("customer secret"). NULL for tenants
    /// that do not call SWIYU registries. Wrapped in `SecretString` so
    /// accidental `Debug` / `Display` prints elide the value and the
    /// memory is zeroized on drop.
    pub oauth_client_secret: Option<SecretString>,
    /// SWIYU OAuth2 refresh token (the "renewal token"). Operators
    /// seed it from the ePortal; the runtime rotates it on every
    /// successful `refresh_token` grant. Wrapped in `SecretString`
    /// for the same reason as `oauth_client_secret`.
    pub oauth_refresh_token: Option<SecretString>,
}
