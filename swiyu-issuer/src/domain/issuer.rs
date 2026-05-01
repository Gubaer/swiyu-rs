use super::ids::{IssuerId, TenantId};

/// A registered credential-issuing entity within a tenant.
///
/// `did` and `signing_key_id` are mandatory once the OIDC binary is
/// in play — every signed credential needs both. `display_name`,
/// `logo_uri`, and `locale` populate the wallet-facing issuer
/// metadata document and are optional; absent fields are simply
/// omitted from the response.
///
/// `signing_key_id` is an opaque handle into the `swiyu-didtool`
/// keystore. The issuer binary does not interpret it; it passes the
/// value through to the keystore when it needs to sign.
#[derive(Debug, Clone)]
pub struct Issuer {
    pub id: IssuerId,
    pub tenant_id: TenantId,
    pub did: String,
    pub signing_key_id: String,
    pub display_name: Option<String>,
    pub logo_uri: Option<String>,
    pub locale: Option<String>,
}
