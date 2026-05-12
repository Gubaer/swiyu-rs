use uuid::Uuid;

use super::ids::TenantId;
use super::secret_encryption_engine::Ciphertext;

/// An organisation operating issuers within swiyu-issuer.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Tenant {
    pub id: TenantId,
    /// SWIYU Business Partner UUID. Required at tenant creation; SWIYU
    /// Business Partner registration is a precondition for admitting a
    /// tenant to the system. Corrigible via `tenant update` on the rare
    /// typo-correction path.
    pub partner_id: Uuid,
    /// Operator-supplied human-readable name for this tenant. Optional;
    /// the UI derives a fallback from the bare id when this is NULL.
    pub display_name: Option<String>,
    /// Operator-supplied freeform notes about this tenant. Optional.
    pub description: Option<String>,
    /// SWIYU OAuth2 client id ("customer key") for this tenant. NULL for
    /// tenants that do not call SWIYU registries.
    pub oauth_client_id: Option<String>,
    /// SWIYU OAuth2 client secret ("customer secret"). NULL for tenants
    /// that do not call SWIYU registries. Carried as the raw encrypted
    /// blob; decryption happens at the OAuth2 provider boundary, not on
    /// every load of the tenant row.
    pub oauth_client_secret: Option<Ciphertext>,
    /// SWIYU OAuth2 refresh token (the "renewal token"). Operators
    /// seed it from the ePortal; the runtime rotates it on every
    /// successful `refresh_token` grant. Carried as the raw encrypted
    /// blob; see [`oauth_client_secret`][Self::oauth_client_secret].
    pub oauth_refresh_token: Option<Ciphertext>,
}
