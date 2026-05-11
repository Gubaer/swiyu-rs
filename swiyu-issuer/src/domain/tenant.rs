use std::fmt;

use secrecy::{ExposeSecret, SecretString};

use super::ids::TenantId;

/// A SWIYU OAuth2 secret persisted as TEXT in the `tenants` table.
///
/// Wraps [`SecretString`][secrecy::SecretString] to keep the
/// zeroize-on-drop and redacted-`Debug` guarantees while supplying
/// the sqlx [`Type`][sqlx::Type] / [`Decode`][sqlx::Decode] /
/// [`Encode`][sqlx::Encode] impls that `SecretString` itself does
/// not provide. This lets [`Tenant`] derive [`FromRow`][sqlx::FromRow]
/// like every other persistence aggregate.
#[derive(Clone)]
pub struct OAuthSecret(SecretString);

impl OAuthSecret {
    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl From<String> for OAuthSecret {
    fn from(value: String) -> Self {
        Self(SecretString::from(value))
    }
}

impl fmt::Debug for OAuthSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("OAuthSecret").field(&"<redacted>").finish()
    }
}

impl sqlx::Type<sqlx::Postgres> for OAuthSecret {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <String as sqlx::Type<sqlx::Postgres>>::type_info()
    }

    fn compatible(ty: &sqlx::postgres::PgTypeInfo) -> bool {
        <String as sqlx::Type<sqlx::Postgres>>::compatible(ty)
    }
}

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for OAuthSecret {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let s = <String as sqlx::Decode<'r, sqlx::Postgres>>::decode(value)?;
        Ok(Self::from(s))
    }
}

impl<'q> sqlx::Encode<'q, sqlx::Postgres> for OAuthSecret {
    fn encode_by_ref(
        &self,
        buf: &mut sqlx::postgres::PgArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        <&str as sqlx::Encode<'q, sqlx::Postgres>>::encode_by_ref(&self.0.expose_secret(), buf)
    }
}

/// An organisation operating issuers within swiyu-issuer.
///
/// Does not derive `PartialEq` / `Eq` because it carries [`OAuthSecret`]
/// secrets, which deliberately do not support equality comparison — a
/// non-constant-time comparison of secret material is a security
/// smell. No code currently compares two `Tenant` values for equality
/// (asserts on `tenant.id` are sufficient), so dropping the derives
/// costs nothing.
#[derive(Debug, Clone, sqlx::FromRow)]
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
    /// that do not call SWIYU registries. Wrapped in [`OAuthSecret`] so
    /// accidental `Debug` prints elide the value and the memory is
    /// zeroized on drop.
    pub oauth_client_secret: Option<OAuthSecret>,
    /// SWIYU OAuth2 refresh token (the "renewal token"). Operators
    /// seed it from the ePortal; the runtime rotates it on every
    /// successful `refresh_token` grant. Wrapped in [`OAuthSecret`]
    /// for the same reason as [`oauth_client_secret`][Self::oauth_client_secret].
    pub oauth_refresh_token: Option<OAuthSecret>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_value() {
        let secret = OAuthSecret::from("sensitive-token-value".to_string());
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("sensitive-token-value"));
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn expose_secret_returns_inner_value() {
        let secret = OAuthSecret::from("token-abc".to_string());
        assert_eq!(secret.expose_secret(), "token-abc");
    }

    #[test]
    fn clone_preserves_value() {
        let secret = OAuthSecret::from("clone-me".to_string());
        let cloned = secret.clone();
        assert_eq!(cloned.expose_secret(), "clone-me");
    }
}
