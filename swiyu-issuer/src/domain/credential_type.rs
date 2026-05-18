use chrono::{DateTime, Duration, Utc};
use serde_json::Value;

use super::DomainError;
use super::ids::{CredentialTypeId, TenantId};

/// Permitted credential-lifecycle verbs for the owning [`CredentialType`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationMode {
    /// Only `revoke` is permitted; suspend / unsuspend are rejected.
    Revocable,
    /// Only `suspend` and `unsuspend` are permitted; revoke is rejected.
    Suspendable,
    /// All three verbs — `revoke`, `suspend`, `unsuspend` — are permitted.
    RevocableAndSuspendable,
    /// No lifecycle verbs are permitted; the credential is immutable
    /// once issued.
    None,
}

impl RevocationMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Revocable => "revocable",
            Self::Suspendable => "suspendable",
            Self::RevocableAndSuspendable => "revocable_and_suspendable",
            Self::None => "none",
        }
    }
}

impl TryFrom<&str> for RevocationMode {
    type Error = DomainError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "revocable" => Ok(Self::Revocable),
            "suspendable" => Ok(Self::Suspendable),
            "revocable_and_suspendable" => Ok(Self::RevocableAndSuspendable),
            "none" => Ok(Self::None),
            _ => Err(DomainError::InvalidInput {
                details: format!("unknown revocation mode: {s}"),
            }),
        }
    }
}

impl sqlx::Type<sqlx::Postgres> for RevocationMode {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <String as sqlx::Type<sqlx::Postgres>>::type_info()
    }

    fn compatible(ty: &sqlx::postgres::PgTypeInfo) -> bool {
        <String as sqlx::Type<sqlx::Postgres>>::compatible(ty)
    }
}

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for RevocationMode {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let s = <&str as sqlx::Decode<'r, sqlx::Postgres>>::decode(value)?;
        RevocationMode::try_from(s).map_err(|e| Box::new(e) as sqlx::error::BoxDynError)
    }
}

impl<'q> sqlx::Encode<'q, sqlx::Postgres> for RevocationMode {
    fn encode_by_ref(
        &self,
        buf: &mut sqlx::postgres::PgArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        <&str as sqlx::Encode<'q, sqlx::Postgres>>::encode_by_ref(&self.as_str(), buf)
    }
}

/// A tenant-owned credential type a tenant's issuers can offer.
#[derive(Debug, Clone)]
pub struct CredentialType {
    /// Generated at construction time; bs58 newtype with prefix `ctype`.
    pub id: CredentialTypeId,
    /// Owning tenant. Two tenants may carry the same `vct` on
    /// independent rows.
    pub tenant_id: TenantId,
    /// SD-JWT VC type identifier (a URI). Embedded in every issued
    /// credential's `vct` claim.
    pub vct: String,
    /// OID4VCI display array (per-locale entries). Surfaced verbatim
    /// in the issuer metadata projection.
    pub display: Value,
    /// Admin-facing, unlocalised description. Never reaches wallets.
    pub internal_description: Option<String>,
    /// JSON Schema 2020-12 document validating the credential's
    /// application-level claims. Compiled on first use into a cached
    /// validator keyed by [`CredentialTypeId`].
    pub claim_schema: Value,
    /// Provenance: the URL the schema was fetched from, if any.
    pub claim_schema_source_url: Option<String>,
    /// Provenance: when the schema was last fetched. Independent of
    /// [`updated_at`][CredentialType::updated_at], which also moves
    /// on structured-field edits.
    pub claim_schema_fetched_at: Option<DateTime<Utc>>,
    /// OID4VCI claims metadata. Surfaced verbatim in the issuer
    /// metadata projection.
    pub claims: Value,
    /// Validity window applied to credentials minted under this type.
    /// Required at creation; no application-level fallback at issuance.
    pub default_validity_duration: Duration,
    /// Permitted credential-lifecycle verbs; see [`RevocationMode`].
    pub revocation_mode: RevocationMode,
    /// Set at construction time.
    pub created_at: DateTime<Utc>,
    /// Bumped on every structured-field edit and every `claim_schema`
    /// write. Drives the validator cache's freshness check.
    pub updated_at: DateTime<Utc>,
    /// Soft-delete marker. Already-issued credentials may still
    /// reference the row long after retirement; rows are never
    /// hard-deleted.
    pub retired_at: Option<DateTime<Utc>>,
}

impl CredentialType {
    // Each parameter maps to a NOT NULL column on `credential_types`;
    // constructing a valid row needs each one up front.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_id: TenantId,
        vct: String,
        display: Value,
        internal_description: Option<String>,
        claim_schema: Value,
        claims: Value,
        default_validity_duration: Duration,
        revocation_mode: RevocationMode,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: CredentialTypeId::generate(),
            tenant_id,
            vct,
            display,
            internal_description,
            claim_schema,
            claim_schema_source_url: None,
            claim_schema_fetched_at: None,
            claims,
            default_validity_duration,
            revocation_mode,
            created_at: now,
            updated_at: now,
            retired_at: None,
        }
    }

    pub fn is_retired(&self) -> bool {
        self.retired_at.is_some()
    }

    /// Marks the credential type as retired at `now`.
    ///
    /// # Errors
    ///
    /// [`DomainError::StateTransitionNotAllowed`] if the row is
    /// already retired.
    pub fn try_retire(&mut self, now: DateTime<Utc>) -> Result<(), DomainError> {
        if self.is_retired() {
            return Err(DomainError::StateTransitionNotAllowed);
        }
        self.retired_at = Some(now);
        self.updated_at = now;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_credential_type() -> CredentialType {
        CredentialType::new(
            TenantId::from_bare("4Mk7yK5pQR7sN3").unwrap(),
            "urn:dummy:dummy-credential".to_string(),
            json!([]),
            None,
            json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "properties": {
                    "first_name": { "type": "string" },
                    "last_name": { "type": "string" }
                },
                "required": ["first_name", "last_name"]
            }),
            json!({}),
            Duration::days(365),
            RevocationMode::RevocableAndSuspendable,
        )
    }

    #[test]
    fn revocation_mode_round_trips_through_str() {
        for mode in [
            RevocationMode::Revocable,
            RevocationMode::Suspendable,
            RevocationMode::RevocableAndSuspendable,
            RevocationMode::None,
        ] {
            let s = mode.as_str();
            let parsed = RevocationMode::try_from(s).unwrap();
            assert_eq!(parsed, mode);
        }
    }

    #[test]
    fn revocation_mode_try_from_rejects_unknown_value() {
        assert!(RevocationMode::try_from("revoked").is_err());
        assert!(RevocationMode::try_from("").is_err());
    }

    #[test]
    fn new_credential_type_is_not_retired() {
        let ct = make_credential_type();
        assert!(!ct.is_retired());
        assert!(ct.retired_at.is_none());
    }

    #[test]
    fn try_retire_stamps_retired_at_and_updated_at() {
        let mut ct = make_credential_type();
        let original_updated_at = ct.updated_at;
        let now = original_updated_at + Duration::seconds(60);
        ct.try_retire(now).unwrap();
        assert_eq!(ct.retired_at, Some(now));
        assert_eq!(ct.updated_at, now);
        assert!(ct.is_retired());
    }

    #[test]
    fn try_retire_already_retired_fails() {
        let mut ct = make_credential_type();
        let now = Utc::now();
        ct.try_retire(now).unwrap();
        let result = ct.try_retire(now + Duration::seconds(60));
        assert!(matches!(
            result,
            Err(DomainError::StateTransitionNotAllowed)
        ));
        assert_eq!(ct.retired_at, Some(now));
    }
}
