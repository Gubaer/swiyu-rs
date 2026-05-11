use chrono::{DateTime, Utc};

use super::DomainError;
use super::ids::{CredentialOfferId, IssuedCredentialId, IssuerId, StatusListId, TenantId};
use super::status_list::StatusListIndex;

/// Lifecycle state of an [`IssuedCredential`].
///
/// New credentials start in `Active`. `Suspended` is reversible
/// (`Active` ↔ `Suspended`); `Revoked` is terminal. `Expired` is
/// **not** a variant — expiry is a derived view at read time,
/// against the credential's `exp` claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuedCredentialState {
    Active,
    Suspended,
    Revoked,
}

impl IssuedCredentialState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Revoked => "revoked",
        }
    }

    pub fn parse(s: &str) -> Result<Self, DomainError> {
        match s {
            "active" => Ok(Self::Active),
            "suspended" => Ok(Self::Suspended),
            "revoked" => Ok(Self::Revoked),
            _ => Err(DomainError::InvalidInput {
                details: format!("unknown issued credential state: {s}"),
            }),
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Revoked)
    }
}

impl sqlx::Type<sqlx::Postgres> for IssuedCredentialState {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <String as sqlx::Type<sqlx::Postgres>>::type_info()
    }

    fn compatible(ty: &sqlx::postgres::PgTypeInfo) -> bool {
        <String as sqlx::Type<sqlx::Postgres>>::compatible(ty)
    }
}

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for IssuedCredentialState {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let s = <&str as sqlx::Decode<'r, sqlx::Postgres>>::decode(value)?;
        IssuedCredentialState::parse(s).map_err(|e| Box::new(e) as sqlx::error::BoxDynError)
    }
}

impl<'q> sqlx::Encode<'q, sqlx::Postgres> for IssuedCredentialState {
    fn encode_by_ref(
        &self,
        buf: &mut sqlx::postgres::PgArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        <&str as sqlx::Encode<'q, sqlx::Postgres>>::encode_by_ref(&self.as_str(), buf)
    }
}

/// Length in bytes of the issuer-side integrity hash of a signed
/// credential.
///
/// SHA-256 over the SD-JWT VC compact serialisation.
pub const INTEGRITY_HASH_LEN: usize = 32;

/// The issuer's record of a credential it has signed.
///
/// Holds metadata only. The signed SD-JWT VC itself is not persisted —
/// the wallet keeps the only copy. [`integrity_hash`][Self::integrity_hash]
/// is the only trace of the issued bytes that survives on the issuer
/// side, used to answer "did we sign this?" without retaining the
/// credential's claims.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct IssuedCredential {
    pub id: IssuedCredentialId,
    pub tenant_id: TenantId,
    pub issuer_id: IssuerId,

    /// The offer this credential was issued from. The relation is
    /// `1:{0..1}`: every issued credential originates from exactly one
    /// offer; an offer that is cancelled or expires before the wallet
    /// picks it up never produces an `IssuedCredential`.
    pub credential_offer_id: CredentialOfferId,

    /// SD-JWT VC type identifier, copied from the originating
    /// `CredentialType` at issuance so later edits to the type row
    /// do not retroactively change what an existing credential reads
    /// as.
    pub vct: String,

    /// JWK thumbprint (RFC 7638) of the wallet's `cnf` key,
    /// base64url-encoded. The full `cnf` key is not retained; the
    /// thumbprint is enough to correlate later presentations or
    /// audit trails.
    pub holder_key_jkt: String,

    /// BitstringStatusList instance whose bits encode this
    /// credential's revocation/suspension state. Bound at issuance
    /// and never re-pointed for the lifetime of the row.
    pub status_list_id: StatusListId,

    /// Position within [`status_list_id`][Self::status_list_id] that
    /// holds this credential's status bits. Allocated at issuance from
    /// the issuer's current list and never reused.
    pub status_list_index: StatusListIndex,

    pub state: IssuedCredentialState,

    /// SHA-256 of the SD-JWT VC compact serialisation handed to the
    /// wallet at issuance.
    #[sqlx(try_from = "Vec<u8>")]
    pub integrity_hash: [u8; INTEGRITY_HASH_LEN],

    pub issued_at: DateTime<Utc>,

    /// Value of the SD-JWT VC's `exp` claim, copied for housekeeping
    /// queries. Verifiers enforce expiry against the signed claim,
    /// not against this column.
    pub expires_at: DateTime<Utc>,
}

impl IssuedCredential {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_id: TenantId,
        issuer_id: IssuerId,
        credential_offer_id: CredentialOfferId,
        vct: String,
        holder_key_jkt: String,
        status_list_id: StatusListId,
        status_list_index: StatusListIndex,
        integrity_hash: [u8; INTEGRITY_HASH_LEN],
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id: IssuedCredentialId::generate(),
            tenant_id,
            issuer_id,
            credential_offer_id,
            vct,
            holder_key_jkt,
            status_list_id,
            status_list_index,
            state: IssuedCredentialState::Active,
            integrity_hash,
            issued_at,
            expires_at,
        }
    }

    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }

    /// Transitions this credential from `Active` to `Suspended`.
    ///
    /// # Errors
    ///
    /// Returns [`StateTransitionNotAllowed`][DomainError::StateTransitionNotAllowed] if the
    /// credential is not currently `Active`.
    pub fn try_suspend(&mut self) -> Result<(), DomainError> {
        match self.state {
            IssuedCredentialState::Active => {
                self.state = IssuedCredentialState::Suspended;
                Ok(())
            }
            _ => Err(DomainError::StateTransitionNotAllowed),
        }
    }

    /// Transitions this credential from `Suspended` back to `Active`.
    ///
    /// # Errors
    ///
    /// Returns [`StateTransitionNotAllowed`][DomainError::StateTransitionNotAllowed] if the
    /// credential is not currently `Suspended`.
    pub fn try_unsuspend(&mut self) -> Result<(), DomainError> {
        match self.state {
            IssuedCredentialState::Suspended => {
                self.state = IssuedCredentialState::Active;
                Ok(())
            }
            _ => Err(DomainError::StateTransitionNotAllowed),
        }
    }

    /// Transitions this credential to terminal `Revoked` from either
    /// `Active` or `Suspended`. One-way; no `try_unrevoke`.
    ///
    /// # Errors
    ///
    /// Returns [`StateTransitionNotAllowed`][DomainError::StateTransitionNotAllowed] if the
    /// credential is already `Revoked`.
    pub fn try_revoke(&mut self) -> Result<(), DomainError> {
        match self.state {
            IssuedCredentialState::Active | IssuedCredentialState::Suspended => {
                self.state = IssuedCredentialState::Revoked;
                Ok(())
            }
            IssuedCredentialState::Revoked => Err(DomainError::StateTransitionNotAllowed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn make_credential() -> IssuedCredential {
        IssuedCredential::new(
            TenantId::from_bare("4Mk7yK5pQR7sN3").unwrap(),
            IssuerId::from_bare("9hXq2vRtL8pK7f").unwrap(),
            CredentialOfferId::from_bare("8KpL9zRT5qWnFm").unwrap(),
            "urn:communal:local-residence-id".to_string(),
            "abcDEF0123456789abcDEF0123456789abcDEF01234".to_string(),
            StatusListId::from_bare("3xY7tQ8mN2vR5w").unwrap(),
            StatusListIndex::try_from(42u32).unwrap(),
            [0u8; INTEGRITY_HASH_LEN],
            Utc::now(),
            Utc::now() + Duration::days(365),
        )
    }

    #[test]
    fn new_credential_is_active() {
        let credential = make_credential();
        assert_eq!(credential.state, IssuedCredentialState::Active);
    }

    #[test]
    fn try_suspend_active_succeeds() {
        let mut credential = make_credential();
        credential.try_suspend().unwrap();
        assert_eq!(credential.state, IssuedCredentialState::Suspended);
    }

    #[test]
    fn try_suspend_already_suspended_fails() {
        let mut credential = make_credential();
        credential.try_suspend().unwrap();
        assert!(credential.try_suspend().is_err());
    }

    #[test]
    fn try_unsuspend_active_fails() {
        let mut credential = make_credential();
        assert!(credential.try_unsuspend().is_err());
    }

    #[test]
    fn try_suspend_then_unsuspend_restores_active() {
        let mut credential = make_credential();
        credential.try_suspend().unwrap();
        credential.try_unsuspend().unwrap();
        assert_eq!(credential.state, IssuedCredentialState::Active);
    }

    #[test]
    fn try_revoke_from_active_succeeds() {
        let mut credential = make_credential();
        credential.try_revoke().unwrap();
        assert_eq!(credential.state, IssuedCredentialState::Revoked);
    }

    #[test]
    fn try_revoke_from_suspended_succeeds() {
        let mut credential = make_credential();
        credential.try_suspend().unwrap();
        credential.try_revoke().unwrap();
        assert_eq!(credential.state, IssuedCredentialState::Revoked);
    }

    #[test]
    fn try_revoke_already_revoked_fails() {
        let mut credential = make_credential();
        credential.try_revoke().unwrap();
        assert!(credential.try_revoke().is_err());
    }

    #[test]
    fn revoked_state_is_terminal() {
        assert!(IssuedCredentialState::Revoked.is_terminal());
        assert!(!IssuedCredentialState::Active.is_terminal());
        assert!(!IssuedCredentialState::Suspended.is_terminal());
    }

    #[test]
    fn state_string_round_trip() {
        for state in [
            IssuedCredentialState::Active,
            IssuedCredentialState::Suspended,
            IssuedCredentialState::Revoked,
        ] {
            assert_eq!(IssuedCredentialState::parse(state.as_str()).unwrap(), state);
        }
    }

    #[test]
    fn parse_rejects_unknown_state() {
        assert!(IssuedCredentialState::parse("expired").is_err());
        assert!(IssuedCredentialState::parse("").is_err());
    }

    #[test]
    fn is_expired_at_uses_expires_at() {
        let credential = make_credential();
        assert!(!credential.is_expired_at(credential.issued_at));
        assert!(credential.is_expired_at(credential.expires_at));
        assert!(credential.is_expired_at(credential.expires_at + Duration::seconds(1)));
    }
}
