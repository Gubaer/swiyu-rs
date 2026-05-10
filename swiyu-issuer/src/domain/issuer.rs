use chrono::{DateTime, Utc};

use super::DomainError;
use super::ids::{IssuerId, TenantId};
use super::signing_engine::{KeyPairId, KeyRole};

/// Lifecycle state of an issuer.
///
/// New issuers start in `Active`. The transition to `Deactivated` is
/// one-way — there is no reactivation. See `aspect-issuer.md`
/// (Lifecycle states).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuerState {
    Active,
    Deactivated,
}

impl IssuerState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Deactivated => "deactivated",
        }
    }

    pub fn parse(s: &str) -> Result<Self, DomainError> {
        match s {
            "active" => Ok(Self::Active),
            "deactivated" => Ok(Self::Deactivated),
            _ => Err(DomainError::InvalidInput {
                details: format!("unknown issuer state: {s}"),
            }),
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Deactivated)
    }
}

/// Outcome of [`Issuer::try_deactivate`].
///
/// `Already` is the saga-resume case: the worker crashed last time
/// after the registry-side publish but before the local state flip
/// committed. On re-run the row is already `Deactivated` and the
/// step must succeed silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkOutcome {
    /// Idempotent re-run: the issuer was already `Deactivated`.
    Already,
    /// First write: the issuer was `Active` and is now `Deactivated`.
    NowDeactivated,
}

/// A registered credential-issuing entity within a tenant.
///
/// The three `*_key_id` fields are `Option<…>` because the seeded
/// dev row from the initial migration is a fixture that bypasses the
/// issuer-management task flow — it has no SigningEngine keys.
/// Issuers created through that flow have all three populated; the
/// OIDC binary refuses to issue credentials when `assertion_key_id`
/// is `None`.
#[derive(Debug, Clone)]
pub struct Issuer {
    pub id: IssuerId,
    pub tenant_id: TenantId,
    pub did: String,

    /// Lifecycle state. `None` for the seeded dev row (predates
    /// lifecycle tracking).
    pub state: Option<IssuerState>,

    /// Human-readable description used in management responses.
    pub description: Option<String>,

    /// Current `Authorized` key pair (Ed25519, signs DID-log entries).
    pub authorized_key_id: Option<KeyPairId>,

    /// Current `Authentication` key pair (P-256, surfaced in the DID
    /// document for wallet authentication challenges).
    pub authentication_key_id: Option<KeyPairId>,

    /// Current `Assertion` key pair (P-256, signs issued credentials).
    pub assertion_key_id: Option<KeyPairId>,

    /// Display name shown in management responses.
    pub display_name: Option<String>,

    /// Legacy presentation metadata read by the OIDC metadata handler.
    pub logo_uri: Option<String>,
    pub locale: Option<String>,

    /// Timestamp of the row insert. Drives stable ordering for the
    /// cursor-paginated list endpoint.
    pub created_at: DateTime<Utc>,
}

impl Issuer {
    /// Returns the `KeyPairId` registered for the given role, if any.
    ///
    /// Returns `None` for the seeded dev row, which has no
    /// SigningEngine keys configured.
    pub fn key_id_for_role(&self, role: KeyRole) -> Option<KeyPairId> {
        match role {
            KeyRole::Authorized => self.authorized_key_id,
            KeyRole::Authentication => self.authentication_key_id,
            KeyRole::Assertion => self.assertion_key_id,
        }
    }

    /// Flips an `Active` issuer to `Deactivated`, idempotent on re-run.
    ///
    /// Returns `MarkOutcome::NowDeactivated` for the `Active → Deactivated`
    /// transition and `MarkOutcome::Already` when the issuer was already
    /// `Deactivated`. The legacy `state = None` row (the seeded dev
    /// fixture predating lifecycle tracking) cannot be deactivated:
    /// it never started in `Active` and has no `Authorized` key to
    /// sign a deactivation entry with.
    pub fn try_deactivate(&mut self) -> Result<MarkOutcome, DomainError> {
        match self.state {
            Some(IssuerState::Active) => {
                self.state = Some(IssuerState::Deactivated);
                Ok(MarkOutcome::NowDeactivated)
            }
            Some(IssuerState::Deactivated) => Ok(MarkOutcome::Already),
            None => Err(DomainError::StateTransitionNotAllowed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_issuer() -> Issuer {
        Issuer {
            id: IssuerId::generate(),
            tenant_id: TenantId::generate(),
            did: "did:tdw:9hXq2vRtL8pK7f:example.com".into(),
            state: None,
            description: None,
            authorized_key_id: None,
            authentication_key_id: None,
            assertion_key_id: None,
            display_name: None,
            logo_uri: None,
            locale: None,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn issuer_state_round_trips_through_strings() {
        for state in [IssuerState::Active, IssuerState::Deactivated] {
            assert_eq!(IssuerState::parse(state.as_str()).unwrap(), state);
        }
    }

    #[test]
    fn issuer_state_parse_rejects_unknown() {
        assert!(IssuerState::parse("paused").is_err());
    }

    #[test]
    fn issuer_state_is_terminal_only_for_deactivated() {
        assert!(!IssuerState::Active.is_terminal());
        assert!(IssuerState::Deactivated.is_terminal());
    }

    #[test]
    fn key_id_for_role_returns_none_for_unmigrated_issuer() {
        let issuer = fixture_issuer();
        assert!(issuer.key_id_for_role(KeyRole::Authorized).is_none());
        assert!(issuer.key_id_for_role(KeyRole::Authentication).is_none());
        assert!(issuer.key_id_for_role(KeyRole::Assertion).is_none());
    }

    #[test]
    fn try_deactivate_flips_active_to_deactivated() {
        let mut issuer = Issuer {
            state: Some(IssuerState::Active),
            ..fixture_issuer()
        };
        let outcome = issuer.try_deactivate().unwrap();
        assert_eq!(outcome, MarkOutcome::NowDeactivated);
        assert_eq!(issuer.state, Some(IssuerState::Deactivated));
    }

    #[test]
    fn try_deactivate_is_idempotent_for_already_deactivated() {
        let mut issuer = Issuer {
            state: Some(IssuerState::Deactivated),
            ..fixture_issuer()
        };
        let outcome = issuer.try_deactivate().unwrap();
        assert_eq!(outcome, MarkOutcome::Already);
        assert_eq!(issuer.state, Some(IssuerState::Deactivated));
    }

    #[test]
    fn try_deactivate_rejects_legacy_state_null_row() {
        let mut issuer = fixture_issuer();
        assert_eq!(issuer.state, None);
        let err = issuer.try_deactivate().unwrap_err();
        assert!(matches!(err, DomainError::StateTransitionNotAllowed));
        assert_eq!(issuer.state, None);
    }

    #[test]
    fn key_id_for_role_returns_set_id_for_migrated_issuer() {
        let authorized = KeyPairId::generate();
        let authentication = KeyPairId::generate();
        let assertion = KeyPairId::generate();

        let issuer = Issuer {
            authorized_key_id: Some(authorized),
            authentication_key_id: Some(authentication),
            assertion_key_id: Some(assertion),
            ..fixture_issuer()
        };

        assert_eq!(
            issuer.key_id_for_role(KeyRole::Authorized),
            Some(authorized)
        );
        assert_eq!(
            issuer.key_id_for_role(KeyRole::Authentication),
            Some(authentication)
        );
        assert_eq!(issuer.key_id_for_role(KeyRole::Assertion), Some(assertion));
    }
}
