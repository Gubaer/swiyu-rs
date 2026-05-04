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

/// A registered credential-issuing entity within a tenant.
///
/// **Transitional shape (v0.1.x).** The new fields below are
/// `Option<…>` during expand-contract while the OIDC binary still
/// signs credentials through `signing_key_id` and the legacy
/// `swiyu-didtool` keystore. The target shape (see
/// `aspect-issuer.md` and `impl-issuer.md`) has the new fields
/// required, with `signing_key_id`, `logo_uri`, and `locale` removed.
/// The seeded dev row created by migration 0004 carries the legacy
/// fields; new issuers created through the issuer-management task
/// flow populate the new fields and leave `signing_key_id` empty.
///
/// `signing_key_id` is an opaque handle into the `swiyu-didtool`
/// keystore. The issuer binary does not interpret it; it passes the
/// value through to the keystore when it needs to sign.
#[derive(Debug, Clone)]
pub struct Issuer {
    pub id: IssuerId,
    pub tenant_id: TenantId,
    pub did: String,

    /// Lifecycle state. `Option<…>` during v0.1.x; `None` for the
    /// seeded dev row from migration 0004 (predates lifecycle tracking).
    pub state: Option<IssuerState>,

    /// Human-readable description used in management responses.
    /// `Option<…>` during v0.1.x; required in the target shape.
    pub description: Option<String>,

    /// Current `Authorized` key pair. `None` for issuers signing
    /// through the legacy `signing_key_id`/`swiyu-didtool` keystore;
    /// `Some` once the issuer is on the SigningEngine.
    pub authorized_key_id: Option<KeyPairId>,

    /// Current `Authentication` key pair. Same transition story as
    /// `authorized_key_id`.
    pub authentication_key_id: Option<KeyPairId>,

    /// Current `Assertion` key pair. Same transition story as
    /// `authorized_key_id`.
    pub assertion_key_id: Option<KeyPairId>,

    /// Legacy: opaque handle into the `swiyu-didtool` keystore. The
    /// OIDC binary reads this for credential signing on the seeded
    /// dev row. `None` for issuers created through the SigningEngine
    /// task flow, which carry their key handles in the three
    /// `*_key_id` fields above. Removed when the OIDC binary
    /// migrates to SigningEngine-based signing.
    pub signing_key_id: Option<String>,

    /// Display name. Currently optional; becomes required (and loses
    /// the `Option<…>` wrapper) when the legacy migration completes.
    pub display_name: Option<String>,

    /// Legacy presentation metadata. The OIDC metadata handler reads
    /// these today; both columns are dropped together with
    /// `signing_key_id`.
    pub logo_uri: Option<String>,
    pub locale: Option<String>,

    /// Timestamp of the row insert. Drives stable ordering for the
    /// cursor-paginated list endpoint. The seeded dev row from
    /// migration 0001 backfills to migration time (per migration 0012);
    /// real issuers carry the worker's `now` from the persist step.
    pub created_at: DateTime<Utc>,
}

impl Issuer {
    /// Returns the `KeyPairId` registered for the given role, if any.
    ///
    /// Returns `None` for issuers that pre-date the SigningEngine
    /// migration — those issuers sign through `signing_key_id` and the
    /// legacy `swiyu-didtool` keystore.
    pub fn key_id_for_role(&self, role: KeyRole) -> Option<KeyPairId> {
        match role {
            KeyRole::Authorized => self.authorized_key_id,
            KeyRole::Authentication => self.authentication_key_id,
            KeyRole::Assertion => self.assertion_key_id,
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
            did: "did:tdw:example.com:9hXq2vRtL8pK7f".into(),
            state: None,
            description: None,
            authorized_key_id: None,
            authentication_key_id: None,
            assertion_key_id: None,
            signing_key_id: Some("fixture".into()),
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
