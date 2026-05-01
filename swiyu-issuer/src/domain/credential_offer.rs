use chrono::{DateTime, Utc};
use serde_json::Value;

use super::DomainError;
use super::ids::{CredentialOfferId, IssuerId, TenantId};
use super::pre_auth_code::PreAuthCodeHash;

/// Lifecycle state of a `CredentialOffer`.
///
/// New offers start in `Pending`. Each offer transitions exactly
/// once to one of the three terminal states: `Issued` when the
/// wallet has picked up the offer and the credential has been
/// issued, `Cancelled` if the offer is withdrawn before pickup,
/// or `Expired` if `expires_at` is reached while still pending.
///
/// v0.1.0 evaluates expiry on read. A background sweeper that
/// flips state on a timer lands in a later slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialOfferState {
    Pending,
    Issued,
    Cancelled,
    Expired,
}

impl CredentialOfferState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Issued => "issued",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn parse(s: &str) -> Result<Self, DomainError> {
        match s {
            "pending" => Ok(Self::Pending),
            "issued" => Ok(Self::Issued),
            "cancelled" => Ok(Self::Cancelled),
            "expired" => Ok(Self::Expired),
            _ => Err(DomainError::InvalidInput {
                details: format!("unknown credential offer state: {s}"),
            }),
        }
    }
}

/// A pending or settled OID4VCI credential offer.
///
/// Created by the management API when a business application asks
/// `swiyu-issuer` to mint an offer for a holder; consumed by the
/// wallet over the OID4VCI flow at the issuance endpoints. The
/// secret pre-authorisation code is returned to the caller exactly
/// once at creation; only its hash is kept on this aggregate.
#[derive(Debug, Clone)]
pub struct CredentialOffer {
    /// Generated at construction time by the application, not by
    /// the database. See `specs/impl_persistence.md` for the
    /// identifier strategy.
    pub id: CredentialOfferId,

    /// Carried directly rather than derived from `issuer_id` so
    /// scoped queries and future row-level security predicates can
    /// filter by tenant without joining.
    pub tenant_id: TenantId,

    /// Issuer that mints the credential. Belongs to `tenant_id`;
    /// the ownership invariant is checked at the request boundary
    /// before this aggregate is constructed.
    pub issuer_id: IssuerId,

    /// SD-JWT VC type identifier (a URI). Determines which JSON
    /// Schema validates `claims`.
    pub vct: String,

    /// Credential claims as a JSON object, validated against the
    /// schema bundled for the `vct` before this aggregate is
    /// constructed.
    pub claims: Value,

    /// Current lifecycle state. See `CredentialOfferState`.
    pub state: CredentialOfferState,

    /// Hash of the OID4VCI pre-authorised code. The bare secret is
    /// returned to the caller exactly once at offer creation and
    /// is never persisted.
    pub pre_auth_code_hash: PreAuthCodeHash,

    /// Last moment the offer is honoured for issuance. After this
    /// instant, reads treat the offer as `Expired`.
    pub expires_at: DateTime<Utc>,

    /// Set at construction time. The DB column also has a
    /// `DEFAULT NOW()` as a safety net for any direct INSERTs.
    pub created_at: DateTime<Utc>,
}

impl CredentialOffer {
    pub fn new(
        tenant_id: TenantId,
        issuer_id: IssuerId,
        vct: String,
        claims: Value,
        pre_auth_code_hash: PreAuthCodeHash,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id: CredentialOfferId::generate(),
            tenant_id,
            issuer_id,
            vct,
            claims,
            state: CredentialOfferState::Pending,
            pre_auth_code_hash,
            expires_at,
            created_at: Utc::now(),
        }
    }

    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }

    /// Transitions this offer from `Pending` to `Issued`.
    ///
    /// Records that the wallet has successfully picked the offer up.
    /// A second attempt fails, so a single offer cannot back two
    /// issuances.
    ///
    /// `now` is a parameter rather than read from the system clock so
    /// the caller can supply a stable reference time — deterministic
    /// in tests, consistent with other time checks made within the
    /// same request.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::StateTransitionNotAllowed`] if the offer
    /// is not currently `Pending` or if `now >= expires_at`.
    pub fn try_issue(&mut self, now: DateTime<Utc>) -> Result<(), DomainError> {
        match self.state {
            CredentialOfferState::Pending if !self.is_expired_at(now) => {
                self.state = CredentialOfferState::Issued;
                Ok(())
            }
            _ => Err(DomainError::StateTransitionNotAllowed),
        }
    }

    /// Transitions this offer from `Pending` to `Cancelled`.
    ///
    /// Used when the business application withdraws an offer before
    /// the wallet has picked it up — for example, after discovering
    /// an error in the claims or learning that the holder's
    /// eligibility has changed.
    ///
    /// Cancellation does not check expiry: a still-`Pending` offer
    /// past its `expires_at` may be cancelled cleanly so the row
    /// reflects an explicit terminal state.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::StateTransitionNotAllowed`] if the offer
    /// is not currently `Pending`.
    pub fn try_cancel(&mut self) -> Result<(), DomainError> {
        match self.state {
            CredentialOfferState::Pending => {
                self.state = CredentialOfferState::Cancelled;
                Ok(())
            }
            _ => Err(DomainError::StateTransitionNotAllowed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use serde_json::json;

    fn make_offer(expires_in: Duration) -> CredentialOffer {
        let pre_auth_code_hash = crate::domain::pre_auth_code::PreAuthCode::generate().hash();
        CredentialOffer::new(
            TenantId::from_bare("4Mk7yK5pQR7sN3").unwrap(),
            IssuerId::from_bare("9hXq2vRtL8pK7f").unwrap(),
            "urn:communal:local-residence-id".to_string(),
            json!({}),
            pre_auth_code_hash,
            Utc::now() + expires_in,
        )
    }

    #[test]
    fn new_offer_is_pending() {
        let offer = make_offer(Duration::minutes(10));
        assert_eq!(offer.state, CredentialOfferState::Pending);
    }

    #[test]
    fn try_issue_pending_unexpired_succeeds() {
        let mut offer = make_offer(Duration::minutes(10));
        offer.try_issue(Utc::now()).unwrap();
        assert_eq!(offer.state, CredentialOfferState::Issued);
    }

    #[test]
    fn try_issue_pending_expired_fails() {
        let mut offer = make_offer(Duration::seconds(-1));
        let result = offer.try_issue(Utc::now());
        assert!(result.is_err());
        assert_eq!(offer.state, CredentialOfferState::Pending);
    }

    #[test]
    fn try_issue_already_issued_fails() {
        let mut offer = make_offer(Duration::minutes(10));
        offer.try_issue(Utc::now()).unwrap();
        let result = offer.try_issue(Utc::now());
        assert!(result.is_err());
    }

    #[test]
    fn try_cancel_pending_succeeds() {
        let mut offer = make_offer(Duration::minutes(10));
        offer.try_cancel().unwrap();
        assert_eq!(offer.state, CredentialOfferState::Cancelled);
    }

    #[test]
    fn try_cancel_issued_fails() {
        let mut offer = make_offer(Duration::minutes(10));
        offer.try_issue(Utc::now()).unwrap();
        assert!(offer.try_cancel().is_err());
    }

    #[test]
    fn state_str_round_trip() {
        for state in [
            CredentialOfferState::Pending,
            CredentialOfferState::Issued,
            CredentialOfferState::Cancelled,
            CredentialOfferState::Expired,
        ] {
            assert_eq!(CredentialOfferState::parse(state.as_str()).unwrap(), state);
        }
    }

    #[test]
    fn state_parse_rejects_unknown() {
        assert!(CredentialOfferState::parse("unknown").is_err());
    }
}
