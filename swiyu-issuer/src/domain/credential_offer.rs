use chrono::{DateTime, Utc};
use serde_json::Value;

use super::DomainError;
use super::ids::{CredentialOfferId, IssuerId, TenantId};
use super::pre_auth_code::PreAuthCode;

/// Lifecycle state of a `CredentialOffer`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialOfferState {
    /// Initial state. The wallet has not yet picked up the offer.
    Pending,
    /// Terminal. The wallet picked up the offer and a credential was issued.
    Issued,
    /// Terminal. The offer was withdrawn before the wallet picked it up.
    Cancelled,
    /// Terminal. `expires_at` was reached while the offer was still pending.
    /// Expiry is evaluated on read.
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
}

impl TryFrom<&str> for CredentialOfferState {
    type Error = DomainError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
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
/// pre-authorisation code lives on this aggregate **plaintext during
/// the pending window** because the OID4VCI by-reference flow makes
/// the bare value retrievable at request time; it is set to `None`
/// at the first terminal-state transition.
#[derive(Debug, Clone)]
pub struct CredentialOffer {
    /// Generated at construction time by the application, not by
    /// the database.
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

    /// Bare OID4VCI pre-authorised code. Held here for the offer's
    /// pending window so the wallet's by-reference offer-uri fetch
    /// can return it. Set to `None` at the first terminal-state
    /// transition (`try_cancel`, `try_issue`).
    pub pre_auth_code: Option<PreAuthCode>,

    /// Last moment the offer is honoured for issuance. After this
    /// instant, reads treat the offer as `Expired`.
    pub expires_at: DateTime<Utc>,

    /// Set at construction time. The DB column also has a
    /// `DEFAULT NOW()` as a safety net for any direct INSERTs.
    pub created_at: DateTime<Utc>,

    /// Stamped when the offer transitions to `Issued`. `None` until
    /// then. The OIDC binary owns the transition itself; the field
    /// is kept on this aggregate so the management API can surface
    /// it without joining other tables.
    pub issued_at: Option<DateTime<Utc>>,

    /// Stamped when the offer transitions to `Cancelled`. `None`
    /// until then.
    pub cancelled_at: Option<DateTime<Utc>>,
}

impl CredentialOffer {
    pub fn new(
        tenant_id: TenantId,
        issuer_id: IssuerId,
        vct: String,
        claims: Value,
        pre_auth_code: PreAuthCode,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id: CredentialOfferId::generate(),
            tenant_id,
            issuer_id,
            vct,
            claims,
            state: CredentialOfferState::Pending,
            pre_auth_code: Some(pre_auth_code),
            expires_at,
            created_at: Utc::now(),
            issued_at: None,
            cancelled_at: None,
        }
    }

    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }

    /// Returns the state as observed at `now`.
    ///
    /// Differs from the stored [`CredentialOfferState`] only when
    /// an offer is still `Pending` past its `expires_at`: storage
    /// keeps `Pending` (v0.1.0 has no background sweeper that flips
    /// state on a timer), but a read at or after `expires_at`
    /// reports `Expired`.
    pub fn observed_state(&self, now: DateTime<Utc>) -> CredentialOfferState {
        match self.state {
            CredentialOfferState::Pending if self.is_expired_at(now) => {
                CredentialOfferState::Expired
            }
            other => other,
        }
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
                self.issued_at = Some(now);
                self.pre_auth_code = None;
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
    /// `now` is a parameter rather than read from the system clock so
    /// the caller can supply a stable reference time — deterministic
    /// in tests, consistent with other time checks made within the
    /// same request.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::StateTransitionNotAllowed`] if the offer
    /// is not currently `Pending`.
    pub fn try_cancel(&mut self, now: DateTime<Utc>) -> Result<(), DomainError> {
        match self.state {
            CredentialOfferState::Pending => {
                self.state = CredentialOfferState::Cancelled;
                self.cancelled_at = Some(now);
                self.pre_auth_code = None;
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
        let pre_auth_code = PreAuthCode::generate();
        CredentialOffer::new(
            TenantId::from_bare("4Mk7yK5pQR7sN3").unwrap(),
            IssuerId::from_bare("9hXq2vRtL8pK7f").unwrap(),
            "urn:communal:local-residence-id".to_string(),
            json!({}),
            pre_auth_code,
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
        let now = Utc::now();
        offer.try_cancel(now).unwrap();
        assert_eq!(offer.state, CredentialOfferState::Cancelled);
        assert_eq!(offer.cancelled_at, Some(now));
    }

    #[test]
    fn try_cancel_issued_fails() {
        let mut offer = make_offer(Duration::minutes(10));
        offer.try_issue(Utc::now()).unwrap();
        assert!(offer.try_cancel(Utc::now()).is_err());
        // cancelled_at must remain unset after a rejected transition.
        assert!(offer.cancelled_at.is_none());
    }

    #[test]
    fn try_cancel_pending_past_expiry_succeeds() {
        let mut offer = make_offer(Duration::seconds(-1));
        let now = Utc::now();
        offer.try_cancel(now).unwrap();
        assert_eq!(offer.state, CredentialOfferState::Cancelled);
        assert_eq!(offer.cancelled_at, Some(now));
    }

    #[test]
    fn try_cancel_already_cancelled_fails() {
        let mut offer = make_offer(Duration::minutes(10));
        let first = Utc::now();
        offer.try_cancel(first).unwrap();
        let second = first + Duration::seconds(5);
        assert!(offer.try_cancel(second).is_err());
        // cancelled_at is the original stamp, not overwritten on retry.
        assert_eq!(offer.cancelled_at, Some(first));
    }

    #[test]
    fn try_issue_stamps_issued_at() {
        let mut offer = make_offer(Duration::minutes(10));
        let now = Utc::now();
        offer.try_issue(now).unwrap();
        assert_eq!(offer.issued_at, Some(now));
        assert!(offer.cancelled_at.is_none());
    }

    #[test]
    fn new_offer_carries_the_pre_auth_code() {
        let offer = make_offer(Duration::minutes(10));
        assert!(offer.pre_auth_code.is_some());
    }

    #[test]
    fn try_cancel_clears_the_pre_auth_code() {
        let mut offer = make_offer(Duration::minutes(10));
        offer.try_cancel(Utc::now()).unwrap();
        assert!(offer.pre_auth_code.is_none());
    }

    #[test]
    fn try_issue_clears_the_pre_auth_code() {
        let mut offer = make_offer(Duration::minutes(10));
        offer.try_issue(Utc::now()).unwrap();
        assert!(offer.pre_auth_code.is_none());
    }

    #[test]
    fn state_str_round_trip() {
        for state in [
            CredentialOfferState::Pending,
            CredentialOfferState::Issued,
            CredentialOfferState::Cancelled,
            CredentialOfferState::Expired,
        ] {
            assert_eq!(
                CredentialOfferState::try_from(state.as_str()).unwrap(),
                state
            );
        }
    }

    #[test]
    fn state_parse_rejects_unknown() {
        assert!(CredentialOfferState::try_from("unknown").is_err());
    }

    #[test]
    fn observed_state_pending_unexpired_stays_pending() {
        let offer = make_offer(Duration::minutes(10));
        assert_eq!(
            offer.observed_state(Utc::now()),
            CredentialOfferState::Pending
        );
    }

    #[test]
    fn observed_state_pending_expired_reports_expired() {
        let offer = make_offer(Duration::seconds(-1));
        assert_eq!(
            offer.observed_state(Utc::now()),
            CredentialOfferState::Expired
        );
        // Stored state is unchanged; observed_state is read-only.
        assert_eq!(offer.state, CredentialOfferState::Pending);
    }

    #[test]
    fn observed_state_issued_stays_issued_regardless_of_time() {
        let mut offer = make_offer(Duration::minutes(10));
        offer.try_issue(Utc::now()).unwrap();
        let later = Utc::now() + Duration::days(365);
        assert_eq!(offer.observed_state(later), CredentialOfferState::Issued);
    }

    #[test]
    fn observed_state_cancelled_stays_cancelled() {
        let mut offer = make_offer(Duration::minutes(10));
        offer.try_cancel(Utc::now()).unwrap();
        let later = Utc::now() + Duration::days(365);
        assert_eq!(offer.observed_state(later), CredentialOfferState::Cancelled);
    }
}
