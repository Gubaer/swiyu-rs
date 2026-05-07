use std::fmt;

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use super::ids::{CredentialOfferId, IssuerId, TenantId};

const ACCESS_TOKEN_BYTES: usize = 16;

/// An OAuth access token — the short-lived bearer secret returned
/// by `POST /token` and presented at `POST /credential`.
///
/// 16 bytes from the OS CSPRNG, base58-encoded. The bare value is
/// returned to the wallet exactly once at the token endpoint and is
/// never persisted; only its [`AccessTokenHash`] is. The redacted
/// `Debug` impl prevents accidental log leakage; comparison against
/// a stored hash always goes through [`AccessTokenHash::matches`].
pub struct AccessTokenSecret(String);

impl AccessTokenSecret {
    pub fn generate() -> Self {
        let mut bytes = [0u8; ACCESS_TOKEN_BYTES];
        getrandom::fill(&mut bytes).expect("OS RNG must be available");
        Self(bs58::encode(&bytes).into_string())
    }

    /// Reconstructs an `AccessTokenSecret` from a bare value the
    /// persistence layer just read out of the database. Mirrors the
    /// `PreAuthCode::from_stored` discipline.
    pub fn from_stored(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn hash(&self) -> AccessTokenHash {
        let mut hasher = Sha256::new();
        hasher.update(self.0.as_bytes());
        let digest = hasher.finalize();
        AccessTokenHash(bs58::encode(&digest).into_string())
    }
}

impl From<AccessTokenSecret> for String {
    fn from(token: AccessTokenSecret) -> Self {
        token.0
    }
}

impl fmt::Debug for AccessTokenSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AccessTokenSecret")
            .field(&"<redacted>")
            .finish()
    }
}

/// A persisted access-token row.
///
/// Returned by `persistence::oidc::access_tokens::find_valid_by_hash`
/// after a successful Bearer-header lookup at the credential
/// endpoint. Carries the offer_id so the handler can fetch the
/// associated `credential_offers` row, and tenant/issuer for
/// defense-in-depth scoping on the subsequent state-transition
/// writes.
#[derive(Debug, Clone)]
pub struct AccessToken {
    pub token_hash: AccessTokenHash,
    pub tenant_id: TenantId,
    pub issuer_id: IssuerId,
    pub offer_id: CredentialOfferId,
    pub expires_at: DateTime<Utc>,
}

/// The persistable form of an [`AccessTokenSecret`]: SHA-256 of the
/// bare value, base58-encoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessTokenHash(String);

impl AccessTokenHash {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn from_stored(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn matches(&self, candidate: &AccessTokenSecret) -> bool {
        self == &candidate.hash()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_secrets_are_distinct() {
        let a = AccessTokenSecret::generate();
        let b = AccessTokenSecret::generate();
        assert_ne!(a.as_str(), b.as_str());
    }

    #[test]
    fn hash_is_deterministic() {
        let secret = AccessTokenSecret::generate();
        assert_eq!(secret.hash(), secret.hash());
    }

    #[test]
    fn matches_succeeds_for_same_secret() {
        let secret = AccessTokenSecret::generate();
        let stored = secret.hash();
        assert!(stored.matches(&secret));
    }

    #[test]
    fn matches_fails_for_different_secrets() {
        let stored = AccessTokenSecret::generate().hash();
        let other = AccessTokenSecret::generate();
        assert!(!stored.matches(&other));
    }

    #[test]
    fn debug_does_not_reveal_secret() {
        let secret = AccessTokenSecret::generate();
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains(secret.as_str()));
        assert!(rendered.contains("redacted"));
    }
}
