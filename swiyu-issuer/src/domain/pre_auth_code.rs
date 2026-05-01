use std::fmt;

use sha2::{Digest, Sha256};

const PRE_AUTH_CODE_BYTES: usize = 16;

/// An OID4VCI pre-authorised code — the short-lived secret returned
/// to the wallet at credential-offer creation, which the wallet
/// later presents at the token endpoint to redeem the credential.
///
/// The bare secret is returned to the API caller exactly once at
/// offer creation and is never persisted. Only its
/// [`PreAuthCodeHash`] is stored, so the database alone is
/// insufficient to redeem an offer.
///
/// `PreAuthCode` deliberately does not implement `Clone`, `Display`,
/// or `serde::Serialize`. The custom `Debug` impl redacts the value
/// to prevent accidental log leakage. To compare a candidate against
/// a stored hash, use [`PreAuthCodeHash::matches`], which keeps the
/// bare secret out of persistence-layer signatures entirely.
pub struct PreAuthCode(String);

impl PreAuthCode {
    pub fn generate() -> Self {
        let mut bytes = [0u8; PRE_AUTH_CODE_BYTES];
        getrandom::fill(&mut bytes).expect("OS RNG must be available");
        Self(bs58::encode(&bytes).into_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }

    /// Reconstructs a `PreAuthCode` from a bare value the persistence
    /// layer just read out of `oidc_offer_bridge`. Mirrors the
    /// `PreAuthCodeHash::from_stored` discipline: the only callers
    /// are inside `persistence`, and the redacted `Debug` impl keeps
    /// the secret out of any incidental log line.
    pub fn from_stored(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn hash(&self) -> PreAuthCodeHash {
        let mut hasher = Sha256::new();
        hasher.update(self.0.as_bytes());
        let digest = hasher.finalize();
        PreAuthCodeHash(bs58::encode(&digest).into_string())
    }
}

// Custom Debug avoids leaking the secret if a PreAuthCode is logged accidentally.
impl fmt::Debug for PreAuthCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PreAuthCode").field(&"<redacted>").finish()
    }
}

/// The persistable form of a [`PreAuthCode`].
///
/// SHA-256 of the bare pre-auth code, base58-encoded. This is the
/// only form of the secret that the persistence layer accepts:
/// `swiyu-issuer`'s database stores the hash, never the bare code.
/// Recovering the original from this hash requires brute-forcing
/// the 128-bit input space, which is computationally infeasible.
///
/// SHA-256 is appropriate here rather than a password hash such as
/// bcrypt or argon2 because the pre-auth code is high-entropy and
/// short-lived: the cost of a slow hash is unnecessary and would
/// only add latency to the wallet's redemption flow.
///
/// Use [`PreAuthCodeHash::matches`] to compare a candidate
/// [`PreAuthCode`] against a stored hash, keeping the bare secret
/// out of any code path that touches persistence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreAuthCodeHash(String);

impl PreAuthCodeHash {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn from_stored(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn matches(&self, candidate: &PreAuthCode) -> bool {
        self == &candidate.hash()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_codes_are_distinct() {
        let a = PreAuthCode::generate();
        let b = PreAuthCode::generate();
        assert_ne!(a.as_str(), b.as_str());
    }

    #[test]
    fn hash_is_deterministic() {
        let code = PreAuthCode::generate();
        assert_eq!(code.hash(), code.hash());
    }

    #[test]
    fn matches_succeeds_for_same_secret() {
        let code = PreAuthCode::generate();
        let stored = code.hash();
        assert!(stored.matches(&code));
    }

    #[test]
    fn matches_fails_for_different_secrets() {
        let stored = PreAuthCode::generate().hash();
        let other = PreAuthCode::generate();
        assert!(!stored.matches(&other));
    }

    #[test]
    fn debug_does_not_reveal_secret() {
        let code = PreAuthCode::generate();
        let rendered = format!("{code:?}");
        assert!(!rendered.contains(code.as_str()));
        assert!(rendered.contains("redacted"));
    }
}
