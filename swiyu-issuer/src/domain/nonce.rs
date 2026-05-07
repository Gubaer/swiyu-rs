use std::fmt;

use sha2::{Digest, Sha256};

const NONCE_BYTES: usize = 16;

/// An OID4VCI `c_nonce` — the short-lived value the wallet binds
/// into its proof JWT at `POST /credential`. Minted alongside the
/// access token at the token endpoint; consumed (deleted) when the
/// credential endpoint validates a wallet proof carrying it.
///
/// 16 bytes from the OS CSPRNG, base58-encoded. The bare value is
/// returned to the wallet exactly once and never persisted; only
/// its [`NonceHash`] is. Same redaction discipline as
/// [`crate::domain::PreAuthCode`] and [`crate::domain::AccessTokenSecret`].
pub struct NonceSecret(String);

impl NonceSecret {
    pub fn generate() -> Self {
        let mut bytes = [0u8; NONCE_BYTES];
        getrandom::fill(&mut bytes).expect("OS RNG must be available");
        Self(bs58::encode(&bytes).into_string())
    }

    /// Reconstructs a `NonceSecret` from a bare value the
    /// persistence layer just read out of the database.
    pub fn from_stored(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn hash(&self) -> NonceHash {
        let mut hasher = Sha256::new();
        hasher.update(self.0.as_bytes());
        let digest = hasher.finalize();
        NonceHash(bs58::encode(&digest).into_string())
    }
}

impl From<NonceSecret> for String {
    fn from(nonce: NonceSecret) -> Self {
        nonce.0
    }
}

impl fmt::Debug for NonceSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("NonceSecret").field(&"<redacted>").finish()
    }
}

/// The persistable form of a [`NonceSecret`]: SHA-256 of the bare
/// value, base58-encoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonceHash(String);

impl NonceHash {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn from_stored(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_nonces_are_distinct() {
        let a = NonceSecret::generate();
        let b = NonceSecret::generate();
        assert_ne!(a.as_str(), b.as_str());
    }

    #[test]
    fn hash_is_deterministic() {
        let nonce = NonceSecret::generate();
        assert_eq!(nonce.hash(), nonce.hash());
    }

    #[test]
    fn matches_succeeds_for_same_nonce() {
        let nonce = NonceSecret::generate();
        let stored = nonce.hash();
        assert_eq!(stored, nonce.hash());
    }

    #[test]
    fn matches_fails_for_different_nonces() {
        let stored = NonceSecret::generate().hash();
        let other = NonceSecret::generate();
        assert_ne!(stored, other.hash());
    }

    #[test]
    fn debug_does_not_reveal_secret() {
        let nonce = NonceSecret::generate();
        let rendered = format!("{nonce:?}");
        assert!(!rendered.contains(nonce.as_str()));
        assert!(rendered.contains("redacted"));
    }
}
