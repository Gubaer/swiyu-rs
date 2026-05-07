use std::fmt;

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use super::DomainError;
use super::ids::{ApiTokenId, TenantId, is_base58_char};

const API_TOKEN_BYTES: usize = 32;
const WIRE_PREFIX: &str = "tok_";

/// Bare API-token secret — the long-lived shared secret a business
/// application sends in `Authorization: Bearer tok_<base58>`.
///
/// The wire form is `tok_<bare>` where `<bare>` is the base58
/// encoding of [`API_TOKEN_BYTES`] random bytes. Internally only the
/// bare body is held; [`as_wire`] reattaches the prefix on demand.
///
/// `ApiTokenSecret` deliberately does not implement `Clone`,
/// `Display`, or `serde::Serialize`. The custom `Debug` impl redacts
/// the value to prevent accidental log leakage. Comparison against a
/// stored token always goes through [`ApiTokenHash`], so the
/// bare secret never enters the persistence-layer signatures.
pub struct ApiTokenSecret(String);

impl ApiTokenSecret {
    pub fn generate() -> Self {
        let mut bytes = [0u8; API_TOKEN_BYTES];
        getrandom::fill(&mut bytes).expect("OS RNG must be available");
        Self(bs58::encode(&bytes).into_string())
    }

    /// Parses a wire-form token (`tok_<base58>`) into its bare body.
    ///
    /// Errors are deliberately coarse — anything malformed maps to a
    /// single [`DomainError::InvalidInput`] variant, so the auth
    /// extractor cannot distinguish "bad prefix" from "non-base58
    /// body" in its 401 response.
    pub fn from_wire(s: &str) -> Result<Self, DomainError> {
        let bare = s
            .strip_prefix(WIRE_PREFIX)
            .ok_or_else(|| DomainError::InvalidInput {
                details: "api token: missing 'tok_' prefix".to_string(),
            })?;
        if bare.is_empty() || bare.len() > 64 {
            return Err(DomainError::InvalidInput {
                details: "api token: bare body length out of range".to_string(),
            });
        }
        if bare.chars().any(|c| !is_base58_char(c)) {
            return Err(DomainError::InvalidInput {
                details: "api token: bare body contains non-base58 character".to_string(),
            });
        }
        Ok(Self(bare.to_string()))
    }

    pub fn bare(&self) -> &str {
        &self.0
    }

    pub fn as_wire(&self) -> String {
        format!("{WIRE_PREFIX}{}", self.0)
    }

    pub fn hash(&self) -> ApiTokenHash {
        let mut hasher = Sha256::new();
        hasher.update(self.0.as_bytes());
        let digest = hasher.finalize();
        ApiTokenHash(bs58::encode(&digest).into_string())
    }
}

impl fmt::Debug for ApiTokenSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ApiTokenSecret")
            .field(&"<redacted>")
            .finish()
    }
}

/// The persistable form of an [`ApiTokenSecret`].
///
/// Base58-encoded SHA-256 of the bare body. SHA-256 is appropriate
/// for high-entropy 256-bit secrets, and a slow password hash would
/// only add latency to the per-request auth path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiTokenHash(String);

impl ApiTokenHash {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn from_stored(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

/// A persisted API token row.
///
/// The bare secret is never stored on this aggregate; only its
/// [`ApiTokenHash`] is. A token is **valid** iff
/// `revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now)`;
/// see [`ApiToken::is_valid_at`].
#[derive(Debug, Clone)]
pub struct ApiToken {
    pub id: ApiTokenId,
    pub tenant_id: TenantId,
    pub name: String,
    pub token_hash: ApiTokenHash,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
}

impl ApiToken {
    /// Constructs a fresh token for `tenant_id` with the given name
    /// and optional expiry. Generates a new id; the caller computes
    /// the hash from the bare secret it minted alongside.
    pub fn new(
        tenant_id: TenantId,
        name: String,
        token_hash: ApiTokenHash,
        expires_at: Option<DateTime<Utc>>,
    ) -> Self {
        Self {
            id: ApiTokenId::generate(),
            tenant_id,
            name,
            token_hash,
            created_at: Utc::now(),
            expires_at,
            revoked_at: None,
            last_used_at: None,
        }
    }

    pub fn is_valid_at(&self, now: DateTime<Utc>) -> bool {
        if self.revoked_at.is_some() {
            return false;
        }
        match self.expires_at {
            Some(exp) => exp > now,
            None => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    /// Bare body of the dev token seeded by migration
    /// `20260502_000003_api_tokens.sql`.
    const DEV_TOKEN_BARE: &str = "DevDevDevDevDevDevDevDevDevDevDevDevDevDe";

    /// Hash literal in the same migration. If `DEV_TOKEN_BARE` ever
    /// changes, recomputing this hash and updating both the migration
    /// and the constant below is mandatory.
    const DEV_TOKEN_HASH: &str = "eNmyzEH7r3JEawZtuEkdePoqyEoNSoKG7FJVZPwXHbh";

    fn make_token() -> ApiToken {
        let secret = ApiTokenSecret::generate();
        ApiToken::new(
            TenantId::from_bare("4Mk7yK5pQR7sN3").unwrap(),
            "test-token".to_string(),
            secret.hash(),
            None,
        )
    }

    #[test]
    fn generated_secrets_are_distinct() {
        let a = ApiTokenSecret::generate();
        let b = ApiTokenSecret::generate();
        assert_ne!(a.bare(), b.bare());
    }

    #[test]
    fn wire_form_roundtrips() {
        let secret = ApiTokenSecret::generate();
        let wire = secret.as_wire();
        let parsed = ApiTokenSecret::from_wire(&wire).unwrap();
        assert_eq!(secret.bare(), parsed.bare());
    }

    #[test]
    fn from_wire_rejects_missing_prefix() {
        // bare body without the tok_ prefix
        assert!(ApiTokenSecret::from_wire("9hXq2vRtL8pK7f").is_err());
    }

    #[test]
    fn from_wire_rejects_wrong_prefix() {
        assert!(ApiTokenSecret::from_wire("offer_9hXq2vRtL8pK7f").is_err());
    }

    #[test]
    fn from_wire_rejects_non_base58_body() {
        assert!(ApiTokenSecret::from_wire("tok_DevDev0Dev").is_err());
    }

    #[test]
    fn from_wire_rejects_empty_body() {
        assert!(ApiTokenSecret::from_wire("tok_").is_err());
    }

    #[test]
    fn hash_is_deterministic() {
        let secret = ApiTokenSecret::generate();
        assert_eq!(secret.hash(), secret.hash());
    }

    #[test]
    fn matches_succeeds_for_same_secret() {
        let secret = ApiTokenSecret::generate();
        let stored = secret.hash();
        assert_eq!(stored, secret.hash());
    }

    #[test]
    fn matches_fails_for_different_secrets() {
        let stored = ApiTokenSecret::generate().hash();
        let other = ApiTokenSecret::generate();
        assert_ne!(stored, other.hash());
    }

    #[test]
    fn debug_does_not_reveal_secret() {
        let secret = ApiTokenSecret::generate();
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains(secret.bare()));
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn dev_token_hash_matches_migration() {
        // Cross-check: the literal in 20260502_000003_api_tokens.sql
        // must match SHA-256 base58 of DEV_TOKEN_BARE. If this fails,
        // either the bare body changed or the migration drifted.
        let secret = ApiTokenSecret::from_wire(&format!("tok_{DEV_TOKEN_BARE}")).unwrap();
        assert_eq!(secret.hash().as_str(), DEV_TOKEN_HASH);
    }

    #[test]
    fn is_valid_at_unrevoked_no_expiry() {
        let token = make_token();
        assert!(token.is_valid_at(Utc::now()));
    }

    #[test]
    fn is_valid_at_revoked_is_invalid() {
        let mut token = make_token();
        token.revoked_at = Some(Utc::now());
        assert!(!token.is_valid_at(Utc::now()));
    }

    #[test]
    fn is_valid_at_unexpired_is_valid() {
        let mut token = make_token();
        token.expires_at = Some(Utc::now() + Duration::days(30));
        assert!(token.is_valid_at(Utc::now()));
    }

    #[test]
    fn is_valid_at_expired_is_invalid() {
        let mut token = make_token();
        token.expires_at = Some(Utc::now() - Duration::seconds(1));
        assert!(!token.is_valid_at(Utc::now()));
    }
}
