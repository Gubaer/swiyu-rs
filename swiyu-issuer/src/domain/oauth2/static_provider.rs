//! `StaticTokenProvider` — test fixture that always returns the
//! same token.
//!
//! Used by per-step executor unit tests that need a `TokenProvider`
//! without exercising the OAuth2 flow. Internal to this crate; not
//! re-exported for use by other crates.

use std::future::Future;

use swiyu_registries::common::AccessToken;

use super::{TokenProvider, TokenProviderError};

/// `TokenProvider` that always hands out the same fixed
/// [`AccessToken`].
///
/// Holds no OAuth2 state and performs no network I/O. `get` and
/// `invalidate` both return a clone of the wrapped token; neither
/// can fail. Intended exclusively as a test fixture for executor
/// unit tests that need a `TokenProvider` without exercising the
/// OAuth2 flow — production code uses the (forthcoming)
/// `OAuth2TokenProvider` instead.
pub struct StaticTokenProvider {
    token: AccessToken,
}

impl StaticTokenProvider {
    pub fn new(token: AccessToken) -> Self {
        Self { token }
    }
}

impl TokenProvider for StaticTokenProvider {
    fn get(&self) -> impl Future<Output = Result<AccessToken, TokenProviderError>> + Send {
        let token = self.token.clone();
        async move { Ok(token) }
    }

    fn invalidate(&self) -> impl Future<Output = Result<AccessToken, TokenProviderError>> + Send {
        let token = self.token.clone();
        async move { Ok(token) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn get_returns_a_masked_token() {
        let provider = StaticTokenProvider::new(AccessToken::new("test-token".to_string()));
        let token = provider.get().await.expect("get returns Ok");
        // The Debug impl masks the value. The actual round-trip from
        // construction → bearer header is exercised via wiremock in the
        // OAuth2 integration tests (Phase 4); here we just confirm the
        // provider is reachable through the trait and emits a token.
        assert_eq!(format!("{token:?}"), "AccessToken(***)");
    }

    #[tokio::test]
    async fn invalidate_returns_a_masked_token() {
        let provider = StaticTokenProvider::new(AccessToken::new("test-token".to_string()));
        let token = provider.invalidate().await.expect("invalidate returns Ok");
        assert_eq!(format!("{token:?}"), "AccessToken(***)");
    }
}
