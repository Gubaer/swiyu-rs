//! OAuth2 token lifecycle for the SWIYU registries.
//!
//! Core abstraction: a [`TokenProvider`] is the in-memory state
//! machine for one OAuth2 credential set. Multi-tenant code holds
//! one provider per tenant; a forthcoming `ProviderRegistry` will
//! own the `tenant_id → Arc<…>` map.

use std::future::Future;

use thiserror::Error;

use swiyu_registries::common::{AccessToken, RegistryError};

use crate::persistence::PersistenceError;

pub mod oauth2_provider;
pub mod static_provider;
pub mod with_refreshed;

pub use oauth2_provider::OAuth2TokenProvider;
pub use static_provider::StaticTokenProvider;
pub use with_refreshed::with_refreshed_token;

/// In-memory state machine for one OAuth2 credential set.
///
/// `&self` because internal synchronisation lives inside each
/// implementation. Multi-tenant runtime polymorphism is achieved
/// through a dispatch enum (introduced alongside the OAuth2
/// backend), not through `&dyn TokenProvider`.
pub trait TokenProvider: Send + Sync {
    /// Returns a currently-valid access token, refreshing
    /// transparently via a `refresh_token` grant if the cached one
    /// has elapsed its safety margin.
    ///
    /// On the warm path (cache populated and comfortably inside the
    /// `expires_in` window) this is a cheap clone; on the cold path
    /// or when the cached token is near expiry it performs a
    /// network round-trip to the OAuth2 token endpoint.
    fn get(&self) -> impl Future<Output = Result<AccessToken, TokenProviderError>> + Send;

    /// Discards the cached access token and forces a fresh
    /// `refresh_token` grant.
    ///
    /// Called when a `401 Unauthorized` from a registry signals
    /// that the token the caller just used is no longer accepted —
    /// typically because the authorization server invalidated it
    /// before its `expires_in` elapsed (operator-driven revocation,
    /// clock skew). Returns the freshly-minted access token so the
    /// caller can retry the registry call once.
    fn invalidate(&self) -> impl Future<Output = Result<AccessToken, TokenProviderError>> + Send;
}

/// Failure modes of a [`TokenProvider`].
///
/// `RefreshRejected` and `MissingCredentials` are not retryable: both
/// require human intervention via the ePortal and the tenant row.
/// `Transport` and `Persistence` are transient and retryable per
/// [`is_retryable`](TokenProviderError::is_retryable).
#[derive(Debug, Error)]
pub enum TokenProviderError {
    /// Refresh token is no longer valid — typically because it
    /// expired (>7 days without a successful refresh) or was revoked
    /// at the authorization server. Recovery requires a fresh renewal
    /// token to be pasted into the tenant row.
    #[error("refresh token rejected: {0}")]
    RefreshRejected(String),
    /// Token endpoint returned a 5xx, or the request failed before
    /// reaching it (network error, timeout). Retryable.
    #[error("token endpoint transport: {0}")]
    Transport(String),
    /// The token endpoint replied 2xx but the body was unparseable
    /// or missing required fields.
    #[error("token endpoint decode: {0}")]
    Decode(String),
    /// Tenant configuration is missing one or more required OAuth2
    /// fields (`oauth_client_id`, `oauth_client_secret`,
    /// `oauth_refresh_token`). Surfaces as Terminal in the worker.
    #[error("tenant missing oauth credentials: {0}")]
    MissingCredentials(String),
    /// Persistence layer error while reading or writing the tenant
    /// row.
    #[error(transparent)]
    Persistence(#[from] PersistenceError),
}

impl TokenProviderError {
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Transport(_) | Self::Persistence(_))
    }
}

/// Return type of [`with_refreshed_token`]: either the registry call
/// itself failed, or the [`TokenProvider`] could not produce a token.
///
/// `is_retryable` defers to the inner error's classification — neither
/// branch knows enough to override the other's judgement.
#[derive(Debug, Error)]
pub enum TokenAwareError {
    #[error(transparent)]
    Registry(#[from] RegistryError),
    #[error(transparent)]
    Token(#[from] TokenProviderError),
}

impl TokenAwareError {
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Registry(e) => e.is_retryable(),
            Self::Token(e) => e.is_retryable(),
        }
    }
}

/// Runtime dispatch enum over the concrete `TokenProvider`
/// implementations.
///
/// `TokenProvider`'s `&self` async-fn-in-trait shape rules out
/// `Box<dyn TokenProvider>`; this enum is the codebase's standard
/// dispatch pattern (see also `AnySigningEngine`). The
/// `ProviderRegistry` (forthcoming) holds providers as
/// `Arc<AnyTokenProvider>` keyed by tenant id.
///
/// The `OAuth2` variant is intentionally larger than `Static`: the
/// real provider carries a DB pool, an HTTP client, and the
/// in-memory cache. The enum is always held inside `Arc<...>`, so
/// the size delta does not propagate through the call chain.
#[allow(clippy::large_enum_variant)]
pub enum AnyTokenProvider {
    OAuth2(OAuth2TokenProvider),
    Static(StaticTokenProvider),
}

impl TokenProvider for AnyTokenProvider {
    // See the OAuth2 impl for why the explicit RPIT form (rather
    // than `async fn`) is load-bearing.
    #[allow(clippy::manual_async_fn)]
    fn get(&self) -> impl Future<Output = Result<AccessToken, TokenProviderError>> + Send {
        async move {
            match self {
                Self::OAuth2(p) => p.get().await,
                Self::Static(p) => p.get().await,
            }
        }
    }

    #[allow(clippy::manual_async_fn)]
    fn invalidate(&self) -> impl Future<Output = Result<AccessToken, TokenProviderError>> + Send {
        async move {
            match self {
                Self::OAuth2(p) => p.invalidate().await,
                Self::Static(p) => p.invalidate().await,
            }
        }
    }
}
