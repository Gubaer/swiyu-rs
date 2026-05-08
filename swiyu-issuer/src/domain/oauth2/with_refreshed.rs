//! `with_refreshed_token` — call-site shape for protected registry
//! calls that may need a one-shot 401-refresh-retry.

use std::future::Future;

use swiyu_registries::common::{AccessToken, RegistryError};

use super::{TokenAwareError, TokenProvider};

/// Run `op` with a fresh access token from `provider`, retrying once
/// on `401 Unauthorized` after `provider.invalidate()`.
///
/// This is the canonical call-site shape for every protected registry
/// call in the worker:
///
/// ```ignore
/// with_refreshed_token(&provider, |token| {
///     registry.allocate_did(token, partner_id)
/// })
/// .await?;
/// ```
///
/// `op` is bounded as `Fn`, not `FnOnce`, because it may run twice (a
/// 401 on the first attempt triggers a single retry with a fresh
/// token). Other registry errors — 5xx, 4xx other than 401, transport
/// failures — are propagated without a retry; outer backoff is the
/// worker's concern.
pub async fn with_refreshed_token<P, T, F, Fut>(provider: &P, op: F) -> Result<T, TokenAwareError>
where
    P: TokenProvider + ?Sized,
    F: Fn(&AccessToken) -> Fut,
    Fut: Future<Output = Result<T, RegistryError>>,
{
    let token = provider.get().await?;
    match op(&token).await {
        Ok(value) => Ok(value),
        Err(RegistryError::HttpStatus { status: 401, .. }) => {
            let token = provider.invalidate().await?;
            op(&token).await.map_err(Into::into)
        }
        Err(other) => Err(other.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use crate::domain::oauth2::TokenProviderError;

    /// In-test `TokenProvider` that records every call and either
    /// returns a fresh access token or a configured failure.
    struct MockTokenProvider {
        calls: Mutex<Vec<&'static str>>,
        get_fails: bool,
    }

    impl MockTokenProvider {
        fn new() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                get_fails: false,
            }
        }

        fn with_get_failure() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                get_fails: true,
            }
        }

        fn calls(&self) -> Vec<&'static str> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl TokenProvider for MockTokenProvider {
        fn get(&self) -> impl Future<Output = Result<AccessToken, TokenProviderError>> + Send {
            self.calls.lock().unwrap().push("get");
            let fails = self.get_fails;
            async move {
                if fails {
                    Err(TokenProviderError::Transport("mock get failure".into()))
                } else {
                    Ok(AccessToken::new("mock-get".to_string()))
                }
            }
        }

        fn invalidate(
            &self,
        ) -> impl Future<Output = Result<AccessToken, TokenProviderError>> + Send {
            self.calls.lock().unwrap().push("invalidate");
            async move { Ok(AccessToken::new("mock-invalidate".to_string())) }
        }
    }

    fn http_401() -> RegistryError {
        RegistryError::HttpStatus {
            status: 401,
            body: "expired".into(),
        }
    }

    fn http_500() -> RegistryError {
        RegistryError::HttpStatus {
            status: 500,
            body: "boom".into(),
        }
    }

    #[tokio::test]
    async fn success_on_first_try_calls_op_once_and_no_invalidate() {
        let provider = MockTokenProvider::new();
        let invocations = Mutex::new(0u32);
        let result: Result<&str, TokenAwareError> = with_refreshed_token(&provider, |_token| {
            *invocations.lock().unwrap() += 1;
            async { Ok("ok") }
        })
        .await;
        assert!(matches!(result, Ok("ok")));
        assert_eq!(provider.calls(), vec!["get"]);
        assert_eq!(*invocations.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn first_call_401_then_success_after_invalidate() {
        let provider = MockTokenProvider::new();
        let invocations = Mutex::new(0u32);
        let result: Result<&str, TokenAwareError> = with_refreshed_token(&provider, |_token| {
            let n = {
                let mut g = invocations.lock().unwrap();
                *g += 1;
                *g
            };
            async move {
                if n == 1 {
                    Err(http_401())
                } else {
                    Ok("ok-after-refresh")
                }
            }
        })
        .await;
        assert!(matches!(result, Ok("ok-after-refresh")));
        assert_eq!(provider.calls(), vec!["get", "invalidate"]);
        assert_eq!(*invocations.lock().unwrap(), 2);
    }

    #[tokio::test]
    async fn second_401_is_terminal() {
        let provider = MockTokenProvider::new();
        let invocations = Mutex::new(0u32);
        let result: Result<(), TokenAwareError> = with_refreshed_token(&provider, |_token| {
            *invocations.lock().unwrap() += 1;
            async { Err(http_401()) }
        })
        .await;
        match result {
            Err(TokenAwareError::Registry(RegistryError::HttpStatus { status: 401, .. })) => {}
            other => panic!("expected Registry(401), got {other:?}"),
        }
        assert_eq!(provider.calls(), vec!["get", "invalidate"]);
        assert_eq!(*invocations.lock().unwrap(), 2);
    }

    #[tokio::test]
    async fn non_401_registry_error_is_not_retried() {
        let provider = MockTokenProvider::new();
        let invocations = Mutex::new(0u32);
        let result: Result<(), TokenAwareError> = with_refreshed_token(&provider, |_token| {
            *invocations.lock().unwrap() += 1;
            async { Err(http_500()) }
        })
        .await;
        match result {
            Err(TokenAwareError::Registry(RegistryError::HttpStatus { status: 500, .. })) => {}
            other => panic!("expected Registry(500), got {other:?}"),
        }
        assert_eq!(provider.calls(), vec!["get"]);
        assert_eq!(*invocations.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn token_error_propagates_without_calling_op() {
        let provider = MockTokenProvider::with_get_failure();
        let invocations = Mutex::new(0u32);
        let result: Result<(), TokenAwareError> = with_refreshed_token(&provider, |_token| {
            *invocations.lock().unwrap() += 1;
            async { Ok(()) }
        })
        .await;
        match result {
            Err(TokenAwareError::Token(TokenProviderError::Transport(_))) => {}
            other => panic!("expected Token(Transport), got {other:?}"),
        }
        assert_eq!(provider.calls(), vec!["get"]);
        assert_eq!(*invocations.lock().unwrap(), 0);
    }
}
