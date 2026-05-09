//! Async-trait abstractions over the two SWIYU registry HTTP clients
//! the worker drives, plus the per-method 401-retry wrappers built on
//! top of them.
//!
//! - [`RegistryFacade`] — Identifier Registry. Used by the
//!   create-issuer, rotate-keys, and deactivate-issuer sagas.
//! - [`StatusRegistryFacade`] — Status Registry. Used by the
//!   create-issuer saga (allocate the entry) and the status-list
//!   publish loop (PUT signed JWTs).
//! - [`allocate_did_with_refresh`], [`publish_log_entry_with_refresh`],
//!   [`create_status_list_entry_with_refresh`],
//!   [`update_status_list_entry_with_refresh`] — pair a
//!   [`crate::domain::TokenProvider`] with the matching facade method,
//!   retrying once on `401 Unauthorized` after `provider.invalidate()`.
//!
//! The per-step worker functions in `worker::create_issuer`,
//! `worker::deactivate_issuer`, and `worker::rotate_keys` take `&impl
//! RegistryFacade` / `&impl StatusRegistryFacade` so unit tests can
//! inject an in-memory mock without pulling wiremock into the
//! unit-test scope, while production code passes the real client
//! wrapping `swiyu_registries`. Native async-in-trait (Rust 2024)
//! with explicit `+ Send` bounds keeps futures unboxed; the traits
//! are consumed via generics rather than `&dyn` because `impl
//! Future` is not object-safe.

use std::future::Future;
use std::sync::Arc;

use swiyu_core::did::DID;
use swiyu_core::didlog::{DIDLog, DIDLogEntry};
use swiyu_registries::common::{AccessToken, RegistryError};
use swiyu_registries::identifier::{Allocation, IdentifierRegistryClient};
use swiyu_registries::status::{StatusListEntry, StatusRegistryClient};

use crate::domain::oauth2::{TokenAwareError, TokenProvider};

/// A successful `fetch_log` result.
pub struct FetchedLog {
    /// Raw JSONL body as returned by the registry. Kept verbatim so
    /// publish_log can PUT the prior entries back unchanged —
    /// re-serialising the parsed entries would risk key-ordering or
    /// whitespace drift that would corrupt the entryHash chain.
    pub raw: String,
    /// Parsed entries, used to build the next log entry on top of the
    /// current tail. The SWIYU registry's PUT endpoint is
    /// "replace the whole log", not "append".
    pub entries: Vec<DIDLogEntry>,
}

/// Concatenates the existing DIDLog (JSONL) with a single new entry
/// line, producing the body to PUT back to the SWIYU registry:
/// previous lines verbatim, one `\n`, the new line, and no trailing
/// newline.
pub fn build_updated_didlog(prev_raw: &str, new_line: &str) -> String {
    let mut out = prev_raw.trim_end_matches('\n').to_string();
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(new_line);
    out
}

/// The registry operations the worker drives across [`CreateIssuer`]
/// and [`DeactivateIssuer`] tasks: allocate the DID space, fetch the
/// current DIDLog tail, and publish a signed DIDLog entry.
///
/// Errors flow through as [`RegistryError`]; callers route between
/// [`StepOutcome::Retry`] and [`StepOutcome::Terminal`] via
/// [`RegistryError::is_retryable`].
///
/// [`CreateIssuer`]: crate::domain::TaskType::CreateIssuer
/// [`DeactivateIssuer`]: crate::domain::TaskType::DeactivateIssuer
/// [`StepOutcome::Retry`]: crate::domain::StepOutcome::Retry
/// [`StepOutcome::Terminal`]: crate::domain::StepOutcome::Terminal
pub trait RegistryFacade: Send + Sync {
    /// Allocates a fresh DID identifier on the SWIYU partner-write
    /// API and returns the DID URL plus its bare identifier. Keyed
    /// by `partner_id` because the partner-write API is multi-tenant
    /// and segments writes by partner.
    fn allocate_did(
        &self,
        token: &AccessToken,
        partner_id: &str,
    ) -> impl Future<Output = Result<Allocation, RegistryError>> + Send;

    /// PUTs a signed DIDLog entry to the SWIYU partner-write API for
    /// the DID identified by `(partner_id, identifier)`. Keyed by
    /// partner-id + identifier rather than by DID because the
    /// partner-write API is the host that authorises writes.
    fn publish_log_entry(
        &self,
        token: &AccessToken,
        partner_id: &str,
        identifier: &str,
        entry: &str,
    ) -> impl Future<Output = Result<(), RegistryError>> + Send;

    /// Fetches and parses the current DIDLog tail for `did`. Keyed by
    /// DID rather than by partner-id + identifier because the public
    /// resolver lives at the URL the DID itself encodes (see
    /// [`DID::log_url`]) — on SWIYU integration that is a different
    /// host from the partner-write API. The JSONL body is parsed into
    /// typed entries on the way out; a malformed body becomes
    /// [`RegistryError::Decode`] (non-retryable), so callers do not
    /// see raw text.
    fn fetch_log(
        &self,
        did: &DID,
    ) -> impl Future<Output = Result<FetchedLog, RegistryError>> + Send;
}

impl RegistryFacade for IdentifierRegistryClient {
    fn allocate_did(
        &self,
        token: &AccessToken,
        partner_id: &str,
    ) -> impl Future<Output = Result<Allocation, RegistryError>> + Send {
        IdentifierRegistryClient::allocate_did(self, token, partner_id)
    }

    fn publish_log_entry(
        &self,
        token: &AccessToken,
        partner_id: &str,
        identifier: &str,
        entry: &str,
    ) -> impl Future<Output = Result<(), RegistryError>> + Send {
        IdentifierRegistryClient::publish_log_entry(self, token, partner_id, identifier, entry)
    }

    async fn fetch_log(&self, did: &DID) -> Result<FetchedLog, RegistryError> {
        let raw = IdentifierRegistryClient::fetch_log(self, did).await?;
        let entries = DIDLog::try_from_jsonl(&raw)
            .map(DIDLog::into_entries)
            .map_err(|e| RegistryError::Decode(format!("DIDLog parse: {e}")))?;
        Ok(FetchedLog { raw, entries })
    }
}

/// Lets tests share a `RegistryFacade` impl between the worker
/// (which takes ownership) and the test body (which inspects mock
/// invocations after the run). All methods auto-deref through the
/// `Arc` to the inner value.
impl<T: RegistryFacade + ?Sized> RegistryFacade for Arc<T> {
    fn allocate_did(
        &self,
        token: &AccessToken,
        partner_id: &str,
    ) -> impl Future<Output = Result<Allocation, RegistryError>> + Send {
        T::allocate_did(self, token, partner_id)
    }

    fn publish_log_entry(
        &self,
        token: &AccessToken,
        partner_id: &str,
        identifier: &str,
        entry: &str,
    ) -> impl Future<Output = Result<(), RegistryError>> + Send {
        T::publish_log_entry(self, token, partner_id, identifier, entry)
    }

    fn fetch_log(
        &self,
        did: &DID,
    ) -> impl Future<Output = Result<FetchedLog, RegistryError>> + Send {
        T::fetch_log(self, did)
    }
}

/// SWIYU Status Registry operations the worker drives across
/// [`CreateIssuer`] (allocate the issuer's first registry-side entry)
/// and the status-list publish loop (PUT signed status-list JWTs).
/// Mirrors [`RegistryFacade`] so callers in
/// [`crate::worker::create_issuer`] and
/// [`crate::worker::status_list_publisher`] can be unit-tested
/// against an in-memory mock without pulling wiremock into scope.
///
/// [`CreateIssuer`]: crate::domain::TaskType::CreateIssuer
pub trait StatusRegistryFacade: Send + Sync {
    fn create_status_list_entry(
        &self,
        token: &AccessToken,
        partner_id: &str,
    ) -> impl Future<Output = Result<StatusListEntry, RegistryError>> + Send;

    fn update_status_list_entry(
        &self,
        token: &AccessToken,
        partner_id: &str,
        entry_id: &str,
        status_list_jwt: &str,
    ) -> impl Future<Output = Result<(), RegistryError>> + Send;
}

impl StatusRegistryFacade for StatusRegistryClient {
    fn create_status_list_entry(
        &self,
        token: &AccessToken,
        partner_id: &str,
    ) -> impl Future<Output = Result<StatusListEntry, RegistryError>> + Send {
        StatusRegistryClient::create_status_list_entry(self, token, partner_id)
    }

    fn update_status_list_entry(
        &self,
        token: &AccessToken,
        partner_id: &str,
        entry_id: &str,
        status_list_jwt: &str,
    ) -> impl Future<Output = Result<(), RegistryError>> + Send {
        StatusRegistryClient::update_status_list_entry(
            self,
            token,
            partner_id,
            entry_id,
            status_list_jwt,
        )
    }
}

impl<T: StatusRegistryFacade + ?Sized> StatusRegistryFacade for Arc<T> {
    fn create_status_list_entry(
        &self,
        token: &AccessToken,
        partner_id: &str,
    ) -> impl Future<Output = Result<StatusListEntry, RegistryError>> + Send {
        T::create_status_list_entry(self, token, partner_id)
    }

    fn update_status_list_entry(
        &self,
        token: &AccessToken,
        partner_id: &str,
        entry_id: &str,
        status_list_jwt: &str,
    ) -> impl Future<Output = Result<(), RegistryError>> + Send {
        T::update_status_list_entry(self, token, partner_id, entry_id, status_list_jwt)
    }
}

// -----------------------------------------------------------------------------
// One-shot 401-retry wrappers for the protected registry calls.
//
// Each function pairs a `TokenProvider` with one `RegistryFacade` or
// `StatusRegistryFacade` method: it fetches a token, performs the
// call, retries once on `401 Unauthorized` after
// `provider.invalidate()`, and otherwise propagates the error.
//
// Why a per-method wrapper rather than a generic
// `with_refreshed_token(closure)` helper: stable Rust's `AsyncFn` does
// not propagate `Send` via HRTB through closures, which trips
// `tokio::spawn(worker.run(...))` at the binary site. A `BoxFuture`
// HRTB closure works for production but its trait-object lifetime
// coerces to `'static`, breaking unit tests that capture stack
// locals. Plain `async fn` with concrete arguments side-steps the
// whole closure-typing problem and is Send-clean for free.
// -----------------------------------------------------------------------------

/// Runs `op` with a freshly fetched access token, retrying once on
/// 401 after `provider.invalidate()`. Inlined for use by the
/// per-method wrappers below.
macro_rules! retry_on_401 {
    ($provider:expr, $token:ident, $call:expr) => {{
        let $token = $provider.get().await?;
        match $call.await {
            Ok(value) => Ok(value),
            Err(RegistryError::HttpStatus { status: 401, .. }) => {
                let $token = $provider.invalidate().await?;
                $call.await.map_err(Into::into)
            }
            Err(other) => Err(other.into()),
        }
    }};
}

/// Calls [`RegistryFacade::allocate_did`] with a fresh access token,
/// retrying once on `401 Unauthorized` after
/// [`TokenProvider::invalidate`].
///
/// # Parameters
/// - `provider`: per-tenant [`TokenProvider`] whose
///   [`get`](TokenProvider::get) / [`invalidate`](TokenProvider::invalidate)
///   bracket the registry call.
/// - `registry`: identifier-registry client. Borrowed; not consumed.
/// - `partner_id`: SWIYU partner UUID embedded in the registry URL —
///   the tenant's `partner_id` column, not a global value.
pub async fn allocate_did_with_refresh<P, R>(
    provider: &P,
    registry: &R,
    partner_id: &str,
) -> Result<Allocation, TokenAwareError>
where
    P: TokenProvider + ?Sized,
    R: RegistryFacade + ?Sized,
{
    retry_on_401!(provider, token, registry.allocate_did(&token, partner_id))
}

/// Calls [`RegistryFacade::publish_log_entry`] with a fresh access
/// token, retrying once on `401 Unauthorized` after
/// [`TokenProvider::invalidate`].
///
/// # Parameters
/// - `provider`: per-tenant [`TokenProvider`] whose
///   [`get`](TokenProvider::get) / [`invalidate`](TokenProvider::invalidate)
///   bracket the registry call.
/// - `registry`: identifier-registry client. Borrowed; not consumed.
/// - `partner_id`: SWIYU partner UUID — the tenant's `partner_id`
///   column.
/// - `identifier`: registry-assigned UUID for the DID being updated;
///   the trailing path segment of the issuer's `did:tdw` identifier.
/// - `entry`: serialised DIDLog payload to PUT. For create the single
///   genesis entry; for rotate / deactivate the prior entries followed
///   by the new one (the SWIYU PUT replaces the whole log).
pub async fn publish_log_entry_with_refresh<P, R>(
    provider: &P,
    registry: &R,
    partner_id: &str,
    identifier: &str,
    entry: &str,
) -> Result<(), TokenAwareError>
where
    P: TokenProvider + ?Sized,
    R: RegistryFacade + ?Sized,
{
    retry_on_401!(
        provider,
        token,
        registry.publish_log_entry(&token, partner_id, identifier, entry)
    )
}

/// Calls [`StatusRegistryFacade::create_status_list_entry`] with a
/// fresh access token, retrying once on `401 Unauthorized` after
/// [`TokenProvider::invalidate`].
///
/// # Parameters
/// - `provider`: per-tenant [`TokenProvider`] whose
///   [`get`](TokenProvider::get) / [`invalidate`](TokenProvider::invalidate)
///   bracket the registry call.
/// - `status_registry`: status-registry client. Borrowed; not
///   consumed.
/// - `partner_id`: SWIYU partner UUID — the tenant's `partner_id`
///   column.
pub async fn create_status_list_entry_with_refresh<P, C>(
    provider: &P,
    status_registry: &C,
    partner_id: &str,
) -> Result<StatusListEntry, TokenAwareError>
where
    P: TokenProvider + ?Sized,
    C: StatusRegistryFacade + ?Sized,
{
    retry_on_401!(
        provider,
        token,
        status_registry.create_status_list_entry(&token, partner_id)
    )
}

/// Calls [`StatusRegistryFacade::update_status_list_entry`] with a
/// fresh access token, retrying once on `401 Unauthorized` after
/// [`TokenProvider::invalidate`].
///
/// # Parameters
/// - `provider`: per-tenant [`TokenProvider`] whose
///   [`get`](TokenProvider::get) / [`invalidate`](TokenProvider::invalidate)
///   bracket the registry call.
/// - `status_registry`: status-registry client. Borrowed; not
///   consumed.
/// - `partner_id`: SWIYU partner UUID — the tenant's `partner_id`
///   column.
/// - `entry_id`: registry-assigned UUID of the status-list entry to
///   replace; the value [`create_status_list_entry_with_refresh`]
///   returned when the entry was first allocated.
/// - `status_list_jwt`: signed `application/statuslist+jwt` payload
///   that becomes the new entry contents.
pub async fn update_status_list_entry_with_refresh<P, C>(
    provider: &P,
    status_registry: &C,
    partner_id: &str,
    entry_id: &str,
    status_list_jwt: &str,
) -> Result<(), TokenAwareError>
where
    P: TokenProvider + ?Sized,
    C: StatusRegistryFacade + ?Sized,
{
    retry_on_401!(
        provider,
        token,
        status_registry.update_status_list_entry(&token, partner_id, entry_id, status_list_jwt)
    )
}

#[cfg(test)]
mod with_refresh_tests {
    use super::*;

    use std::sync::Mutex;

    use crate::domain::oauth2::TokenProviderError;
    use crate::worker::test_support::{AllocateCall, MockRegistry};

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

    fn allocation() -> Allocation {
        Allocation {
            url: "https://reg.example/api/v1/did/abc/did.jsonl".into(),
            identifier: "abc".into(),
        }
    }

    fn http_401() -> AllocateCall {
        AllocateCall::HttpStatus {
            status: 401,
            body: "expired".into(),
        }
    }

    fn http_500() -> AllocateCall {
        AllocateCall::HttpStatus {
            status: 500,
            body: "boom".into(),
        }
    }

    fn allocate_invocations(registry: &MockRegistry) -> usize {
        registry.allocate_invocations.lock().unwrap().len()
    }

    #[tokio::test]
    async fn success_on_first_try_calls_op_once_and_no_invalidate() {
        let provider = MockTokenProvider::new();
        let registry = MockRegistry::new();
        registry.enqueue_allocate(AllocateCall::Ok(allocation()));

        let result = allocate_did_with_refresh(&provider, &registry, "p").await;

        assert!(result.is_ok());
        assert_eq!(provider.calls(), vec!["get"]);
        assert_eq!(allocate_invocations(&registry), 1);
    }

    #[tokio::test]
    async fn first_call_401_then_success_after_invalidate() {
        let provider = MockTokenProvider::new();
        let registry = MockRegistry::new();
        registry.enqueue_allocate(http_401());
        registry.enqueue_allocate(AllocateCall::Ok(allocation()));

        let result = allocate_did_with_refresh(&provider, &registry, "p").await;

        assert!(result.is_ok());
        assert_eq!(provider.calls(), vec!["get", "invalidate"]);
        assert_eq!(allocate_invocations(&registry), 2);
    }

    #[tokio::test]
    async fn second_401_is_terminal() {
        let provider = MockTokenProvider::new();
        let registry = MockRegistry::new();
        registry.enqueue_allocate(http_401());
        registry.enqueue_allocate(http_401());

        let result = allocate_did_with_refresh(&provider, &registry, "p").await;

        match result {
            Err(TokenAwareError::Registry(RegistryError::HttpStatus { status: 401, .. })) => {}
            other => panic!("expected Registry(401), got {other:?}"),
        }
        assert_eq!(provider.calls(), vec!["get", "invalidate"]);
        assert_eq!(allocate_invocations(&registry), 2);
    }

    #[tokio::test]
    async fn non_401_registry_error_is_not_retried() {
        let provider = MockTokenProvider::new();
        let registry = MockRegistry::new();
        registry.enqueue_allocate(http_500());

        let result = allocate_did_with_refresh(&provider, &registry, "p").await;

        match result {
            Err(TokenAwareError::Registry(RegistryError::HttpStatus { status: 500, .. })) => {}
            other => panic!("expected Registry(500), got {other:?}"),
        }
        assert_eq!(provider.calls(), vec!["get"]);
        assert_eq!(allocate_invocations(&registry), 1);
    }

    #[tokio::test]
    async fn token_error_propagates_without_calling_op() {
        let provider = MockTokenProvider::with_get_failure();
        let registry = MockRegistry::new();

        let result = allocate_did_with_refresh(&provider, &registry, "p").await;

        match result {
            Err(TokenAwareError::Token(TokenProviderError::Transport(_))) => {}
            other => panic!("expected Token(Transport), got {other:?}"),
        }
        assert_eq!(provider.calls(), vec!["get"]);
        assert_eq!(allocate_invocations(&registry), 0);
    }
}
