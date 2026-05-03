# Implementation: Identifier Registry Client

This document specifies the async HTTP client for the SWIYU Identifier Registry, exposed by the `swiyu-registries` crate behind the `identifier` feature as `swiyu_registries::identifier::IdentifierRegistryClient`. The blocking equivalent in `swiyu-didtool/src/swiyu.rs` is the reference for endpoint shapes and response parsing; this client is the async, library-grade replacement intended for use from `swiyu-issuer` (and, later, the verifier service and an async-migrated `swiyu-didtool`).

The crate is a thin wrapper over `reqwest`: it exists so callers do not each re-implement bearer auth, retry classification, and response decoding against the same registry. Domain types (DIDs, DIDLog entries) continue to live in `swiyu-core`; this crate only deals with HTTP-level shapes.

## Async runtime

The client is async-only. All operations are `async fn` returning futures; there is no blocking variant and none is planned in this crate. `swiyu-didtool` retains its existing blocking `reqwest::blocking::Client` for the CLI use case — the two clients coexist and share no runtime. Migrating the CLI to async is an explicit non-goal of this slice (and is called out as a separate later piece of work in [`../../swiyu-issuer/specs/impl-issuer.md`](../../swiyu-issuer/specs/impl-issuer.md#registry-interaction)).

Concrete consequences:

- The crate depends on async `reqwest` only (`Cargo.toml` already pulls `reqwest` without the `blocking` feature). No `block_on`, no `tokio::task::spawn_blocking`, no blocking I/O on the request path.
- `reqwest::Client` is internally `Arc`-shared and `Clone`. `IdentifierRegistryClient` therefore takes `&self` on every method, and a single instance can be cloned (or borrowed across tokio tasks) to serve a worker pool without further wrapping in `Arc<Mutex<…>>`.
- The crate is runtime-tied to tokio because that is what `reqwest`'s async path requires; this matches the runtime already used by every consumer (`swiyu-issuer`, future verifier service). Other runtimes (`async-std`, `smol`) are not supported.
- Operations are not internally retried, so the request future is straightforwardly cancellation-safe: dropping it cancels the in-flight HTTP request. Callers that need at-least-once semantics across cancels persist the operation outcome themselves (this is exactly what the `swiyu-issuer` worker does via `state_data`).
- `allocate_did` is non-idempotent at the registry: a `POST` that succeeds but whose response is dropped (cancellation, transport error after server-side commit) leaves an allocated identifier the caller does not know about. The client does not paper over this; the worker handles it by checking `state_data.assigned_did` before re-issuing the call. `publish_log_entry` and `fetch_log` are idempotent (PUT and GET respectively) and safe to retry as long as the same entry bytes are re-sent.
- Tests use `#[tokio::test]` and the async API of `wiremock` (`MockServer::start().await`), exercising the same async code paths as production.

## Module layout

Code added by this slice:

- `swiyu-registries/src/identifier/mod.rs` — `IdentifierRegistryClient` struct, `new`/`with_http` constructors, accessors. Re-exports the operation modules.
- `swiyu-registries/src/identifier/allocate.rs` — `allocate_did` operation, request/response types.
- `swiyu-registries/src/identifier/publish.rs` — `publish_log_entry` operation, request/response types.
- `swiyu-registries/src/identifier/fetch.rs` — `fetch_log` operation, response type. Out of scope for v1 in `swiyu-issuer`, but added in this crate so verifier-side flows can pick it up without a second pass over the module layout.
- `swiyu-registries/src/common/error.rs` — already contains `RegistryError`; extended with one variant if a registry-specific failure mode emerges (none required by the v1 endpoints).
- `swiyu-registries/src/common/auth.rs` — `AccessToken` newtype that wraps the bearer token in `zeroize::Zeroizing` so it does not leak into logs or panics. Constructed from a `String` by the caller (typically from an env var read in the binary's startup path).

The crate stays env-agnostic: no `std::env::var` calls inside `swiyu-registries`. Consumers (e.g. the `issuer-mgmt` binary) read `SWIYU_REGISTRY_URL`, `SWIYU_PARTNER_ID`, and `SWIYU_ACCESS_TOKEN` themselves and pass them as constructor arguments. This matches the contract already documented in [`../../swiyu-issuer/specs/impl-issuer.md`](../../swiyu-issuer/specs/impl-issuer.md#configuration).

## Client surface

```rust
pub struct IdentifierRegistryClient {
    base_url: String,
    access_token: AccessToken,
    http: reqwest::Client,
}

impl IdentifierRegistryClient {
    pub fn new(base_url: String, access_token: AccessToken) -> Result<Self, RegistryError>;
    pub fn with_http(base_url: String, access_token: AccessToken, http: reqwest::Client) -> Self;

    pub async fn allocate_did(&self, partner_id: &str) -> Result<Allocation, RegistryError>;
    pub async fn publish_log_entry(&self, partner_id: &str, identifier: &str, entry: &str) -> Result<(), RegistryError>;
    pub async fn fetch_log(&self, identifier: &str) -> Result<String, RegistryError>;
}
```

`new` builds a default `reqwest::Client` with a sensible request timeout (`30s`) and HTTPS-only redirect policy. `with_http` lets the caller inject a pre-configured client — used by tests (against a local mock server) and by callers that want to share a client/connection pool across registries.

Methods take `&self` so the client is cheaply shareable; `reqwest::Client` is itself `Clone` and internally `Arc`-ed, so a single `IdentifierRegistryClient` can serve a worker pool without further wrapping.

`partner_id` is a per-call argument rather than a constructor field. The first consumer (`swiyu-issuer`) pins one partner per process today, but a verifier service may eventually talk to the registry on behalf of multiple partners; threading it through call sites costs nothing and avoids rebuilding the client to switch tenants.

### `Allocation`

```rust
pub struct Allocation {
    pub url: String,
    pub identifier: String,
}
```

`url` is the registry-published URL where the DIDLog will be served (e.g. `https://identifier-reg.swiyu.admin.ch/api/v1/did/<UUID>` or with a `/did.jsonl` suffix). `identifier` is the UUID extracted from that URL — used as the path segment in subsequent `publish_log_entry` and `fetch_log` calls. The extraction logic mirrors `swiyu-didtool/src/swiyu.rs::extract_identifier`: strip a trailing `/did.jsonl` if present, trim trailing `/`, take the last non-empty path segment.

### `AccessToken`

```rust
pub struct AccessToken(zeroize::Zeroizing<String>);

impl AccessToken {
    pub fn new(token: String) -> Self;
    pub(crate) fn as_str(&self) -> &str;
}
```

`Debug` is implemented to print `AccessToken(***)` rather than the raw token. `as_str` is crate-private so the token only leaves the crate via the `Authorization` header that `reqwest` builds.

## Endpoint mapping

| Operation | Method | Path | Auth | Body | Response |
| --- | --- | --- | --- | --- | --- |
| `allocate_did` | `POST` | `/api/v1/identifier/business-entities/{partner_id}/identifier-entries` | Bearer | (none) | `{ "identifierRegistryUrl": "<url>" }` |
| `publish_log_entry` | `PUT` | `/api/v1/identifier/business-entities/{partner_id}/identifier-entries/{identifier}` | Bearer | DIDLog entry, one JSON line, no trailing newline, `Content-Type: application/jsonl+json` | (empty body, status 2xx) |
| `fetch_log` | `GET` | `/api/v1/did/{identifier}/did.jsonl` | (none) | (none) | DIDLog body as `text/plain`/`application/jsonl+json` |

`base_url` is concatenated as `{base_url.trim_end_matches('/')}/{path}`. Trailing slashes on the configured base URL are tolerated (matching `swiyu-didtool` behaviour) so operators do not have to remember a normalisation rule.

`fetch_log` uses an unauthenticated public path; it does not send the bearer token. The other two operations always send `Authorization: Bearer <token>`.

The registry's response for `allocate_did` is parsed by reading the JSON field `identifierRegistryUrl`. If the field is missing or non-string, the call returns `RegistryError::Decode`. Other fields in the response are ignored — they may be added by the registry in the future without breaking this client.

## Authentication

The bearer token is supplied at construction and reused for every authenticated request. v1 assumes a static, long-lived token (the SWIYU integration registry issues one per partner). Token rotation, OAuth2 client-credentials refresh, and per-request token override are out of scope; if needed they land as a follow-up that takes a `Fn() -> AccessToken` provider instead of a stored token.

A 401 from the registry surfaces as `RegistryError::HttpStatus { status: 401, body }`. `is_retryable()` returns `false` for it: a stale token is a configuration problem and retrying will not help. Callers (the worker) classify it as terminal.

## Error handling

All operations return `Result<T, RegistryError>` using the existing `swiyu_registries::common::RegistryError` enum (`Transport`, `HttpStatus { status, body }`, `Decode`). No new variants are added by this slice.

Mapping rules:

- `reqwest::Error` from `send()` → `RegistryError::Transport`.
- Non-2xx status → `RegistryError::HttpStatus { status, body }`. The body is read into a `String` (best-effort; if reading the body fails, the body is set to `""` and the status is still surfaced).
- JSON decode failure on a 2xx response → `RegistryError::Decode(message)` where `message` describes which field was missing or malformed (e.g. `"missing identifierRegistryUrl"`, `"identifierRegistryUrl is not a string"`).
- Identifier-extraction failure on the allocation response → `RegistryError::Decode("cannot extract identifier from identifierRegistryUrl '<url>'")`.

Retry classification stays in `RegistryError::is_retryable` and is consumed by callers; the client itself does not retry. Centralising backoff in the worker keeps the client deterministic and one-call-per-method, which is much easier to test.

## Observability

Each operation emits a single `tracing` span at `debug` level with fields: `op` (`"allocate_did"` / `"publish_log_entry"` / `"fetch_log"`), `partner_id`, `identifier` (when applicable), `status` (set on response), `attempt` is **not** recorded — retries belong to the caller, not the client.

Request/response bodies are not logged at `debug`. Error bodies (the `body` field of `HttpStatus`) are only included in the span when the response is non-2xx, and even then are truncated to 4 KiB to keep logs bounded if the registry returns a verbose HTML error page.

The bearer token is never logged; the `AccessToken` `Debug` impl masks it, and the `Authorization` header is constructed by `reqwest` after our span fields are recorded.

## Configuration defaults

The default `reqwest::Client` built by `IdentifierRegistryClient::new`:

- request timeout: `30s` (covers transport + server-side handling; the registry typically responds well under a second).
- connect timeout: `10s`.
- TLS: rustls with webpki-roots (already pinned in `Cargo.toml`).
- HTTPS-only: `https_only(true)` so a misconfigured `http://` base URL fails fast rather than silently downgrading.
- User agent: `swiyu-registries/<crate version>`.

Operators that need different timeouts pass a custom client to `with_http`.

## Tests

Two layers:

- **Unit tests** in each operation module, exercising request construction (URL, method, headers, body) and response parsing (success path, missing field, malformed UUID, 4xx body propagation, 5xx classification). The HTTP layer is stubbed with [`wiremock`](https://crates.io/crates/wiremock) — chosen over hand-rolled `hyper` test servers because the assertion DSL keeps the tests readable and it is already a low-cost dev-dependency in the Rust ecosystem.
- **Integration tests** in `swiyu-registries/tests/identifier.rs`, driving a `wiremock` server through the public `IdentifierRegistryClient` API for each of the three operations end-to-end. These do not need network access and run as part of `cargo test` with no extra setup.

End-to-end validation against the real SWIYU integration registry is performed manually via `swiyu-didtool` until the issuer-management slice exercises the async client in its own integration tests with a stubbed registry.

## Out of scope for v1

- **Retries / backoff** inside the client. Caller-driven only.
- **Token refresh.** Static bearer token at construction.
- **Connection pool sharing across registries** beyond what `with_http` enables. A workspace-level `RegistryClient` factory may emerge once the status and trust registries are implemented.
- **Streaming `fetch_log`.** The DIDLog body is read into a `String` in full; logs are kilobytes-scale and a streaming API adds complexity without a current consumer.
- **Pagination / list endpoints.** None of the v1 operations are paginated.
