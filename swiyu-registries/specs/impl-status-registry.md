# Implementation: Status Registry Client

This document specifies the async HTTP client for the SWIYU Status Registry, exposed by the `swiyu-registries` crate behind the `status` feature as `swiyu_registries::status::StatusRegistryClient`. The reference for endpoint shapes is the OpenAPI spec the Java issuer ships at `issuer-service/specs/SWIYU_Core_Business_status.yaml` (title `SWIYU Service API`, tagged `Status Business API`); the Rust client mirrors what `ch.admin.bj.swiyu.issuer.service.statusregistry.StatusRegistryClient` does today.

The crate is a thin wrapper over `reqwest`: it exists so callers do not each re-implement bearer auth, retry classification, and response decoding against the same registry. Domain types — the SD-JWT VC status pointer, the bitstring decoder for `SwissTokenStatusList-1.0` — already live in `swiyu-core::statuslist`; this crate only deals with HTTP-level shapes.

## Async runtime

Same constraints as the identifier client (see [`impl-identifier-registry.md`](impl-identifier-registry.md#async-runtime)): async-only on tokio, `&self` methods, no internal retries, no `block_on`. The crate stays runtime-agnostic at the source level beyond requiring `reqwest`'s async path.

## Module layout

Code added by this slice:

- `swiyu-registries/src/status/mod.rs` — `StatusRegistryClient` struct, `new` / `with_http` constructors, accessors. Re-exports the operation modules.
- `swiyu-registries/src/status/create.rs` — `create_status_list_entry` operation and `StatusListEntry` response type.
- `swiyu-registries/src/status/update.rs` — `update_status_list_entry` operation.
- `swiyu-registries/src/status/list.rs` — `list_status_list_entries` operation, `ListParams` request type, and `StatusListEntriesPage` / `StatusListEntrySummary` response types.

The `status` feature gates the entire `status` module from `lib.rs`. `RegistryError` and `AccessToken` are reused from `common/`; no new variants are needed.

## Client surface

```rust
pub struct StatusRegistryClient {
    base_url: String,
    http: reqwest::Client,
}

impl StatusRegistryClient {
    pub fn new(base_url: String) -> Result<Self, RegistryError>;
    pub fn with_http(base_url: String, http: reqwest::Client) -> Self;

    pub async fn create_status_list_entry(&self, token: &AccessToken, partner_id: &str) -> Result<StatusListEntry, RegistryError>;
    pub async fn update_status_list_entry(&self, token: &AccessToken, partner_id: &str, entry_id: &str, status_list_jwt: &str) -> Result<(), RegistryError>;
    pub async fn list_status_list_entries(&self, token: &AccessToken, partner_id: &str, params: ListParams) -> Result<StatusListEntriesPage, RegistryError>;
}
```

`token`, `partner_id` and `entry_id` are all per-call arguments rather than constructor fields, matching the identifier client. The client carries no tenant or auth state, so a single instance can serve every tenant in a multi-tenant process by being handed the right token at each call.

### `StatusListEntry`

```rust
pub struct StatusListEntry {
    pub id: String,
    pub registry_url: String,
}
```

`id` is the entry UUID returned by the registry as `id` in `StatusListEntryCreationDto`; it is used as the `entry_id` path segment in subsequent `update_status_list_entry` calls. `registry_url` is the public URL where the published status-list JWT will be served (e.g. `https://status-registry.admin.ch/api/v1/statuslist/<UUID>.jwt`) — a verifier dereferences this URL to fetch the JWT before decoding it via `swiyu_core::statuslist::StatusList`.

The id is kept as `String` rather than `uuid::Uuid` to avoid pulling in another dependency; the Rust client treats it as an opaque token whose only contract is round-tripping into the path of the next call. Same choice as `Allocation::identifier`.

### `ListParams`

```rust
pub struct ListParams {
    pub page: u32,           // zero-based, default 0
    pub size: u32,           // default 20
    pub sort: Vec<String>,   // each element "property,(asc|desc)"
}

impl Default for ListParams { ... } // page=0, size=20, sort=vec![]
```

Pagination follows Spring's conventions because the registry is a Spring service; the spec's defaults (page=0, size=20) are reproduced. `sort` is a free-form list because the spec leaves the property names open and verifying them client-side would just drift from the server.

### `StatusListEntriesPage` and `StatusListEntrySummary`

```rust
pub struct StatusListEntriesPage {
    pub entries: Vec<StatusListEntrySummary>,
    pub page: u32,
    pub size: u32,
    pub total_elements: u64,
    pub total_pages: u32,
}

pub struct StatusListEntrySummary {
    pub id: String,
    pub created_at: String,
    pub updated_at: String,
}
```

The Spring `Page<T>` envelope carries a dozen fields (`pageable`, `sort`, `first`, `last`, `empty`, `numberOfElements`, …); the Rust client surfaces only the five that callers actually use and drops the rest. `created_at` and `updated_at` are exposed as the raw RFC 3339 strings the registry returns — the client does not pull in `chrono` or `time`; consumers parse if they need a typed timestamp. This matches the convention in `swiyu-core` of leaving timestamp parsing to the consumer.

## Endpoint mapping

| Operation | Method | Path | Auth | Body | Response |
| --- | --- | --- | --- | --- | --- |
| `create_status_list_entry` | `POST` | `/api/v1/status/business-entities/{partner_id}/status-list-entries/` | Bearer | (none) | `StatusListEntryCreationDto` → `{ id, registry_url }` |
| `update_status_list_entry` | `PUT` | `/api/v1/status/business-entities/{partner_id}/status-list-entries/{entry_id}` | Bearer | the status-list JWT verbatim, `Content-Type: application/statuslist+jwt` | (empty body, status 2xx) |
| `list_status_list_entries` | `GET` | `/api/v1/status/business-entities/{partner_id}/status-list-entries/` | Bearer | (none); query params `page`, `size`, `sort` | `PageStatusListEntryDto` → `StatusListEntriesPage` |

`base_url` is concatenated as `{base_url.trim_end_matches('/')}/{path}`. Trailing slashes on the configured base URL are tolerated, matching the identifier client.

The path keeps the trailing slash on `status-list-entries/` exactly as the OpenAPI defines it — the registry rejects the bare form on some routes (the Java client also keeps it).

`update_status_list_entry` sends the JWT as the request body bytes (UTF-8) without any wrapping JSON envelope; that is what `application/statuslist+jwt` mandates and what the Java `StatusBusinessApiApi.updateStatusListEntry(... String)` does.

## Authentication

All three operations send `Authorization: Bearer <token>` from the [`AccessToken`](../src/common/auth.rs) supplied per call by the caller. Unlike the identifier registry's `fetch_log`, there is no public unauthenticated path on this API. The verifier-side dereference of the published `registry_url` is a separate concern handled by the consumer — it is just an HTTPS GET of a public URL and does not belong on this client. Acquisition and refresh of the bearer token is owned by `swiyu-issuer`; see [`../../swiyu-issuer/specs/aspect-oauth2.md`](../../swiyu-issuer/specs/aspect-oauth2.md).

A 401 from the registry surfaces as `RegistryError::HttpStatus { status: 401, body }` and `is_retryable()` returns `false`: a stale or wrong token is a configuration problem and retrying will not help. A 403 means the token is valid but cannot act on the requested partner / entry; same treatment. A 404 on `update` means the entry does not exist (or does not belong to this partner), also non-retryable. 429 and 5xx are retryable per the existing `is_retryable` rules.

## Error handling

Same enum, same mapping rules as the identifier client:

- `reqwest::Error` from `send()` → `RegistryError::Transport`.
- Non-2xx → `RegistryError::HttpStatus { status, body }`. Body read best-effort.
- JSON decode failure on a 2xx response → `RegistryError::Decode(message)` naming the missing/invalid field (`"missing id"`, `"missing statusRegistryUrl"`, `"id is not a string"`, etc.).
- For the `list` operation, a missing `content` array, or any pagination field with the wrong JSON type, also produces `RegistryError::Decode`. Unknown extra fields are ignored — the registry is free to add more without breaking this client.

The client never retries internally; classification stays in `RegistryError::is_retryable`.

## Idempotency

- `create_status_list_entry` is **not idempotent**: every successful POST mints a new entry. If the response is lost (cancellation, transport failure after server commit), the entry exists at the registry but the caller never learns its `id`. Callers that need at-least-once must persist their intent before the call and check it before retrying, the same pattern the identifier worker uses for `allocate_did`.
- `update_status_list_entry` is idempotent at the registry: re-sending the same JWT bytes for the same `entry_id` is safe and is the expected retry pattern for a worker.
- `list_status_list_entries` is read-only and trivially idempotent.

## Observability

Each operation emits a single `tracing` span at `debug` level with the operation name, `partner_id`, `entry_id` (when applicable), and `status` (set on response). Request and response bodies are not logged; the JWT in particular is treated as opaque sensitive material. The bearer token is masked by `AccessToken`'s `Debug` impl and never appears in span fields.

## Configuration defaults

`StatusRegistryClient::new` builds a default `reqwest::Client` with the same hardened settings as the identifier client: 30 s request timeout, 10 s connect timeout, HTTPS-only, rustls + webpki-roots, user agent `swiyu-registries/<crate version>`. Operators with different requirements pass a custom client to `with_http`.

## Tests

Two layers, mirroring the identifier client:

- **Unit tests** in each operation module exercising request construction (URL, method, headers, body, query string) and response parsing (success path, missing field, malformed JSON, 4xx body propagation, 5xx classification). HTTP layer stubbed with `wiremock`.
- **Integration tests** in `swiyu-registries/tests/status.rs` driving the public `StatusRegistryClient` API against a `wiremock` server end-to-end for each of the three operations.

End-to-end validation against the real SWIYU integration registry is performed manually until the issuer-management slice exercises the async client in its own integration tests with a stubbed registry.

## Out of scope for v1

- **Retries / backoff** inside the client. Caller-driven only.
- **Token refresh.** Static bearer token at construction; the Java code already runs an OAuth2 client-credentials refresh in `StatusRegistryTokenService` but that belongs to the consumer, not this crate.
- **Status-list size guard** equivalent to the Java `StatusRegistryContentLengthInterceptor`. That interceptor protects the verifier-side dereference of a published status list; this crate only handles the partner-write API where bodies are JWTs the caller produced and whose size the caller already controls.
- **Streaming or chunked uploads.** Status-list JWTs are a few kilobytes; reading them as `&str` is fine.
- **Typed timestamps** on `StatusListEntrySummary`. Raw RFC 3339 strings; consumers parse if needed.
- **`Sort` envelope round-tripping.** The `sort` query param is sent; the response's `sort` object is dropped because no consumer reads it back.
