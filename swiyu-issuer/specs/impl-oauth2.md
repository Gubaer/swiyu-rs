# Implementation: OAuth2 token lifecycle

This document describes how the OAuth2 aspect (see [`aspect-oauth2.md`](aspect-oauth2.md)) is realised inside `swiyu-issuer`. It is a sibling of [`impl-key-management.md`](impl-key-management.md) and follows the same conventions: a domain-layer trait abstraction, a runtime-selected dispatch enum, and concrete backends.

The protocol-side picture (token endpoint, grant types, the four ePortal credentials, the empirical TTLs) lives in [`swiyu-registries/specs/aspect-oauth2.md`](../../swiyu-registries/specs/aspect-oauth2.md). This document is strictly about how `swiyu-issuer` implements the partner side.

## Module location

```
swiyu-issuer/src/domain/oauth2/
    mod.rs              — TokenProvider trait, AnyTokenProvider, errors, re-exports
    refresh_token.rs    — RefreshToken newtype (zeroizing, masked Debug)
    cached_token.rs     — CachedToken in-memory state
    oauth2_provider.rs  — OAuth2TokenProvider (the real backend)
    static_provider.rs  — StaticTokenProvider (test-only)
    registry.rs         — ProviderRegistry (tenant_id → Arc<AnyTokenProvider>)
    with_refreshed.rs   — with_refreshed_token helper
```

Backend selection is process-wide: `AnyTokenProvider::OAuth2` is used in production; `AnyTokenProvider::Static` is an internal test fixture for executor unit tests that need a `TokenProvider` without exercising the OAuth2 flow. The selection is *per provider instance* rather than via a global env var, because real deployments hold one provider per tenant — all `OAuth2` — while tests instantiate `Static` directly. There is no `OAUTH2_BACKEND` env var.

## Supporting types

```rust
/// A SWIYU OAuth2 refresh token. Wraps the secret in zeroize::Zeroizing
/// so its memory is overwritten on drop, masks Debug to never leak the
/// value in logs/spans, and is Clone so a copy can be persisted while
/// the original is consumed by a refresh_token grant.
pub struct RefreshToken(zeroize::Zeroizing<String>);

impl RefreshToken {
    pub fn new(token: String) -> Self;
    pub(crate) fn as_str(&self) -> &str;
}
```

`AccessToken` is the existing newtype from `swiyu-registries::common::auth`; this crate does not redefine it.

```rust
/// Snapshot of one successful refresh_token grant, held in memory by an
/// OAuth2TokenProvider. The refresh token field reflects the rotated
/// value the realm returned, not the bootstrap value the operator
/// pasted into the tenant row.
struct CachedToken {
    access: AccessToken,
    refresh: RefreshToken,
    expires_at: chrono::DateTime<chrono::Utc>,
}
```

## Trait

```rust
pub trait TokenProvider: Send + Sync {
    fn get(
        &self,
    ) -> impl Future<Output = Result<AccessToken, TokenProviderError>> + Send;

    fn invalidate(
        &self,
    ) -> impl Future<Output = Result<AccessToken, TokenProviderError>> + Send;
}
```

Notes on the shape:

- **Native async-fn-in-trait** (Rust 2024). Same convention as `RegistryFacade` and `SigningEngine`: a trait whose method returns `impl Future`, consumed via generics, not `&dyn`. Multi-tenant runtime polymorphism is achieved through the `AnyTokenProvider` enum below — the same dispatch pattern used for `AnySigningEngine`.
- **`&self`.** Internal synchronisation lives inside each implementation (an in-memory cache plus a `tokio::sync::Mutex` for single-flight refresh in `OAuth2TokenProvider`; nothing for `StaticTokenProvider`).
- **`get` returns a clone.** The cached `AccessToken` is `Clone`; the trait clones the cached value into the caller. The cache holds the original.
- **`invalidate` returns a fresh access token.** The contract is "the cached access token, if any, is gone, and the caller now holds a freshly minted one". Implemented by `OAuth2TokenProvider` as "drop the cache, perform a grant, return the new token". For `StaticTokenProvider` it is a no-op that returns the same fixed token (`StaticTokenProvider` is for tests that do not exercise rotation).

## Errors

```rust
#[derive(Debug, thiserror::Error)]
pub enum TokenProviderError {
    /// Refresh token is no longer valid — typically because it expired
    /// (>7 days without a successful refresh) or was revoked at the
    /// authorization server. The caller cannot recover; the deployment
    /// requires a fresh renewal token to be pasted into the tenant row.
    #[error("refresh token rejected: {0}")]
    RefreshRejected(String),

    /// Token endpoint returned a non-2xx and non-4xx response, or the
    /// request itself failed. Retryable per the same rules as
    /// `swiyu_registries::common::RegistryError::is_retryable`.
    #[error("token endpoint transport: {0}")]
    Transport(String),

    /// The token endpoint replied with 2xx but the body was unparseable
    /// or missing required fields.
    #[error("token endpoint decode: {0}")]
    Decode(String),

    /// Tenant configuration is missing required fields (client_id,
    /// client_secret, refresh_token, or token_url) — the operator has
    /// not finished onboarding the tenant. Surfaces as Terminal in the
    /// worker.
    #[error("tenant missing oauth credentials: {0}")]
    MissingCredentials(String),

    /// Persistence layer error while reading or writing the tenant row.
    #[error(transparent)]
    Persistence(#[from] crate::persistence::PersistenceError),
}

impl TokenProviderError {
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Transport(_) | Self::Persistence(_))
    }
}
```

`MissingCredentials` and `RefreshRejected` are deliberately not retryable: both require human intervention via the ePortal and the tenant row.

## AnyTokenProvider

```rust
pub enum AnyTokenProvider {
    OAuth2(OAuth2TokenProvider),
    Static(StaticTokenProvider),
}

impl TokenProvider for AnyTokenProvider {
    fn get(&self) -> impl Future<Output = Result<AccessToken, TokenProviderError>> + Send {
        async move {
            match self {
                Self::OAuth2(p) => p.get().await,
                Self::Static(p) => p.get().await,
            }
        }
    }

    fn invalidate(&self) -> impl Future<...> + Send {
        // analogous
    }
}
```

The runtime holds providers as `Arc<AnyTokenProvider>`; the enum gives a stable concrete type for the registry map below.

## `OAuth2TokenProvider`

```rust
pub struct OAuth2TokenProvider {
    tenant_id: TenantId,
    pool: sqlx::PgPool,
    http: reqwest::Client,
    token_url: String,
    cached: tokio::sync::RwLock<Option<CachedToken>>,
    refresh_lock: tokio::sync::Mutex<()>,
    safety_margin: chrono::Duration,
}

impl OAuth2TokenProvider {
    pub fn new(
        tenant_id: TenantId,
        pool: sqlx::PgPool,
        http: reqwest::Client,
        token_url: String,
        safety_margin: chrono::Duration,
    ) -> Self;
}
```

### `get`

1. Read-lock `cached`. If `Some(token)` and `expires_at - now > safety_margin`, return a clone of `token.access` and unlock.
2. Drop the read lock; acquire `refresh_lock` (single-flight per provider).
3. Re-check `cached` under the read lock — another `get()` waiter may have just refreshed it. If valid, return.
4. Open a DB transaction:
   - `SELECT oauth_client_id, oauth_client_secret, oauth_refresh_token FROM tenants WHERE id = $1 FOR UPDATE`. The `FOR UPDATE` lock blocks any concurrent refresher on another replica.
   - `MissingCredentials` if any column is `NULL`.
   - Perform a `refresh_token` grant against `token_url` using the freshly-read refresh token. (Note: the DB-locked value may be newer than what we had cached if another replica refreshed earlier.)
   - On 4xx → `RefreshRejected`; on 5xx / network → `Transport`; on 2xx, parse `access_token`, `refresh_token`, `expires_in`.
   - `UPDATE tenants SET oauth_refresh_token = $new WHERE id = $1`.
   - Commit.
5. Compute `expires_at = now + expires_in`. Write-lock `cached` to `Some(CachedToken { … })`.
6. Drop `refresh_lock`. Return `cached.access.clone()`.

The transaction encompasses the network call to Keycloak. This is intentional: a 4xx response implies the held refresh token is dead, and we want the rollback to leave the row untouched so a manually-pasted recovery value (concurrently inserted by the operator) is not clobbered. The lock duration is bounded by the Keycloak round-trip latency (sub-second under healthy conditions); under pathological latency, the per-tenant row lock blocks at most one other replica's grant attempt.

### `invalidate`

1. Write-lock `cached`, set to `None`, drop the lock.
2. Call `self.get()` and return its result.

The two operations share the lock-and-grant body so any concurrency invariants apply uniformly.

### Refresh cadence

`OAuth2TokenProvider` does **not** run a scheduler internally. Pre-emptive refresh is driven by the worker / publisher loops that already poll on a tick: each call to `provider.get()` checks the cached expiry, and the safety margin (`expires_in × (1 - SWIYU_TOKEN_REFRESH_FRACTION)`, default 0.25 of the access-token TTL) ensures grants happen comfortably before expiry. There is no separate "refresh every N seconds" task because there is no work to do in the absence of registry calls; on a quiet deployment, an unused token simply ages out of cache and the next call refreshes it lazily.

This deliberately differs from a clock-driven scheduler: it keeps the design minimal and avoids a second tokio task per tenant. The seven-day refresh-token TTL is monitored externally (Prometheus alert on consecutive `RefreshRejected` errors); the runtime itself is reactive.

## `StaticTokenProvider`

```rust
pub struct StaticTokenProvider {
    token: AccessToken,
}

impl StaticTokenProvider {
    pub fn new(token: AccessToken) -> Self;
}

impl StaticTokenProvider {
    async fn get(&self) -> Result<AccessToken, TokenProviderError> {
        Ok(self.token.clone())
    }

    async fn invalidate(&self) -> Result<AccessToken, TokenProviderError> {
        Ok(self.token.clone())
    }
}
```

For executor unit tests that need a fixed token without exercising the OAuth2 flow. Internal to this crate; not exported for use by other crates.

## `ProviderRegistry`

```rust
pub struct ProviderRegistry {
    pool: sqlx::PgPool,
    http: reqwest::Client,
    token_url: String,
    safety_margin: chrono::Duration,
    providers: tokio::sync::RwLock<HashMap<TenantId, Arc<AnyTokenProvider>>>,
}

impl ProviderRegistry {
    pub fn new(
        pool: sqlx::PgPool,
        http: reqwest::Client,
        token_url: String,
        safety_margin: chrono::Duration,
    ) -> Self;

    /// Returns the provider for the given tenant, constructing it lazily
    /// on first use. The returned Arc is cheaply clonable and shared
    /// across all callers; provider state (in-memory cache, refresh
    /// lock) is shared per tenant within a single replica.
    pub async fn provider_for(
        &self,
        tenant_id: &TenantId,
    ) -> Arc<AnyTokenProvider>;
}
```

`provider_for` does double-checked lookup:

1. Read-lock the map; return `Arc::clone` if present.
2. Drop the read lock, write-lock, re-check, insert, return.

Construction is purely in-memory (no DB I/O); the actual OAuth2 grant happens lazily on the first `provider.get()`. There is no eviction on tenant-config change in v1; operators redeploy or restart the process when rotating credentials, which is consistent with `aspect-oauth2.md`'s operational considerations.

## `with_refreshed_token` helper

```rust
pub async fn with_refreshed_token<T, F, Fut>(
    provider: &impl TokenProvider,
    op: F,
) -> Result<T, TokenAwareError>
where
    F: Fn(&AccessToken) -> Fut,
    Fut: Future<Output = Result<T, swiyu_registries::common::RegistryError>>,
{
    let token = provider.get().await?;
    match op(&token).await {
        Ok(value) => Ok(value),
        Err(swiyu_registries::common::RegistryError::HttpStatus { status: 401, .. }) => {
            let token = provider.invalidate().await?;
            op(&token).await.map_err(Into::into)
        }
        Err(other) => Err(other.into()),
    }
}
```

`TokenAwareError` is a thin wrapper around `RegistryError | TokenProviderError`:

```rust
#[derive(Debug, thiserror::Error)]
pub enum TokenAwareError {
    #[error(transparent)]
    Registry(#[from] swiyu_registries::common::RegistryError),
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
```

The closure shape (`Fn(&AccessToken) -> Fut`) keeps each registry method's per-call argument list visible at the call site, while the wrapper centralises the 401-retry decision. Per-step executors call this directly:

```rust
let outcome = with_refreshed_token(&provider, |token| {
    registry.allocate_did(token, partner_id)
})
.await;
```

## Persistence

The `tenants` table carries three OAuth2 columns; in the consolidated `20260430_000001_init.sql` baseline they look like:

```sql
oauth_client_id     TEXT,
oauth_client_secret BYTEA,
oauth_refresh_token BYTEA
```

`oauth_client_id` is not a secret and stays TEXT. The two secret columns are BYTEA because they hold self-describing ciphertext blobs produced by the `SecretEncryptionEngine`; see [`impl-secret-management.md`](impl-secret-management.md) for the envelope format. All three are `NULL`-able because tenants that do not call SWIYU registries (today: none, but the option is preserved) do not need OAuth2 credentials. Workers requesting a token for such a tenant fail Terminal with `MissingCredentials`. `tenant create` does **not** write the OAuth2 columns; operators populate `oauth_client_id` and `oauth_client_secret` via the `tenant set-oauth-credentials` subcommand at onboarding (a one-off operation); the recurring operation — pasting a fresh renewal token from the ePortal after a >7-day cliff or credential rotation — is supported by the `tenant import-oauth-refresh-token` subcommand. The runtime updates `oauth_refresh_token` on every successful grant.

### OAuth2 operator subcommands

OAuth2 credentials land in tenant rows via two `swiyu-issuer-cli` subcommands. The CLI binary, the `tenant` subcommand namespace, and the general tenant-lifecycle commands (`create`, `update`) are described in [`impl-tenant-management.md`](impl-tenant-management.md); this section covers only the OAuth2-credential paths.

```
swiyu-issuer-cli tenant set-oauth-credentials       --tenant <bare-tenant-id> --client-id <id> --client-secret-stdin
swiyu-issuer-cli tenant import-oauth-refresh-token  --tenant <bare-tenant-id> --token <refresh-token>
```

`tenant set-oauth-credentials` writes `oauth_client_id` and `oauth_client_secret` for the named tenant. The two columns are written atomically; partial updates would leave the row unable to mint tokens. The client secret is read from stdin so it never lands in shell history.

`tenant import-oauth-refresh-token` connects to the database via `DATABASE_URL`, validates that the tenant exists, and writes `<refresh-token>` to `tenants.oauth_refresh_token`. Idempotent: re-running with the same token is a no-op as far as the runtime is concerned (the runtime would have rotated it on the next grant anyway). The `--token` value is read from a hidden CLI argument; for shell-history-safety, operators may prefer to pipe via env var or a heredoc — the implementation accepts both `--token <value>` and `--token-stdin` for the prompted form.

Both subcommands write directly to the database and perform no OAuth2 grant themselves. The token endpoint URL is *not* per-tenant — every tenant's credentials authenticate against the same SWIYU realm. It comes from the `SWIYU_TOKEN_URL` env var read by the `swiyu-issuer-mgmtapi` daemon at startup and threaded into `ProviderRegistry::new`; `swiyu-issuer-cli` does not consume it.

As part of this slice the pre-existing top-level `mint-token` subcommand on `swiyu-issuer-mgmtapi` is migrated verbatim (same DB connection logic, same secret-printing semantics, same exit codes) to `swiyu-issuer-cli tenant api-token mint` — API tokens are tenant-scoped, so the verb belongs under `tenant`. See [`impl_auth.md`](impl_auth.md) for the API-token side. After the migration, `swiyu-issuer-mgmtapi` is server-only and stops mixing the long-running daemon with one-shot operator commands.

### Encryption at rest

All three secret columns store **plaintext UTF-8** in the v1 schema, matching how `signing_engine_dev_keypairs.private_key` stores plaintext PEM in dev mode. Encryption-at-rest is a load-bearing follow-up handled in a separate spec; the column type stays `TEXT` and the migration to encrypted bytes lands with that work. The trade-off is explicit and called out in `aspect-oauth2.md`'s *Operational considerations*: production deployments should not run on this v1 storage unmodified.

### Persistence module

```
swiyu-issuer/src/persistence/tenants.rs   — extended with:
    fn read_oauth_credentials_for_update(...)       — SELECT … FOR UPDATE
    fn write_oauth_refresh_token(...)               — UPDATE oauth_refresh_token
```

Both functions take `&mut sqlx::Transaction<'_, Postgres>` rather than `&mut PgConnection` so the caller controls the transaction lifecycle; `OAuth2TokenProvider::get` opens the transaction, calls these, performs the network grant, and commits.

## Worker / Publisher integration

`Worker` and `StatusListPublisher` swap their static `AccessToken` field for a `ProviderRegistry`:

```rust
pub struct Worker<R, S, C> {
    pool: PgPool,
    registry: R,
    engine: S,
    status_registry: C,
    providers: Arc<ProviderRegistry>,   // was: access_token: AccessToken
    rng: Box<dyn RngCore + Send + Sync>,
    config: WorkerConfig,
}
```

In `runner.rs`, each `execute_*` step that previously took `&self.access_token` now resolves the per-tenant provider before dispatching:

```rust
let provider = self.providers.provider_for(&task.tenant_id).await;
let outcome = execute_allocate_did(&tenant, &state, &self.registry, &*provider).await;
```

Per-step executors take `&impl TokenProvider` instead of `&AccessToken`. They call `with_refreshed_token` for the actual registry operation. `build_deactivation_log` and `build_rotation_log` are unchanged — they call `fetch_log` (unauthenticated) and need no provider.

`StatusListPublisher` resolves the provider per `run_round`; its single registry call (`update_status_list_entry`) goes through `with_refreshed_token`.

## Configuration surface

New env vars consumed by the binary at startup, passed into `ProviderRegistry::new`:

| Variable | Default | Meaning |
|---|---|---|
| `SWIYU_TOKEN_URL` | (required) | OAuth2 token endpoint URL (the SWIYU Keycloak realm) |
| `SWIYU_TOKEN_REFRESH_FRACTION` | `0.75` | Fraction of `expires_in` after which a token is refreshed; expressed as a `f32`, valid range `[0.5, 0.95]` |
| `SWIYU_TOKEN_HTTP_TIMEOUT_SECS` | `15` | Per-request timeout for token-endpoint calls |

`SWIYU_ACCESS_TOKEN` is removed: the runtime no longer reads a manually-pasted access token. The transitional comment in `swiyu-issuer/.env.example` is deleted and the four OAuth2 vars are promoted to the active configuration block.

## Local development seeding

`oauth_refresh_token` rotates on every successful grant, but starts NULL on a freshly migrated database — no migration can embed a real refresh token. Without explicit handling, every `docker compose down -v && up -d` cycle leaves the contributor's dev tenant with NULL credentials and the next worker call fails with `MissingCredentials`. The init migration also no longer seeds any dev tenant row: every contributor brings their own SWIYU Business Partner record and credentials.

The dev loop is closed by a compose-driven bootstrap: the contributor pastes their `DEV_TENANT_*` values into `.env` once, and a one-shot compose service finds or creates their dev tenant row and writes the OAuth2 columns idempotently. The `.env` value survives `docker compose down -v`, so the manual ePortal step happens at the cadence of the OAuth2 refresh-token cliff (~7 days) rather than the cadence of DB wipes. Absent oauth values silently skip the corresponding write; the failure surfaces at the first worker call.

### CLI

A single subcommand drives the bootstrap end-to-end. See [`impl-tenant-management.md`](impl-tenant-management.md#tenant-bootstrap-dev-from-env) for the full semantics; the OAuth2-relevant summary:

```
swiyu-issuer-cli tenant bootstrap-dev-from-env [--force]
```

Without `--force`, the OAuth2 columns are written only-if-empty: a runtime-rotated `oauth_refresh_token` survives a re-run, and an existing `(oauth_client_id, oauth_client_secret)` pair is left alone. With `--force`, every supplied OAuth2 column is overwritten — the operator path after credential rotation at the ePortal.

The two long-form subcommands `tenant set-oauth-credentials` and `tenant import-oauth-refresh-token` remain available for column-by-column edits (e.g. surgical refresh-token rotation outside the bootstrap loop). Both still accept `--only-if-empty` for the dev-loop semantics; the operator path omits it.

### Compose service

A one-shot `bootstrap-dev-tenant` compose service runs once after Postgres is healthy and gates the long-running `swiyu-issuer-mgmtapi` service on its successful completion. It uses the `runtime-cli` Docker target (the same builder layers as `swiyu-issuer-mgmtapi`, but only the `swiyu-issuer-cli` binary in the runtime image) and exits cleanly after the seed.

The entrypoint runs `bootstrap-dev-from-env` in two passes so per-tenant Vault Transit keys (when `SECRET_ENCRYPTION_ENGINE=vault`) can be provisioned between the row creation and the OAuth2-column writes: the runtime tenant id is captured from the first call's stdout, fed into the Vault key-provisioning curl loop, and used by the second call. The `dev` secret-encryption engine path runs both passes too; the Vault loop is a no-op there.

```yaml
bootstrap-dev-tenant:
  build:
    context: ..
    dockerfile: swiyu-issuer/Dockerfile
    target: runtime-cli
  depends_on:
    postgres:
      condition: service_healthy
    vault-init:
      condition: service_completed_successfully
  environment:
    DATABASE_URL: postgres://...
    DEV_TENANT_PARTNER_ID: ${DEV_TENANT_PARTNER_ID}
    DEV_TENANT_DISPLAY_NAME: ${DEV_TENANT_DISPLAY_NAME}
    DEV_TENANT_DESCRIPTION: ${DEV_TENANT_DESCRIPTION}
    DEV_TENANT_CLIENT_ID: ${DEV_TENANT_CLIENT_ID}
    DEV_TENANT_CLIENT_SECRET: ${DEV_TENANT_CLIENT_SECRET}
    DEV_TENANT_REFRESH_TOKEN: ${DEV_TENANT_REFRESH_TOKEN}
    SECRET_ENCRYPTION_ENGINE: ${SECRET_ENCRYPTION_ENGINE:-dev}
    # ...VAULT_*, SECRET_ENCRYPTION_DEV_MASTER_KEY...
  entrypoint:
    - /bin/sh
    - -c
    - |
      set -e
      # Phase 1: ensure the row exists, capture the runtime tenant id.
      # Oauth env vars are unset for this call so a vault-engine
      # secret write cannot fire before the Transit key is provisioned.
      TENANT_ID=$$(
        env -u DEV_TENANT_CLIENT_ID -u DEV_TENANT_CLIENT_SECRET -u DEV_TENANT_REFRESH_TOKEN \
          swiyu-issuer-cli tenant bootstrap-dev-from-env
      )
      if [ "$$SECRET_ENCRYPTION_ENGINE" = "vault" ]; then
        for family in oauth2_client_secret oauth2_refresh_token; do
          curl -fsS -X POST -H "X-Vault-Token: $$VAULT_TOKEN" \
            -H "Content-Type: application/json" \
            -d '{"type":"aes256-gcm96"}' \
            "$$VAULT_ADDR/v1/transit/keys/tenant-$$TENANT_ID-$$family" >/dev/null
        done
      fi
      # Phase 2: write oauth columns (only-if-empty by default).
      swiyu-issuer-cli tenant bootstrap-dev-from-env >/dev/null
  restart: "no"

swiyu-issuer-mgmtapi:
  depends_on:
    bootstrap-dev-tenant:
      condition: service_completed_successfully
```

The CLI runs migrations itself, so no separate migrate step is needed. The compose path omits `--force`, matching the dev-loop semantics (preserve runtime-rotated tokens). Contributors who want to force-resync from `.env` after rotating credentials at the ePortal run the CLI directly with `--force`.

### Dockerfile

The image builds three runtime targets from a single cargo-chef cook layer:

```dockerfile
RUN cargo build --release \
  --bin swiyu-issuer-mgmtapi --bin swiyu-issuer-oidcapi --bin swiyu-issuer-cli
...
FROM runtime-base AS runtime-cli
COPY --from=builder /app/target/release/swiyu-issuer-cli /usr/local/bin/
```

### `tenant set-oauth-credentials` and `tenant import-oauth-refresh-token`

These long-form subcommands are still the operator path for surgical edits to the OAuth2 columns outside the bootstrap loop. They keep their `--only-if-empty` flag (the dev-loop semantics): when supplied, the write is a no-op if the target column(s) are already non-NULL; omitted, the write overwrites unconditionally.

```
swiyu-issuer-cli tenant set-oauth-credentials \
    --tenant <bare-tenant-id> \
    --client-id <value> \
    [--client-secret <value> | --client-secret-stdin] \
    [--only-if-empty]

swiyu-issuer-cli tenant import-oauth-refresh-token \
    --tenant <bare-tenant-id> \
    [--token <value> | --token-stdin] \
    [--only-if-empty]
```

`--client-secret` / `--client-secret-stdin` and `--token` / `--token-stdin` are mutually exclusive, enforced by `clap::ArgGroup`. Operators almost always want the `…-stdin` form — pasting the secret on the command line leaves it in shell history. `set-oauth-credentials` writes both columns atomically inside one transaction; the all-or-none rule avoids leaving the row in a partial state, and it is what `--only-if-empty` keys off (skip if **both** columns are non-NULL).

## Testing

Test approach mirrors the existing pattern (mock the wire boundary, exercise everything else for real):

- **Unit tests for `OAuth2TokenProvider`** in `domain/oauth2/oauth2_provider.rs`. Use `wiremock` for the token endpoint, real `sqlx::test` Postgres pool for persistence. Cases: cold start, warm path, pre-emptive refresh, lazy 401 retry, refresh-token-rejected (4xx), transport error retry, single-flight (multiple concurrent `get()` calls produce one Keycloak request).
- **Unit tests for `ProviderRegistry`** in `domain/oauth2/registry.rs`. Real pool, two tenants, assert lazy construction and per-tenant isolation (one tenant's `invalidate` does not touch the other's cache).
- **Unit tests for `with_refreshed_token`** with a hand-rolled `TokenProvider` mock that records `get`/`invalidate` calls. Cases: success on first try, 401 on first try and success on retry, 401 on first try and 401 on retry (terminal), other RegistryError on first try (no retry).
- **Integration test in `tests/oauth2_e2e.rs`**: tenants table seeded with valid `oauth_*` columns, `wiremock` stub for the token endpoint, `wiremock` stub for one identifier-registry endpoint, exercise an end-to-end `Worker::run` round, assert the rotated refresh token landed in the DB and the registry call carried the expected bearer header.
- **Existing executor tests** are updated to pass a `StaticTokenProvider` instead of an `AccessToken`. The mock invocation logs already drop the token; only the wiring at the construction site changes.

## Out of scope (this implementation)

- Encryption at rest of `oauth_client_secret` and `oauth_refresh_token` — handled in a separate spec.
- Tenant-lifecycle subcommands (`tenant create`, `tenant update`) are introduced in their own slice; see [`impl-tenant-management.md`](impl-tenant-management.md). Other tenant- and sub-resource verbs (`tenant list` / `deactivate`, `tenant api-token list` / `revoke`, …) remain future work. This implementation ships only the OAuth2-related subcommands plus the verbatim `mint-token` migration.
- Token introspection / revocation endpoints. Not part of the SWIYU partner surface.
- Per-tenant token-endpoint URLs. v1 deployments use one URL per process.
- Cross-replica refresh skipping (the optimisation where the just-locked-and-read refresh token's TTL is comfortable enough that the local replica skips its own grant). Initial release always grants under the lock; the optimisation is an easy follow-up if the per-tenant grant rate becomes a bottleneck.
