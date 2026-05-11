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

`oauth_client_id` is not a secret and stays TEXT. The two secret columns are BYTEA because they hold self-describing ciphertext blobs produced by the `SecretEncryptionEngine`; see [`impl-secret-management.md`](impl-secret-management.md) for the envelope format. All three are `NULL`-able because tenants that do not call SWIYU registries (today: none, but the option is preserved) do not need OAuth2 credentials. Workers requesting a token for such a tenant fail Terminal with `MissingCredentials`. Operators populate `oauth_client_id` and `oauth_client_secret` via direct SQL at onboarding (a one-off operation); the recurring operation — pasting a fresh renewal token from the ePortal after a >7-day cliff or credential rotation — is supported by the `tenant import-oauth-refresh-token` subcommand below. The runtime updates `oauth_refresh_token` on every successful grant.

### Operator subcommand

Operator commands live in a new `swiyu-issuer-cli` binary, separate from the long-running `issuer-mgmt` daemon. Tenant is the primary resource; everything operators do is either a verb on a tenant or on a sub-resource owned by a tenant. The CLI mirrors that hierarchy:

```
swiyu-issuer-cli tenant <verb-or-subresource> [args]
```

v1 ships:

```
swiyu-issuer-cli tenant import-oauth-refresh-token --tenant <bare-tenant-id> --token <refresh-token>
swiyu-issuer-cli tenant api-token mint              --tenant <bare-tenant-id> --name <label> [--expires-in 30d]
```

`tenant import-oauth-refresh-token` connects to the database via `DATABASE_URL`, validates that the tenant exists, and writes `<refresh-token>` to `tenants.oauth_refresh_token`. Idempotent: re-running with the same token is a no-op as far as the runtime is concerned (the runtime would have rotated it on the next grant anyway). The `--token` value is read from a hidden CLI argument; for shell-history-safety, operators may prefer to pipe via env var or a heredoc — the implementation accepts both `--token <value>` and `--token-stdin` for the prompted form.

`tenant api-token mint` migrates verbatim from `issuer-mgmt`'s pre-existing top-level `mint-token` subcommand (same DB connection logic, same secret-printing semantics, same exit codes), now nested under `tenant api-token` because API tokens are tenant-scoped. After the migration, `issuer-mgmt` is server-only — it stops mixing the long-running daemon with one-shot operator commands.

The CLI is the future home for additional tenant- and tenant-sub-resource operations (`tenant create`, `tenant list`, `tenant deactivate`, `tenant api-token list`, `tenant api-token revoke`, rotate `client_id` / `client_secret`, …); v1 ships only the two commands above because they are the only ones currently load-bearing. The nested subcommand structure lets future commands land without restructuring.

The token endpoint URL is *not* per-tenant — every tenant's credentials authenticate against the same SWIYU realm. It comes from the `SWIYU_TOKEN_URL` env var read by the `issuer-mgmt` daemon at startup and threaded into `ProviderRegistry::new`. `swiyu-issuer-cli` does not need this env var: its commands write directly to the DB and do not perform OAuth2 grants themselves.

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

`oauth_refresh_token` rotates on every successful grant, but starts NULL on a freshly migrated database — the migration that seeds the dev tenant cannot embed a real refresh token. Without explicit handling, every `docker compose down -v && up -d` cycle leaves the dev tenant with NULL credentials and the next worker call fails with `MissingCredentials`.

The dev loop is closed by a compose-driven auto-seed: the operator pastes a refresh token from the ePortal into `.env` once per refresh-token TTL window (~7 days), and a one-shot compose service writes it to the dev tenant whenever the column is NULL. The `.env` value survives `docker compose down -v`, so the operator's manual ePortal step happens at the cadence of the OAuth2 refresh-token cliff rather than the cadence of DB wipes. An empty value silently skips the seed, so first-run dev still works without the operator pasting anything; the failure surfaces at the first worker call as today.

### `--only-if-empty` flag

`swiyu-issuer-cli tenant import-oauth-refresh-token` gains an `--only-if-empty` flag that turns the write into a no-op when `oauth_refresh_token IS NOT NULL`. The check-and-write runs in one transaction so a token rotation between the SELECT and the UPDATE does not get clobbered.

```
swiyu-issuer-cli tenant import-oauth-refresh-token \
    --tenant <bare-tenant-id> --token-stdin --only-if-empty
```

The operator path (re-pasting a rotated token after a >7-day cliff) omits the flag and overwrites unconditionally — same code path otherwise.

### Compose service

A new one-shot `bootstrap-dev-tenant` compose service runs once after Postgres is healthy, and gates the long-running `issuer-mgmt` service on its successful completion. It uses the same image as `issuer-mgmt` (which now ships `swiyu-issuer-cli` alongside) and exits cleanly after the seed.

```yaml
bootstrap-dev-tenant:
  image: swiyu-issuer-issuer-mgmt
  depends_on:
    postgres:
      condition: service_healthy
  environment:
    DATABASE_URL: postgres://...
    DEV_TENANT_ID: ${DEV_TENANT_ID:-4Mk7yK5pQR7sN3}
    SWIYU_REFRESH_TOKEN: ${SWIYU_REFRESH_TOKEN}
  entrypoint: ["/bin/sh", "-c"]
  command: |
    if [ -n "$$SWIYU_REFRESH_TOKEN" ]; then
      printf '%s' "$$SWIYU_REFRESH_TOKEN" | \
        swiyu-issuer-cli tenant import-oauth-refresh-token \
          --tenant "$$DEV_TENANT_ID" --token-stdin --only-if-empty
    fi
  restart: "no"

issuer-mgmt:
  depends_on:
    bootstrap-dev-tenant:
      condition: service_completed_successfully
```

The CLI runs migrations itself, so no separate migrate step is needed. The same env var (`SWIYU_REFRESH_TOKEN`) was already declared in `.env.example` as a doc-only seed; this section turns that comment into a working code path. `DEV_TENANT_ID` defaults to the bare id of the tenant seeded by `migrations/20260430_000001_init.sql`; it is parameterised so the magic string in the compose file becomes a named knob, even though no current dev workflow overrides the default.

### Dockerfile

The image now builds and ships both binaries:

```dockerfile
RUN cargo build --release --bin issuer-mgmt --bin swiyu-issuer-cli
...
COPY --from=builder /app/target/release/issuer-mgmt      /usr/local/bin/
COPY --from=builder /app/target/release/swiyu-issuer-cli /usr/local/bin/
```

### `tenant set-oauth-credentials` and the `oauth_client_id` / `oauth_client_secret` columns

The other two OAuth2 columns have the same "must be in DB before any worker call" problem as `oauth_refresh_token`, but rotate far less frequently — `aspect-oauth2.md` describes them as a one-time onboarding write that survives the runtime's per-grant refresh-token rotation. They are written by a sibling CLI subcommand and the same `bootstrap-dev-tenant` compose service.

#### CLI

```
swiyu-issuer-cli tenant set-oauth-credentials \
    --tenant <bare-tenant-id> \
    --client-id <value> \
    [--client-secret <value> | --client-secret-stdin] \
    [--only-if-empty]
```

`--client-secret` and `--client-secret-stdin` are mutually exclusive, enforced by a `clap::ArgGroup` mirroring `import-oauth-refresh-token`. Operators almost always want `--client-secret-stdin` — pasting the secret on the command line leaves it in shell history.

The subcommand writes both columns atomically inside one transaction. It does **not** touch `oauth_refresh_token`, which has a separate lifecycle (rotated by the runtime on every grant) and is handled by `tenant import-oauth-refresh-token`.

#### `--only-if-empty` semantics

Skip the write when **both** `oauth_client_id` and `oauth_client_secret` are non-NULL; write both otherwise. The all-or-none rule avoids leaving the row in a partial state if one column was nuked out-of-band, and it is what the dev-loop auto-seed wants: re-seeding only when the column pair is genuinely empty.

The operator path — credential rotation at the ePortal — omits the flag and overwrites unconditionally. Both columns must always be supplied together; the subcommand intentionally does not let an operator update only one half of the pair.

#### Lib function

```rust
pub async fn set_oauth_credentials(
    pool: &PgPool,
    tenant_id: &TenantId,
    client_id: String,
    client_secret: SecretString,
    only_if_empty: bool,
) -> Result<SeedOutcome, SetOauthCredentialsError>;
```

Reuses the `SeedOutcome { Wrote, Skipped }` enum from `import_oauth_refresh_token`. `SetOauthCredentialsError` mirrors `ImportOauthRefreshTokenError` (`TenantNotFound`, `Persistence`, `Sqlx` variants).

#### `bootstrap-dev-tenant` extension

The compose service grows a credentials seed step that runs **before** the existing refresh-token seed. Order matters: a refresh-token grant can only succeed once `client_id` and `client_secret` are populated, so the credentials must land first.

```yaml
command: |
  if [ -n "$$SWIYU_CLIENT_ID" ] && [ -n "$$SWIYU_CLIENT_SECRET" ]; then
    printf '%s' "$$SWIYU_CLIENT_SECRET" \
      | swiyu-issuer-cli tenant set-oauth-credentials \
          --tenant "$$DEV_TENANT_ID" \
          --client-id "$$SWIYU_CLIENT_ID" \
          --client-secret-stdin --only-if-empty
  fi
  if [ -n "$$SWIYU_REFRESH_TOKEN" ]; then
    printf '%s' "$$SWIYU_REFRESH_TOKEN" \
      | swiyu-issuer-cli tenant import-oauth-refresh-token \
          --tenant "$$DEV_TENANT_ID" --token-stdin --only-if-empty
  fi
```

Both blocks are gated on the relevant env var being non-empty; with both empty, the bootstrap silently skips and the first worker call fails with `MissingCredentials`, same as without this service. `SWIYU_CLIENT_ID` and `SWIYU_CLIENT_SECRET` were already declared in `.env.example` as doc-only seeds; this design promotes them to active env vars consumed by the bootstrap service.

## Testing

Test approach mirrors the existing pattern (mock the wire boundary, exercise everything else for real):

- **Unit tests for `OAuth2TokenProvider`** in `domain/oauth2/oauth2_provider.rs`. Use `wiremock` for the token endpoint, real `sqlx::test` Postgres pool for persistence. Cases: cold start, warm path, pre-emptive refresh, lazy 401 retry, refresh-token-rejected (4xx), transport error retry, single-flight (multiple concurrent `get()` calls produce one Keycloak request).
- **Unit tests for `ProviderRegistry`** in `domain/oauth2/registry.rs`. Real pool, two tenants, assert lazy construction and per-tenant isolation (one tenant's `invalidate` does not touch the other's cache).
- **Unit tests for `with_refreshed_token`** with a hand-rolled `TokenProvider` mock that records `get`/`invalidate` calls. Cases: success on first try, 401 on first try and success on retry, 401 on first try and 401 on retry (terminal), other RegistryError on first try (no retry).
- **Integration test in `tests/oauth2_e2e.rs`**: tenants table seeded with valid `oauth_*` columns, `wiremock` stub for the token endpoint, `wiremock` stub for one identifier-registry endpoint, exercise an end-to-end `Worker::run` round, assert the rotated refresh token landed in the DB and the registry call carried the expected bearer header.
- **Existing executor tests** are updated to pass a `StaticTokenProvider` instead of an `AccessToken`. The mock invocation logs already drop the token; only the wiring at the construction site changes.

## Out of scope (this implementation)

- Encryption at rest of `oauth_client_secret` and `oauth_refresh_token` — handled in a separate spec.
- Additional `swiyu-issuer-cli` subcommands beyond `tenant import-oauth-refresh-token`, `tenant set-oauth-credentials`, and the migrated `tenant api-token mint` (`tenant create` / `list` / `deactivate`, `tenant api-token list` / `revoke`, …). The binary's nested subcommand structure accommodates them as they land; this implementation ships only the OAuth2-related set plus the verbatim mint-token migration.
- Token introspection / revocation endpoints. Not part of the SWIYU partner surface.
- Per-tenant token-endpoint URLs. v1 deployments use one URL per process.
- Cross-replica refresh skipping (the optimisation where the just-locked-and-read refresh token's TTL is comfortable enough that the local replica skips its own grant). Initial release always grants under the lock; the optimisation is an easy follow-up if the per-tenant grant rate becomes a bottleneck.
