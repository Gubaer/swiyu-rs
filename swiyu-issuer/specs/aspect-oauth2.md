# Aspect: OAuth2 token lifecycle

This document describes how `swiyu-issuer` obtains, caches, and refreshes the OAuth2 access tokens it presents to the SWIYU registries on behalf of its tenants.

It is the issuer-side complement to [`swiyu-registries/specs/aspect-oauth2.md`](../../swiyu-registries/specs/aspect-oauth2.md). That document describes the SWIYU OAuth2 protocol itself — endpoints, grant types, partner credentials, the empirical facts about TTLs and rotation. This document describes how a multi-tenant issuer process implements the partner side of that protocol: the `TokenProvider` abstraction, the refresh state machine, the integration with tenant configuration, and the operational considerations around the seven-day refresh-token TTL.

## Where this layer sits

`swiyu-registries` is a thin HTTP wrapper. Its registry clients (`IdentifierRegistryClient`, `StatusRegistryClient`) accept an `&AccessToken` as a per-call argument and do nothing about acquiring or refreshing it. Everything OAuth2 — the token endpoint, the `refresh_token` grants, the per-tenant in-memory cache, the rotation handling, and the per-tenant persistence of the rotated refresh token — lives in `swiyu-issuer`. This split matches the dependency direction (registries cannot depend on issuer) and concentrates the operational concerns (tenant configuration, persistence, monitoring) where they naturally belong.

## TokenProvider abstraction

The `TokenProvider` is the in-memory state machine for one OAuth2 credential set. It exposes two operations:

- `async fn get(&self) -> Result<AccessToken, ...>` — return a currently-valid access token, refreshing transparently via a `refresh_token` grant if the cached one has elapsed its safety margin.
- `async fn invalidate(&self) -> Result<AccessToken, ...>` — discard the cached access token and force a fresh `refresh_token` grant. Called by code that observed a `401` from a registry and wants to retry once with a new token.

A small helper around the trait keeps the 401-refresh-retry pattern terse at worker call sites — for example:

```text
with_refreshed_token(provider, |token| client.allocate_did(token, partner_id))
```

— which calls `provider.get()`, runs the inner closure with the resulting token, and retries the closure once with a freshly-`invalidate`d token if the first attempt returned `RegistryError::HttpStatus { status: 401, .. }`. Other failure modes (network errors during a grant, 5xx from the token endpoint, transport errors during the registry call) are surfaced to the caller; backoff and outer retry policy belong to the worker, not to this layer.

Two implementations are needed in the initial release:

- **`OAuth2TokenProvider`** — the real implementation. Performs `refresh_token` grants against the SWIYU Keycloak realm, caches the access token in memory, runs single-flight refresh, and writes the rotated refresh token back to the tenant row's `refresh_token` column. The column is the single source of truth for the tenant's refresh token: operators populate it manually at onboarding (with the renewal token from the ePortal) and again for recovery; in between, the runtime keeps it up to date automatically on every grant.
- **`StaticTokenProvider`** — test-only. Wraps a fixed `AccessToken`. No caching, no refresh. Used by integration tests that do not exercise the OAuth2 flow, and (potentially) by `swiyu-didtool` for one-shot CLI invocations against a manually-pasted token.

## Multi-tenancy

`swiyu-issuer` is multi-tenant: a single process serves many tenants, with each tenant in 1:1 correspondence with a SWIYU business partner. Every business partner is provisioned with its own credentials in the Swiss ePortal, so every tenant carries its own `(client_id, client_secret, refresh_token)` triple on the tenant row and mints its own access tokens at runtime.

The shape of the design:

- **One `TokenProvider` per tenant.** A `TokenProvider` instance is the in-memory state machine for exactly one OAuth2 credential set: it owns the cached access token, the refresh token, the expiry instant, and the single-flight refresh slot. Two tenants with different credential sets hold two distinct `TokenProvider` instances; their state never crosses.
- **Per-tenant fault isolation.** Token caches, refresh-in-flight slots, and refresh-token values are scoped strictly to a single `TokenProvider`. A failed refresh, a revoked credential, or a misconfigured tenant affects only that tenant's flows; other tenants continue untouched.
- **Tenant-to-provider mapping.** `swiyu-issuer` holds the equivalent of a `tenant_id -> Arc<dyn TokenProvider>` map. Providers are constructed lazily on first use for a given tenant and cached for the lifetime of the process (or until the tenant's configuration changes, whichever is shorter).
- **Single registry-client instance.** `swiyu-registries` clients are tenant-agnostic — they take a token per call — so a single `IdentifierRegistryClient` (and a single `StatusRegistryClient`) serves every tenant in the process. No per-tenant client construction, no duplicated `reqwest::Client` connection pools.

The cost of this design is per-tenant state proportional to the number of active tenants. For realistic deployments (tens to low hundreds of tenants) this is a few KiB of memory per tenant plus one in-flight refresh slot — negligible. The benefit is a sharp per-tenant fault boundary and a clean follow-up path to per-tenant persistence without disturbing `swiyu-registries`.

## Acquisition flow

The runtime maintains a small state machine per tenant. The access token lives in memory only and is re-acquired after a process restart; the refresh token is the durable state, held in the tenant row's `refresh_token` column. Every successful grant rotates that column to the new value the realm returned.

1. **Cold start.** Read the tenant's `refresh_token` column. Perform a `refresh_token` grant against the configured token endpoint. Cache the resulting access token in memory together with the response's `expires_in` (deriving an absolute expiry instant `now + expires_in - safety_margin`), and write the rotated `refresh_token` back to the column.
2. **Warm path, token still valid.** `provider.get()` returns the cached access token without contacting the token endpoint.
3. **Pre-emptive refresh.** Before the cached expiry instant elapses, perform a `refresh_token` grant using the in-memory refresh token. Cache the new access token and persist the rotated refresh token to the tenant row. This keeps live calls off the slow path and keeps the system away from the `expires_in` boundary where clock skew bites.
4. **Lazy refresh on `401`.** A protected registry call that returns `401 Unauthorized` is surfaced by `swiyu-registries` as `RegistryError::HttpStatus { status: 401, .. }`. The wrapper around `provider.invalidate()` performs an on-demand `refresh_token` grant (persisting the rotated refresh token) and retries the original call once. This covers two cases the scheduler cannot: revocation by the SWIYU operations team, and clock skew between this process and the authorization server that makes a token look valid locally when the server already considers it expired.
5. **Refresh-token failure.** A 4xx response on a `refresh_token` grant means the held refresh token is no longer valid — typically because the deployment went more than seven days without a successful refresh and the refresh-token TTL elapsed, or the operations team revoked the credential. There is no fallback: `client_credentials` is gateway-forbidden (900908). The error is surfaced; recovery is a human operation: paste a fresh renewal token from the ePortal into the tenant's `refresh_token` column. The next grant attempt picks it up automatically.

## Lifecycle invariants

These properties must hold for any `TokenProvider` implementation in this crate.

- **One credential set per `TokenProvider`.** A given instance holds exactly one `(client_id, client_secret)` pair together with the access and refresh tokens minted from it. Multi-tenant isolation is achieved by holding one provider per tenant; the provider itself is not aware of tenancy.
- **Tokens never appear in logs.** The `AccessToken` newtype in `swiyu-registries` masks `Debug` and zeroizes on drop. Refresh tokens — which are *more* sensitive than access tokens, since they directly mint new access tokens — must be wrapped equivalently inside this crate.
- **No token endpoint URL is ever hardcoded.** The URL is configuration, supplied at construction. Default values (e.g. an obvious-default for the integration environment) belong in the binary's startup path, not in this crate.
- **No clock-trust beyond `expires_in`.** The runtime's clock is trusted to compare against an expiry instant derived from the response's `expires_in`. JWT `exp` claims inside the access token are not parsed — they are the authorization server's concern, not this client's.
- **Refresh is serialised per credential set, both within one replica and across replicas.** Within one replica, an in-memory single-flight pattern (one concurrent refresh, additional callers awaiting the same future) coalesces concurrent demand. Across replicas, the actual grant is wrapped in a DB transaction with a row-level lock on the tenant row (`SELECT … FOR UPDATE`): a concurrent refresher on another replica blocks until the lock releases, then re-reads the rotated token and skips its own grant if the freshly-read token's TTL is comfortable. This avoids races that would otherwise rely on the SWIYU grace-window rotation to be tolerable.
- **Acquisition is async.** Every operation that touches the token endpoint is `async` on tokio. There is no blocking variant.

## What this layer does not do

- It does not authenticate end users. There is no human in the loop on the registry side. End-user authentication for the management API is a different concern.
- It does not negotiate scopes. The SWIYU Keycloak realm issues a single tier of access; there is no need to request specific scopes per call.
- It does not relax the seven-day refresh-token TTL. Persistence keeps the refresh token alive across process restarts, so a restart of an otherwise-healthy deployment is invisible to the OAuth2 layer; but a real outage longer than seven days still strands the deployment and requires an operator to paste a fresh renewal token from the ePortal into the tenant row.
- It does not persist access tokens. Only the refresh token is durable. Access tokens are session artefacts: a process restart re-acquires them via a `refresh_token` grant on the next call (one Keycloak round-trip per tenant on cold start). This avoids encrypting yet another short-lived secret at rest, at the cost of one extra grant per restart.

## Out of scope for the initial release

- Any grant other than `refresh_token`. `client_credentials` is gateway-forbidden for SWIYU partner Anwendungen — see [`swiyu-registries/specs/aspect-oauth2.md`](../../swiyu-registries/specs/aspect-oauth2.md).
- Token introspection (`POST /token/introspect`) or revocation (`POST /revocations`).

## Operational considerations

- **Seven-day refresh-token cliff is bounded by outage length.** Because the refresh token is persisted on the tenant row and rotated on every scheduled refresh, normal operation never approaches the cliff: as long as the deployment performs at least one successful refresh within any seven-day window, the stored token stays alive indefinitely. The cliff only triggers on a real outage longer than seven days (a long holiday shutdown, a forgotten dev environment, a stalled disaster-recovery scenario). When that happens, the stored refresh token is dead and an operator must paste a fresh renewal token from the ePortal into the tenant's `refresh_token` column. Monitoring should alert on consecutive `refresh_token` grant failures so the cliff is detected before it becomes user-visible.
- **Secret-at-rest surface.** The `refresh_token` column is as sensitive as `client_secret` and must be encrypted at rest with the same care. It is the single durable token secret for the tenant; access tokens are not persisted.
- **Manual seeding and recovery share a code path.** Onboarding a tenant, recovering after a >7-day outage, and recovering from a revoked credential are all the same operation: paste the renewal token from the ePortal into the tenant's `refresh_token` column. The runtime does not distinguish between "first use" and "recovery" — it just reads the column on the next grant attempt.
- **`client_id` / `client_secret` rotation from the ePortal.** Rotating these is a tenant-config update followed by replacing the affected `TokenProvider` instance. The previously stored refresh token was minted under the old client and may no longer be valid against the rotated client, so operators paste a fresh renewal token at the same time as updating `client_id` / `client_secret`.
