# Implementation: API-token authentication (v0.1.2)

This document captures concrete implementation decisions for the first real authentication slice. For the multi-tenancy concepts this slice gives teeth to see [`aspect-multi-tenancy.md`](aspect-multi-tenancy.md). For the identifier and prefix conventions reused by API tokens see [`impl_persistence.md`](impl_persistence.md). For the management API surface that consumes the resulting `TenantContext` see [`impl_api_management.md`](impl_api_management.md).

Status: preliminary; living document. v0.1.0 introduced the `TenantContext` extractor as a stub that always resolved to the seeded tenant read from `DEFAULT_TENANT_ID`. v0.1.2 replaces that stub with real API-token authentication; handler signatures do not change, per the promise made in `impl_api_management.md`. The `DEFAULT_TENANT_ID` env var is retired in this slice.

The pre-v0.1.2 stub was acceptable only because alpha/beta data is throwaway (see [`aspect-persistence.md`](aspect-persistence.md) maturity rules). Removing it now is consistent with that policy and does not require a minor-version bump.

## Frame

The first real durchstich for auth is "an API token issued for a tenant authorises a business application to call every endpoint that scopes by `TenantId`." The slice has to:

- replace the body of the `TenantContext` extractor with a token-driven lookup;
- introduce an `api_tokens` table;
- supply two ways to mint tokens — a fixed dev token planted by migration (alpha/beta convenience) and an `swiyu-issuer-mgmtapi mint-token` CLI subcommand (the path real operators use);
- preserve the existing handler signatures so the management API surface is untouched.

Per-issuer scope, token rotation flows, an admin web UI, and any list/revoke endpoints are explicitly **out of scope** for v0.1.2.

## Token format

Prefix discipline mirrors the rest of the codebase:

- **Wire form**: `tok_<base58>` — what the operator copies, pastes into a config, or types into an HTTP header.
- **Stored form**: only the SHA-256 hex digest of the bare body (the part after the prefix), stored as `TEXT`.

The bare body is **32 random bytes from a CSPRNG, base58-encoded** (~44 characters). 256 bits of entropy is well past brute-force reach with the SHA-256 lookup index; argon2/bcrypt would add CPU per request without measurable security benefit at this entropy.

Comparison is by indexed hash lookup: hash the presented token, `SELECT … WHERE token_hash = $1`. The lookup is constant-time at the index level (no early-exit per byte against a known good secret).

## Storage

A new aggregate, in its own persistence submodule. Schema:

```sql
CREATE TABLE api_tokens (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ
);

CREATE INDEX api_tokens_by_tenant ON api_tokens (tenant_id);
```

Choices worth flagging:

- **`id` carries the bare base58 form** (no `apitok_` prefix in the column), per the project-wide rule that DB stores the bare form. Logs and any future JSON surface use the prefixed form via the same `domain::ids` newtype mechanism.
- **`token_hash` is `UNIQUE`** so a generation collision (cosmic, given 256 bits) is rejected at insert time rather than allowing two tokens to map to the same secret.
- **`name` is operator-supplied at mint time** — short label like `"prod-bp-import"`. Surfaces in audit logs once the audit slice lands.
- **`expires_at` and `revoked_at` are nullable** and independently set. A token is **valid** iff `revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())`.
- **`last_used_at`** is updated by the auth path on a successful request. v0.1.2 writes it inline (one extra `UPDATE` per authenticated request); a throttled or batched update lands if the write rate ever becomes a concern.
- **No CHECK constraint** on `id`/`token_hash` formats; application layer validates at insert.

## Module layout

`swiyu-issuer/src/persistence/api_tokens.rs`:

- `insert(conn, token: &ApiToken)` — write a freshly minted row.
- `find_valid_by_hash(conn, token_hash)` — returns the matching `ApiToken` if and only if the row is unrevoked and not expired at the supplied `now`. `None` collapses any other failure mode into "no such valid token".
- `mark_used(conn, id, now)` — bumps `last_used_at`.

`swiyu-issuer/src/domain/api_token.rs`:

- `ApiToken` — the aggregate (id, tenant_id, name, token_hash, created_at, expires_at, revoked_at, last_used_at).
- `ApiTokenSecret` — the bare-string newtype, returned exactly once from `mint(...)` and never reconstructable from the database.
- `ApiTokenHash` — the stored-side newtype wrapping the SHA-256 hex digest, with `from_secret(...)` and `from_stored(...)` constructors.

`swiyu-issuer/src/api_management/auth.rs`:

- The existing `TenantContext` extractor body is replaced. It reads `Authorization: Bearer …`, strips the `tok_` prefix, hashes, looks up via `api_tokens::find_valid_by_hash`, bumps `last_used_at`, and returns `TenantContext { tenant_id }`. On any failure it returns `ApiError::Unauthorised` (401).

`swiyu-issuer/src/bin/swiyu-issuer-mgmtapi.rs`:

- Becomes a small dispatcher. With no positional argument, runs the server (current behaviour). With `mint-token`, runs the CLI flow.

## Wire-level behaviour

- **Header**: `Authorization: Bearer tok_<base58>`. No alternative header (`X-API-Token`, query parameter, etc.) is supported.
- **Missing or malformed header**: 401 `unauthorised` with a generic `details` message. Do not leak which step failed.
- **Expired or revoked token**: 401 `unauthorised`. Same body.
- **Tenant deleted out from under a still-valid token**: 401. (The FK on `tenant_id` should make this near-impossible, but defensive nonetheless.)
- **Operational probes** (`/healthz`, `/readyz`) remain unauthenticated. They are explicitly excluded from the `TenantContext` extractor by route.

## CLI subcommand

```
swiyu-issuer-mgmtapi mint-token --tenant <bare-tenant-id> --name <label> \
    [--expires-in <duration>]
```

- `--tenant` is the **bare** base58 tenant id (no prefix), to match the URL convention.
- `--name` is required; the label is mandatory so audit log lines have something useful.
- `--expires-in` accepts a humanised duration (`30d`, `12h`, `90d`); omitting it mints a non-expiring token.
- Output: the bare wire form (`tok_…`) printed to stdout exactly once, followed by a one-line "save this now; the hash is what we keep" reminder on stderr. Exit status 0 on success.
- Implementation flow: load config → connect pool → run pending migrations → generate `ApiTokenSecret` → insert via `persistence::api_tokens::insert` → print → exit.

The dispatcher in `bin/swiyu-issuer-mgmtapi.rs` uses `clap` (added by this slice). Subcommand parsing is simple enough that hand-rolled arg matching would also work; `clap` earns its keep when the next admin subcommand lands (revoke-token, list-tokens, …).

## Dev token seeding

The migration that creates `api_tokens` also seeds **one fixed dev token** for the seeded tenant `4Mk7yK5pQR7sN3`:

- Bare wire form: `tok_DevDevDevDevDevDevDevDevDevDevDevDevDevDe` (a documented well-known value, NOT generated; valid base58, no collision concern at this entropy).
- The migration inserts the corresponding SHA-256 hex hash directly into `api_tokens.token_hash`.
- `name = "seeded-dev-token"`.
- `expires_at = NULL`, `revoked_at = NULL`.

Rationale:

- Migrations cannot read env vars, so the bare token cannot arrive that way at migration time. Hardcoding the dev token's hash is operationally simpler than running a post-migration seeder.
- The dev token is **alpha/beta-only** by policy. The transition to production maturity (prod-1) revokes it explicitly via a later migration; see [`aspect-persistence.md`](aspect-persistence.md) for maturity rules.

`docker-compose.yml` and `test-commands.txt` should be updated in the same slice to use the dev token.

## Error mapping

A new variant is added (see [`impl_api_management.md`](impl_api_management.md) for the existing table):

| Source                                     | HTTP          |
|--------------------------------------------|---------------|
| `ApiError::Unauthorised` (auth failure)    | 401           |

Already in the table — no schema change to `ErrorBody`.

The auth extractor never returns 403 in v0.1.2; per-issuer scope is the slice that introduces "authenticated but not authorised here". Until then, every authenticated tenant has full access to its own resources, and cross-tenant access falls under the existing 404 ownership-check rule (defense in depth: the `require_issuer_owned_by_tenant` boundary check still runs).

## Configuration

Environment variables consumed by `swiyu-issuer-mgmtapi`:

- `DATABASE_URL` — unchanged.
- `BIND_ADDR` — unchanged.
- `ISSUER_BASE_URL` — unchanged.
- `DEFAULT_TENANT_ID` — **removed**. Authentication now derives the tenant from the token, not from config.

No new env vars in v0.1.2.

## Tests

- Domain unit tests:
- `ApiTokenSecret::generate` produces a valid `tok_…` string.
- `ApiTokenHash::from_secret` is deterministic.
- Round-trip: hash a generated secret, look up by that hash, compare equality on the stored aggregate.
- Persistence unit tests (DB-backed once the integration test harness lands; until then, smoke against a local Postgres):
- `find_valid_by_hash` returns `None` for revoked tokens.
- `find_valid_by_hash` returns `None` for expired tokens.
- `mark_used` bumps `last_used_at`.
- Auth-extractor tests:
- Missing header → 401.
- Bad scheme (`Basic …`) → 401.
- Unknown token → 401.
- Valid token populates `TenantContext.tenant_id`.
- Cross-tenant: a token for tenant A on a request to a tenant B issuer's path returns 404 from the existing ownership check (regression test that asymmetry is unchanged).
- CLI smoke test:
- `swiyu-issuer-mgmtapi mint-token --tenant <id> --name foo` prints a `tok_…` to stdout, the row is in `api_tokens`, the printed token's hash matches `token_hash`.

## Suggested slice ordering

1. Migration: `api_tokens` table + the seeded dev-token row.
2. Domain: `ApiTokenSecret`, `ApiTokenHash`, `ApiToken`.
3. Persistence: `insert`, `find_valid_by_hash`, `mark_used`.
4. `auth.rs` extractor body swap. Handlers untouched.
5. `bin/swiyu-issuer-mgmtapi.rs` dispatcher + `mint-token` subcommand.
6. Update `docker-compose.yml`, `test-commands.txt`, and any developer onboarding to use the dev token. Remove `DEFAULT_TENANT_ID` references.
7. Tests per the section above.

Steps 1–3 may land together. Step 4 must come last among the server-side changes; step 5 may land alongside or just after.

## What is deliberately not in v0.1.2

- **Per-issuer token scope.** The multi-tenancy spec already describes per-issuer scoping; v0.1.2 is tenant-level only. Lifts in a later v0.1.x slice when the audit log makes the policy observable.
- **Token list / revoke endpoints** in the management API. The v0.1.2 path is "use the CLI to mint, edit the row directly to revoke". An admin endpoint lands when the admin web UI lands.
- **Token rotation semantics.** Rotation = mint a new one and revoke the old one; no in-place update. Codify if and when the pattern feels insufficient.
- **Rate limiting on failed auth attempts.** Bitbucket / origin proxies handle DOS; per-token throttling lands when there is a real client and a real signal.
- **HSM-backed token verification.** API tokens are symmetric secrets. Production maturity may revisit this if a key-backed scheme (e.g. mTLS, signed JWTs against the issuer's signing key) becomes the standard for cantonal integrations.
- **Audit log entries for auth events** (mint, successful authentication, failed attempts). Wired in by the audit slice that follows this one. The auth slice ships with the `last_used_at` field so the audit slice can correlate.

## Forward compatibility with OAuth / OIDC

The v0.1.2 design is a deliberately small, self-contained authentication scheme — local API tokens only. The choice does **not** paint the codebase into a corner if an OAuth or OIDC integration (cantonal SSO, Keycloak, federated business-app identity, …) becomes a requirement later.

Two invariants do most of the work:

- **Handlers only see `TenantContext`.** Swapping the auth backend is local to the `auth.rs` extractor body. Even when `TenantContext` later grows a richer principal model, handler signatures stay put. This is the same hands-off promise that carried the `TenantContext` stub through v0.1.0 and v0.1.1.
- **`Authorization: Bearer …` is the only accepted scheme.** That is also the scheme OAuth uses, so the wire surface does not have to break when a second token kind is introduced.

### Migration path (do none of this preemptively)

1. Introduce a `TokenVerifier` trait with the v0.1.2 behaviour as `LocalApiTokenVerifier`. The extractor body delegates to it. Behaviour-preserving refactor.
2. Add a second verifier — `JwtVerifier` (JWKS-based, for an external IdP) or `IntrospectionVerifier` (RFC 7662, for opaque tokens validated remotely). The extractor dispatches by token prefix: `tok_*` → local, `eyJ*` → JWT, otherwise → configured fallback.
3. Extend `TenantContext` **additively** with a `principal: Principal { ApiToken | OAuthClient | OAuthUser }` and, eventually, a `scopes` field. Done at the point a second principal kind exists, not before. The audit-log design in [`aspect-persistence.md`](aspect-persistence.md) already names "actor kind and id"; the data model has room.
4. Make tenant resolution pluggable. Today the resolution is a DB lookup; for JWT it would be claim-based (a `tenant_id` claim, or an `aud`/`scope` translation rule).

The forcing function for any of the above is "a second verifier actually exists." Doing the trait-based refactor with a single implementation in v0.1.2 is over-engineering; the surface is small enough that the refactor is a localised PR when the time comes.

### Constraints to preserve now

So that the migration above stays cheap, v0.1.2 must not bake in assumptions that would have to be undone:

- Keep 401 response bodies **generic**. Don't leak which step failed; OAuth flows depend on the same discretion.
- Don't add custom auth headers (`X-API-Token`, query parameters, …). Only `Authorization: Bearer`. Anything else would need deprecation when a second verifier lands.
- `last_used_at` is a property of **locally-minted API tokens**, not of authentication in general. It lives on `api_tokens`, not on `TenantContext`. Don't surface it through any abstraction that the future `JwtVerifier` would have to implement.
- The `mint-token` CLI is not OAuth-replaceable. It keeps making sense for CI, smoke tests, and machine-to-machine flows where spinning up a full IdP would be overkill. Plan for coexistence, not replacement.

## Open

- **`last_used_at` write strategy.** Inline per-request `UPDATE` is the v0.1.2 lean. If contention shows up under bursty authenticated traffic, throttle to once per N seconds per token, or batch via a deferred-write queue. Not worth over- engineering before there is a measurable signal.
- **Default token TTL.** v0.1.2 mints non-expiring tokens by default. A finite default (e.g. 90 days) would push operators toward rotation but adds friction in dev/CI. Revisit when the audit slice surfaces token-age metrics.
- **CLI argument parsing crate.** `clap` is the lean for the reasons above. If `mint-token` stays the only subcommand for more than one release, hand-rolled `args().collect()` parsing would shave the dependency. Decide when `revoke-token` lands.
- **Dev token rotation policy.** The seeded dev token's hash is baked into a migration. Rotating it (e.g. to invalidate a leaked alpha token) requires shipping a follow-up migration. Acceptable for alpha/beta; document explicitly so it does not surprise.
- **Bootstrap for fresh tenants.** Onboarding a real tenant (post-v0.1.2) needs a way to mint the **first** API token for that tenant. Today the `mint-token` subcommand is the answer (operator runs it on the server). When tenant onboarding lands via an admin UI / API, that flow needs its own initial-token story.
