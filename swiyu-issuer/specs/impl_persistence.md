# Implementation: persistence (v0.1.0)

This document captures concrete implementation decisions for the
persistence layer as of release v0.1.0. For the conceptual model see
[`aspect-persistence.md`](aspect-persistence.md); for the technology
choices that underlie it see [`aspect-technology.md`](aspect-technology.md).

Status: preliminary; living document. Reflects the v0.1.0 walking-skeleton
scope — one seeded tenant, one seeded issuer, credential offers as the
first aggregate.

## Module layout

`swiyu-issuer/src/persistence/`:

- `mod.rs` — module declarations and re-exports.
- `pool.rs` — `connect(database_url)` and `run_migrations(pool)`.
- `errors.rs` — `PersistenceError` enum.
- `credential_offers.rs` — placeholder for the v0.1.0 aggregate (empty
  at v0.1.0).

`swiyu-issuer/migrations/` holds versioned `.sql` migration files. The
binaries call `sqlx::migrate!("./migrations").run(pool)` at startup.

## Public surface

- `persistence::PersistenceError` — typed error wrapping `sqlx::Error`.
- `persistence::connect(database_url)` — pool construction.
- `persistence::run_migrations(pool)` — applies pending migrations.
- `persistence::credential_offers` — submodule, namespaced.

Submodules stay namespaced (e.g. `persistence::credential_offers::insert`)
because aggregate-level function names like `insert` and `find` are not
unique enough to flatten safely at the persistence root.

## Identifier strategy

**IDs are short random base58 strings, not UUIDs.**

Rationale:

- The wallet-facing credential offer URL is encoded in a QR code; URL
  length directly affects QR density and scan reliability. UUID-based
  paths are unnecessarily long for that case.
- Hash-of-UUID was considered and rejected: it is a roundabout way to
  arrive at a short identifier, and a truncated hash has the same
  collision math as generating the same number of random bytes
  directly. The added blake3 dependency and the two-step UUID +
  derived-ID storage were not worth it.

Generation: 10 random bytes from a CSPRNG, base58-encoded (~14
characters). Done at the application layer, not in the database.

Storage: `TEXT` columns. (`BYTEA` would be denser but every log line
and SQL result has to convert; `TEXT` is what humans read anyway.)

Collision math: at 80 bits and 100 million rows ever stored, collision
probability per insert is ~10⁻⁹. Insert with the unique constraint and
retry on conflict; in practice retries do not occur.

### Prefix discipline

- **DB stores the bare form**, e.g. `9hXq2vRtL8pK7f`.
- **Wallet-facing offer URL uses the bare form**
  (`/o/9hXq2vRtL8pK7f`) to keep QR codes minimal.
- **Management API JSON bodies and logs use the prefixed form**,
  e.g. `tenant_4Mk7yK5pQR7sN3`, `issuer_9hXq2vRtL8pK7f`,
  `offer_8KpL9zRT5qWnFm`. Self-describing in logs and HTTP traffic.
- The prefix is **added/stripped at the API boundary**, never in
  persistence or domain.

The future `domain::ids` newtypes own the prefix logic: `Display` and
`Serialize` produce the prefixed form, `FromStr` and `Deserialize`
accept it, and a `bare()` accessor returns the unprefixed value for
the wallet-facing offer URL.

Format validation lives in the newtype constructor (`generate()`
produces only valid base58; `FromStr` rejects invalid strings). The
database does not enforce a base58 character class — easier to evolve
than a CHECK constraint, and the application layer is the primary
enforcement anyway.

## v0.1.0 schema

`migrations/20260430_000001_init.sql`:

- `tenants(id text primary key)`.
- `issuers(id text primary key, tenant_id text not null references tenants(id))`.
- `credential_offers(id, tenant_id, issuer_id, vct,
  claims jsonb, state, pre_auth_code_hash, expires_at, created_at)`.
  The `vct` column holds the SD-JWT VC type identifier; see
  [`impl_credential_schema.md`](impl_credential_schema.md).
- Index on `credential_offers(tenant_id, issuer_id)`.
- Seeded one tenant (`4Mk7yK5pQR7sN3`) and one issuer
  (`9hXq2vRtL8pK7f`) with hand-picked fixed IDs for predictable
  dev/test setups.

Storage-type choices worth flagging:

- **`state` as `TEXT`**, not a Postgres `enum`. Avoids enum-migration
  friction; revisit only if values need stronger DB-level constraints.
- **`tenant_id` carried on `credential_offers`** even though
  `issuer_id` would be sufficient via the FK chain. Reason: scoped
  queries filter by tenant directly, RLS predicates will key on
  `tenant_id`, and the composite `(tenant_id, issuer_id)` index is
  useful. Light, intentional denormalisation.
- **No CHECK constraint on ID column length or character class**.
  Application-layer validation in the newtype constructor is the
  primary enforcement; database-level validation can be added later
  if a need appears.

## Cargo dependencies

```toml
sqlx = { version = "0.8", default-features = false, features = [
    "runtime-tokio", "tls-rustls",
    "postgres", "macros", "migrate",
    "chrono", "json",
] }
```

The `uuid` feature is intentionally absent: identifiers are `TEXT`,
not Postgres `uuid`. `bs58` will be added when ID generation is
implemented in `domain/`.

## Function-shape conventions (for code added later)

- **Free functions in submodules**, not repository structs. There is
  a single backend, so a trait-based abstraction would be premature.
- Every function takes a sqlx executor argument (`&mut PgConnection`)
  so it composes into transactions.
- Every function takes `TenantId` and, where relevant, `IssuerId` as
  required arguments. Tenant scoping is enforced at the signature
  level, before SQL ever runs.
- Query predicates filter by both `tenant_id` and `issuer_id` even
  when only one would suffice; combined with future RLS, this is
  defense in depth.
- Errors map to `PersistenceError` via `?` and the
  `From<sqlx::Error>` impl on `PersistenceError::Db`.

## What is deliberately not in v0.1.0

- `tenants.rs`, `issuers.rs`, `admin_users.rs`, `api_tokens.rs`,
  `audit.rs`, `oidc_ephemeral.rs`, `status_lists.rs`,
  `issued_credentials.rs`, `credential_types.rs` — wait for their
  respective slices. `issuers.rs` in particular waits for the auth
  layer that produces a `TenantContext` and the request-boundary
  ownership check that needs it.
- Postgres row-level security policies — defense in depth turned on
  once tests run with multiple tenants.
- Partial-update / state-transition–specific functions on
  `credential_offers`. Full-row update is fine at this scale.
- `bs58` dependency. Pulled in when `domain::ids` arrives with
  `generate()` and `FromStr`.

## Open

- ID character set in URLs: base58 versus base32. Base58 is the
  current lean (avoids visually similar characters). Revisit if a
  reason to prefer case-insensitive comparison appears.
- Whether the management API IDs include type prefixes only on the
  wire (`Serialize`/`Deserialize`) or also in the URL path. Current
  lean: prefix in JSON bodies and logs, bare IDs everywhere in URLs.
