# Implementation: persistence

This document captures the concrete implementation of the `swiyu-issuer` persistence layer. For the conceptual model see [`aspect-persistence.md`](aspect-persistence.md); for the technology choices that underlie it see [`aspect-technology.md`](aspect-technology.md).

Status: living document. Reflects the persistence layer as it stands today.

## Module layout

`swiyu-issuer/src/persistence/`:

- `mod.rs` — module declarations, the `ListPage<T>` paginated-result type, and re-exports.
- `pool.rs` — `connect(database_url)` and `run_migrations(pool)`.
- `errors.rs` — `PersistenceError` enum.
- `helpers.rs` — internal helpers, including `map_database_error` which maps Postgres SQLSTATE 23505 (`unique_violation`) onto `PersistenceError::UniqueViolation`.
- `tenants.rs`, `issuers.rs`, `api_tokens.rs`, `credential_offers.rs`, `issued_credentials.rs`, `operation_tasks.rs`, `status_lists.rs` — one submodule per aggregate.
- `tenant_secret_keys.rs` — pure functions that derive the `SecretEncryptionEngine` key names for a given tenant (`oauth2_client_secret:<tenant_id>`, `oauth2_refresh_token:<tenant_id>`). Kept separate so the naming convention has one home and the write/read paths in `tenants.rs` cannot drift.
- `oidc/` — submodule grouping the OIDC token endpoint's persistent state: `access_tokens.rs`, `nonces.rs`, plus an `oidc/credential_offers.rs` for offer lookups the OIDC handlers need.

`swiyu-issuer/migrations/` holds versioned `.sql` migration files. The binaries call `sqlx::migrate!("./migrations").run(pool)` at startup.

## Public surface

- `persistence::PersistenceError` — typed error: `NotFound`, `UniqueViolation { what }`, `DataIntegrity { details }`, `Db(sqlx::Error)`.
- `persistence::ListPage<T>` — paginated-result wrapper carrying `items` and a `has_more` flag; the underlying queries fetch `limit + 1` rows and drop the extra one.
- `persistence::connect(database_url)` — pool construction.
- `persistence::run_migrations(pool)` — applies pending migrations.
- Aggregate submodules (`persistence::tenants`, `persistence::issuers`, …) — exposed namespaced rather than flattened, because aggregate-level function names like `insert` and `find` are not unique enough to merge at the persistence root.

## Identifier strategy

**IDs are short random base58 strings, not UUIDs**, with one exception noted below.

Rationale:

- The wallet-facing credential offer URL is encoded in a QR code; URL length directly affects QR density and scan reliability. UUID-based paths are unnecessarily long for that case.
- Hash-of-UUID was considered and rejected: it is a roundabout way to arrive at a short identifier, and a truncated hash has the same collision math as generating the same number of random bytes directly. The added blake3 dependency and the two-step UUID + derived-ID storage were not worth it.

Generation: 10 random bytes from a CSPRNG, base58-encoded (~14 characters). Done at the application layer, not in the database.

Storage: `TEXT` columns. (`BYTEA` would be denser but every log line and SQL result has to convert; `TEXT` is what humans read anyway.)

Collision math: at 80 bits and 100 million rows ever stored, collision probability per insert is ~10⁻⁹. Insert with the unique constraint and retry on conflict; in practice retries do not occur.

**Exception: SigningEngine key pair IDs are UUIDs**, not base58. The DevSigningEngine table `signing_engine_dev_keypairs` is owned by `swiyu-signing-engine`, which uses `uuid::Uuid` for its identifiers; `issuers.{authorized,authentication,assertion}_key_id` mirror that type. The boundary between the two crates' identifier conventions runs through those FK columns.

### Prefix discipline

- **DB stores the bare form**, e.g. `9hXq2vRtL8pK7f`.
- **Wallet-facing offer URL uses the bare form** (`/o/9hXq2vRtL8pK7f`) to keep QR codes minimal.
- **Management API JSON bodies and logs use the prefixed form**, e.g. `tenant_4Mk7yK5pQR7sN3`, `issuer_9hXq2vRtL8pK7f`, `offer_8KpL9zRT5qWnFm`. Self-describing in logs and HTTP traffic.
- The prefix is **added/stripped at the API boundary**, never in persistence or domain.

The `domain::ids` newtypes own the prefix logic: `Display` and `Serialize` produce the prefixed form, `FromStr` and `Deserialize` accept it, and a `bare()` accessor returns the unprefixed value for the wallet-facing offer URL.

Format validation lives in the newtype constructor (`generate()` produces only valid base58; `FromStr` rejects invalid strings). The database does not enforce a base58 character class — easier to evolve than a CHECK constraint, and the application layer is the primary enforcement anyway.

## Schema

Migrations live in `swiyu-issuer/migrations/`. Two files are in place today:

- `20260430_000001_init.sql` — single pre-production baseline. Collapses the original 0001 through 0015 migrations together with the subsequent OAuth2 column additions and their re-typing for encryption-at-rest. The expand/contract history of the alpha period was discarded because the data is throwaway and the file is easier to read as one piece.

All subsequent schema changes go in their own numbered migration on top of the baseline. The naming convention (`<DATE>_<SEQ>_<description>.sql`) is documented in `LESSONS-LEARNED.md`; in short, only the leading date is the sqlx migration version, so two files sharing a date prefix collide.

### `tenants`

`id` (TEXT, PK), `partner_id` (TEXT, nullable), `oauth_client_id` (TEXT, nullable), `oauth_client_secret` (BYTEA, nullable), `oauth_refresh_token` (BYTEA, nullable).

`partner_id` is the SWIYU business-partner UUID. Nullable so non-registry-touching tenants stay possible; the worker's `allocate_did` step fails Terminal with `tenant_missing_partner_id` when it is `NULL` and a registry call is required.

The two BYTEA columns hold self-describing ciphertext blobs produced by the `SecretEncryptionEngine` (format version, `key_name`, and `key_version` travel inside the blob, so no companion columns are needed to identify the key under which a value was encrypted). The domain `Tenant` carries them as `Option<Ciphertext>`; decryption happens at the OAuth2 provider boundary, not on every load of the tenant row. Plaintext secrets remain wrapped in `secrecy::SecretString` while they cross the application layer (zeroize-on-drop, redacted `Debug`). Operators populate `oauth_client_id` / `oauth_client_secret` via the `swiyu-issuer-cli tenant set-oauth-credentials` subcommand; the refresh token's recurring import path is `swiyu-issuer-cli tenant import-oauth-refresh-token`. `oauth_client_id` itself is not a secret and stays TEXT. See [`aspect-oauth2.md`](aspect-oauth2.md), [`impl-oauth2.md`](impl-oauth2.md), and [`aspect-secret-management.md`](aspect-secret-management.md).

### `issuers`

`id` (TEXT, PK), `tenant_id` (FK → `tenants`), `did`, `state`, `description`, `authorized_key_id` / `authentication_key_id` / `assertion_key_id` (UUID, nullable until provisioned), `display_name`, `logo_uri`, `locale`, `current_status_list_id` (FK → `status_lists`, nullable), `created_at`.

The three role-keyed key columns are UUIDs because they reference rows in the SigningEngine's own table; they are populated by the `create_issuer` worker flow. `current_status_list_id` is `NULL` until the same worker's `provision_status_list` step fills it in. `created_at` drives the stable cursor order (`created_at DESC, id DESC`) for the paginated list endpoint.

### `credential_offers`

`id` (TEXT, PK), `tenant_id` (FK), `issuer_id` (FK), `vct`, `claims` (JSONB), `state` (TEXT), `pre_auth_code` (TEXT, nullable), `expires_at`, `created_at`, `cancelled_at` (nullable), `issued_at` (nullable). Index on `(tenant_id, issuer_id)`.

Storage-type and modelling choices worth flagging:

- **`tenant_id` carried alongside `issuer_id`** even though `issuer_id` alone would identify the tenant via the FK chain. Scoped queries filter by tenant directly, future RLS predicates key on `tenant_id` without joining, and the composite index supports the common access pattern. Intentional, narrow denormalisation.
- **`state` as `TEXT`**, not a Postgres `ENUM`. Avoids enum-migration friction; revisit only if values need stronger DB-level constraints.
- **`pre_auth_code` is the bare value, nullable.** OID4VCI's by-reference issuance flow forces the bare value to be retrievable when the wallet fetches `/credential-offer/{offer_id}`, so the column holds the raw code while the offer is pending and is set to `NULL` at the first terminal-state transition (cancel, issue, or expiry sweep). The exposure is bounded by `expires_at`. See [`impl_api_oidc.md`](impl_api_oidc.md).

### `api_tokens`

`id` (TEXT, PK), `tenant_id` (FK), `name`, `token_hash` (TEXT, UNIQUE), `created_at`, `expires_at` (nullable), `revoked_at` (nullable), `last_used_at` (nullable). Index on `tenant_id`.

`token_hash` is `base58(SHA-256(bare token body))`. The bare token never reaches the database. A token is valid iff `revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())`. See [`impl_auth.md`](impl_auth.md).

### OIDC token endpoint state

Two focused tables under the `oidc_*` prefix. The earlier "one table with a kind discriminator vs. several focused tables" question is resolved in favour of focused tables: clearer schema, per-table indexing, and the columns of the two tables genuinely differ.

`oidc_access_tokens`: `token_hash` (TEXT, PK), `tenant_id`, `issuer_id`, `offer_id` (UNIQUE, FK → `credential_offers ON DELETE CASCADE`), `expires_at`, `created_at`. Index on `expires_at`. The `UNIQUE (offer_id)` constraint is the row-level guard against double redemption — a second `/token` request for the same offer races to this constraint and loses; the handler maps the conflict to OAuth `invalid_grant`.

`oidc_nonces`: `nonce_hash` (TEXT, PK), `tenant_id`, `issuer_id`, `offer_id` (FK → `credential_offers ON DELETE CASCADE`, **not** unique — multiple nonces per offer are allowed today and required by future batch credential issuance), `expires_at`, `created_at`. Indexes on `offer_id` and `expires_at`.

Both tables follow the one-shot-secret rule: only `SHA-256(secret)` is on disk; the bare value lives outside the database.

### DevSigningEngine storage

`signing_engine_dev_keypairs`: `id` (UUID, PK), `algorithm` (TEXT), `private_key` (BYTEA, **plaintext**), `public_key` (BYTEA), `created_at`. No tenant or issuer columns — the engine is ignorant of issuer ownership; the `(issuer, role) -> current_id` mapping lives in the `issuers` row.

This table is logically owned by `swiyu-signing-engine`; the migration creates it from `swiyu-issuer` because both crates ship together and there is no separate migration runner for the engine. Plaintext is intentional for the dev/test maturity tier — the aspect-level "AEAD-wrapped per-tenant KEK" intermediate step is not implemented today. Production deployments use the Vault-backed signing engine, which does not touch this table.

### `operation_tasks`

Async worker queue backing `create_issuer`, `rotate_keys`, `deactivate_issuer`.

Columns: `id` (TEXT, PK), `tenant_id` (FK), `task_type`, `state`, `step` (nullable), `attempts` (INT), `next_attempt_at` (nullable), `error_code` (nullable), `error_message` (nullable), `input` (JSONB), `state_data` (JSONB, default `'{}'`), `result_issuer_id` (nullable), `created_at`, `updated_at`, `completed_at` (nullable).

Indexes:

- `operation_tasks_dispatch` — partial index on `(next_attempt_at NULLS FIRST, created_at)` WHERE `state IN ('pending', 'in_progress')`. Keeps the worker's "find next runnable" probe fast as completed/failed rows accumulate.
- `operation_tasks_tenant` — `(tenant_id, created_at DESC)` for the management API's task-listing endpoint.

Rows persist after completion as an operational trace. See [`aspect-issuer.md`](aspect-issuer.md) and [`impl-issuer.md`](impl-issuer.md).

### `status_lists`

One row per BitstringStatusList instance. Bitstring is a fixed 32 KB (`statusSize=2`, capacity 131 072 credentials, two bits per credential).

Columns: `id` (TEXT, PK), `issuer_id` (FK), `bitstring` (BYTEA, CHECK `octet_length = 32768`), `allocated_count` (INT, CHECK `≤ 131072`), `committed_version` (BIGINT), `published_version` (BIGINT), `last_publish_attempt_at` (nullable), `last_publish_error` (nullable), `next_publish_attempt_at` (nullable), `publish_attempts` (INT), `registry_entry_id` (nullable TEXT), `registry_url` (nullable TEXT), `created_at`.

Indexes:

- `status_lists_issuer` — `(issuer_id)` for the issuer-scoped queries.
- `status_lists_dirty` — partial index on `(next_publish_attempt_at NULLS FIRST)` WHERE `committed_version > published_version`. Powers the publish worker's "find next dirty list" probe.

The `committed_version` / `published_version` pair drives the publish worker: when committed exceeds published, the list is dirty and a publish round is needed. The signed status-list credential itself is **not** stored — only the registry pointer (`registry_entry_id`, `registry_url`) is. There is no public status-list endpoint hosted by `swiyu-issuer`.

`registry_entry_id` and `registry_url` are nullable; a row stays unallocated-on-registry from local insert until the `create_issuer` worker's `create_status_list_entry` step fills them in.

The FK `issuers.current_status_list_id → status_lists(id)` is added at the end of the init migration once both tables exist.

### `issued_credentials`

Issuer-side record of every credential signed. Metadata only — the signed SD-JWT VC bytes are not retained; `integrity_hash` (SHA-256 of the compact serialisation handed to the wallet) is the only trace.

Columns: `id` (TEXT, PK), `tenant_id` (FK), `issuer_id` (FK), `credential_offer_id` (FK, UNIQUE), `vct`, `holder_key_jkt` (RFC 7638 thumbprint, base64url), `status_list_id` (FK), `status_list_index` (INT), `state` (TEXT, default `'active'`), `integrity_hash` (BYTEA), `issued_at`, `expires_at`.

Constraints:

- `UNIQUE (credential_offer_id)` — codifies the 1:{0..1} relation from offers to issued credentials.
- `UNIQUE (status_list_id, status_list_index)` — codifies "indices are not reused".

Indexes:

- `issued_credentials_tenant_issuer` — `(tenant_id, issuer_id, issued_at DESC)` for the management list endpoint.
- `issued_credentials_holder` — `(tenant_id, issuer_id, holder_key_jkt)` for holder-keyed lookups.

`vct` and `holder_key_jkt` are denormalised at issuance time so later edits to the originating credential type do not retroactively rewrite an existing credential's view, and so the wallet's `cnf` key need not be retained beyond its thumbprint. `state` carries `'active'`, `'suspended'`, `'revoked'`; expiry is **not** a stored state — it is derived from `expires_at` at read time. See [`aspect-credential-management.md`](aspect-credential-management.md).

### Seed data

The init migration seeds one tenant (`4Mk7yK5pQR7sN3`, partner_id = kacon gmbh), one issuer (`9hXq2vRtL8pK7f`, no key triple yet), and one API token (`9DevDevDevDev1`, bare body `DevDevDevDevDevDevDevDevDevDevDevDevDevDe`). IDs are hand-picked valid 14-character base58 strings so they look like real generated IDs to dev tooling. The token hash is a literal; a unit test in `domain::api_token` recomputes it and asserts equality, so any change to the seed body breaks loudly. The seeded token is alpha/beta-only by policy and must be revoked by a follow-up migration before prod-1.

## Cargo dependencies

```toml
sqlx = { version = "0.8", default-features = false, features = [
    "runtime-tokio", "tls-rustls",
    "postgres", "macros", "migrate",
    "chrono", "json", "uuid",
] }
```

The `uuid` feature is present because `issuers.{authorized,authentication,assertion}_key_id` and `signing_engine_dev_keypairs.id` are Postgres `uuid`. `bs58` is used by `domain::ids` for ID generation and parsing. `secrecy` is used to wrap the OAuth2 client secret and refresh token end-to-end so they never appear in `Debug` output.

## Function-shape conventions

- **Free functions in submodules**, not repository structs. There is a single backend, so a trait-based abstraction would be premature.
- Every function takes a sqlx executor argument (`&mut PgConnection`) so it composes into transactions.
- Every function takes `TenantId` and, where relevant, `IssuerId` as required arguments. Tenant scoping is enforced at the signature level, before SQL ever runs.
- Query predicates filter by both `tenant_id` and `issuer_id` even when only one would suffice; combined with future RLS, this is defense in depth.
- Errors flow through `helpers::map_database_error` (which lifts SQLSTATE 23505 unique-violations into `PersistenceError::UniqueViolation`) and otherwise propagate via `?` and the `From<sqlx::Error>` impl on `PersistenceError::Db`. Encryption-layer failures surface as `PersistenceError::Encryption` via a `From<SecretEncryptionError>` impl, so functions that encrypt or decrypt on the way to/from the row can propagate with `?`.

## Resolved decisions

These were open in earlier drafts and are now settled in the code:

- **OIDC ephemeral storage**: focused tables (`oidc_access_tokens`, `oidc_nonces`), not a single table with a kind discriminator.
- **What to retain of an issued credential**: metadata plus an `integrity_hash`; the signed compact SD-JWT VC bytes are not persisted.
- **Pre-auth code storage**: bare nullable column on `credential_offers`, not a separate bridge table.
- **OAuth2 secret storage at rest**: encrypted via the `SecretEncryptionEngine` and stored as self-describing ciphertext blobs in BYTEA columns. Per-tenant key names (`oauth2_client_secret:<tenant_id>`, `oauth2_refresh_token:<tenant_id>`) are derived by `persistence::tenant_secret_keys`. The earlier "plaintext text with `SecretString` only in-memory" arrangement is gone.

## Still not implemented

- Postgres row-level security policies. The schema is shaped to support them (tenant_id on every aggregate) but no policies are installed yet.
- Periodic-cleanup sweeper for expired `oidc_access_tokens`, `oidc_nonces`, and pre-auth codes. Expired rows currently accumulate until the surrounding flow ignores them on read.
- Audit log table and writer. The aspect describes the intended shape; no schema or code is in place.
- DevSigningEngine private keys remain plaintext BYTEA in `signing_engine_dev_keypairs`. Wrapping them through the same `SecretEncryptionEngine` path that now protects the OAuth2 secrets is a candidate next step; not done today because the dev signing engine is dev/test-only and the production path goes through Vault Transit, which holds the keys natively.

## Open

- **ID character set in URLs**: base58 versus base32. Base58 is the current lean (avoids visually similar characters). Revisit if a reason to prefer case-insensitive comparison appears.
- **Management API ID prefixes in URL paths**: currently prefixed in JSON bodies and logs, bare in URLs. Whether to surface prefixes in URL path segments is undecided.
