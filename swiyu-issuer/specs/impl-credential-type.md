# Implementation: Credential type

This document describes how the `CredentialType` aspect (see [`aspect-credential-type.md`](aspect-credential-type.md)) is realised inside the `swiyu-issuer` crate. It covers the domain types, the `credential_types` and `issuer_credential_types` schema, the JSON-Schema validator cache, the OID4VCI metadata projection that consumes both tables, and the tenant-admin management API for managing credential types and their assignment to issuers.

For the conceptual model (ownership at the tenant, assignment to issuers, lifecycle), see [`aspect-credential-type.md`](aspect-credential-type.md). For domain-vocabulary definitions (`vct`, `CredentialConfiguration`, `CredentialSchema`), see [`aspect-domain.md`](aspect-domain.md). For the BA-facing issuance flow that *consumes* credential types, see [`impl-credential-management.md`](impl-credential-management.md). For the broader domain-module layout, see [`impl_domain.md`](impl_domain.md); for the persistence-module conventions (id prefixes, enum-as-text, audit log), see [`impl_persistence.md`](impl_persistence.md).

Status: preliminary; living document. Supersedes the earlier `impl_credential_schema.md`, which was framed around the walking-skeleton (one bundled schema, no DB-backed types).

## Module layout

New and extended code:

- `swiyu-issuer/src/domain/credential_type.rs` — `CredentialType` aggregate, `CredentialTypeId`, `RevocationMode`. Replaces the compile-time `vct.rs` catalogue.
- `swiyu-issuer/src/domain/issuer_credential_type.rs` — `IssuerCredentialTypeAssignment` aggregate; the *(issuer, credential_type)* link row.
- `swiyu-issuer/src/persistence/credential_types.rs` — CRUD on `credential_types`, per-blob accessors for `claim_schema` / `display` / `claims`.
- `swiyu-issuer/src/persistence/issuer_credential_types.rs` — assign / un-assign / list-by-issuer / list-by-type.
- `swiyu-issuer/src/api_management/credential_types.rs` — tenant-admin handlers for the credential-type and assignment endpoints.
- `swiyu-issuer/src/api_oidc/metadata.rs` — extended to project `credential_configurations_supported` from the joined `credential_types` × `issuer_credential_types` rows.
- `swiyu-issuer/src/state/validators.rs` — the compiled-validator cache used by the issuance handler (`api_oidc::credential`) and by the `PUT /schema` handler to reject invalid uploads.

## Domain types

### `CredentialType`

```rust
pub struct CredentialType {
    pub id: CredentialTypeId,
    pub tenant_id: TenantId,
    pub vct: String,

    // Display surfaces
    pub display: serde_json::Value,            // OID4VCI display array (per-locale entries)
    pub internal_description: Option<String>,  // admin-facing, unlocalised

    // Claim schema and metadata
    pub claim_schema: serde_json::Value,                // JSON Schema 2020-12 document
    pub claim_schema_source_url: Option<String>,
    pub claim_schema_fetched_at: Option<DateTime<Utc>>,
    pub claims: serde_json::Value,                      // OID4VCI claims metadata

    // Issuance behaviour
    pub default_validity_duration: Duration,
    pub revocation_mode: RevocationMode,

    // Audit and lifecycle
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub retired_at: Option<DateTime<Utc>>,
}

pub enum RevocationMode {
    Revocable,
    Suspendable,
    RevocableAndSuspendable,
    None,
}
```

`display`, `claims`, and `claim_schema` are held as `serde_json::Value` rather than typed structs because their internal shape is externally defined (OID4VCI metadata schema, JSON Schema 2020-12) and evolves faster than the DDL can keep up. The aspect document calls this the structured-columns vs. document-blobs split; the *split* is implemented here.

`default_validity_duration` is `chrono::Duration` in memory and `INTERVAL` on the DB side. `revocation_mode` is `TEXT` on the DB and converted via the project's enum-as-text convention (see [`impl_persistence.md`](impl_persistence.md)).

Four OID4VCI protocol fields the aspect document lists as `CredentialType` properties — `format`, `signing_algorithm`, `cryptographic_binding_methods_supported`, `proof_types_supported` — are **not** carried as columns. They are fixed by the SWIYU profile (`vc+sd-jwt` for the credential format; ES256 over P-256 for assertion signing; holder-key binding and proof-of-possession types tracking what the SWIYU wallet sends). Per-credential-type variation here would have nowhere to land in the SWIYU ecosystem, so the OID4VCI projection sources them from `swiyu-core` profile constants instead of a row read. See *OID4VCI metadata projection* below.

### `CredentialTypeId`

Newtype following the project bs58/prefix convention. Prefix: `ctype`. Wire form: `ctype_<bare-base58>`. Matches every other identifier in the codebase and decouples the URL from any externally meaningful string. (The aspect spec leaves identifier shape as an open question — `(tenant_id, slug)` or the `vct` itself as alternatives — but the impl resolves it to the bs58 form.)

### `IssuerCredentialTypeAssignment`

```rust
pub struct IssuerCredentialTypeAssignment {
    pub issuer_id: IssuerId,
    pub credential_type_id: CredentialTypeId,
    pub tenant_id: TenantId,
    pub assigned_at: DateTime<Utc>,
}
```

No dedicated id newtype: the *(issuer_id, credential_type_id)* pair is the primary key. `tenant_id` is denormalised onto the row for two reasons: it makes "list all credential types assigned to any issuer of tenant *T*" a single-table scan, and it gives row-level security (per [`aspect-multi-tenancy.md`](aspect-multi-tenancy.md)) a column to predicate on without joining back.

## Persistence schema

One migration adds `credential_types`; a follow-up migration adds `issuer_credential_types`. Both sequence after the issuer-management slice's migrations.

### `credential_types`

```sql
CREATE TABLE credential_types (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    vct TEXT NOT NULL,

    display JSONB NOT NULL DEFAULT '[]'::jsonb,
    internal_description TEXT,

    claim_schema JSONB NOT NULL,
    claim_schema_source_url TEXT,
    claim_schema_fetched_at TIMESTAMPTZ,
    claims JSONB NOT NULL DEFAULT '{}'::jsonb,

    default_validity_duration INTERVAL NOT NULL,
    revocation_mode TEXT NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at TIMESTAMPTZ,

    UNIQUE (tenant_id, vct)
);

CREATE INDEX credential_types_tenant_active
    ON credential_types (tenant_id)
    WHERE retired_at IS NULL;
```

- `UNIQUE (tenant_id, vct)` codifies "a tenant has at most one credential-type row per `vct`". It does **not** constrain cross-tenant `vct` collisions — two tenants may carry the same `vct` on independent rows, as required by [`aspect-credential-type.md`](aspect-credential-type.md) § *Ownership*.
- `claim_schema` is `NOT NULL`: a credential type without a schema cannot validate claims at issuance, so the row would be unusable. Newly created types arrive with their schema in the same management-API exchange (or are rejected).
- `revocation_mode` is `TEXT` with values `revocable` / `suspendable` / `revocable_and_suspendable` / `none`, per enum-as-text convention. The value **drives runtime behaviour**: the credential-lifecycle handlers (`POST /issued-credentials/{id}/suspend`, `…/unsuspend`, `…/revoke`, per [`impl-credential-management.md`](impl-credential-management.md)) reject any call whose verb is not permitted by the credential type's mode — e.g. a `revoke` against a credential of a type marked `suspendable` returns HTTP 409. Whether all four mode values are supported is still open in [`aspect-credential-type.md`](aspect-credential-type.md) § *Open questions*; enforcement is on regardless of how the value set lands.
- `default_validity_duration` is required at credential-type creation: the management API rejects a `POST /credential-types` body without it, and there is **no application-level fallback at issuance**. Validity is a per-credential-type business decision (a library card and a council-membership credential are unlikely to share a validity window), so silently picking a default would produce credentials with surprise expiry. Per-issuance override of this default is a separate question, captured in [`aspect-credential-type.md`](aspect-credential-type.md) § *Open questions — Validity overrides per issuance*.
- The partial index supports the hot path "list a tenant's *active* credential types"; retired rows stay in the table for audit and historical lookup from already-issued credentials.

### `issuer_credential_types`

```sql
CREATE TABLE issuer_credential_types (
    issuer_id TEXT NOT NULL REFERENCES issuers(id),
    credential_type_id TEXT NOT NULL REFERENCES credential_types(id),
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (issuer_id, credential_type_id)
);

CREATE INDEX issuer_credential_types_tenant
    ON issuer_credential_types (tenant_id);

CREATE INDEX issuer_credential_types_credential_type
    ON issuer_credential_types (credential_type_id);
```

The cross-tenant constraint — *both* the issuer and the credential type must belong to the same tenant — is enforced in application code at the assignment handler, not via a check constraint. A SQL-level enforcement would require either a trigger (heavy) or a denormalised `tenant_id` on every referenced row plus a composite FK; the application check is the simplest faithful enforcement and matches how the issuance handler already performs *(tenant, issuer, credential type)* ownership checks before claim validation.

### Relationship to credential-offer / issued-credential rows

`credential_offers.vct` and `issued_credentials.vct` are opaque strings, not foreign keys to `credential_types`. The `vct` on those rows is part of the historical record of what was issued — it is the URI the wallet's SD-JWT VC carries in its `vct` claim, and verifiers may still resolve credentials minted under a type long after that type is retired. A foreign key would couple the row's lifetime to the type's: `ON DELETE RESTRICT` blocks retirement of a type that has any issued credentials (operationally awkward, since types accumulate issued credentials by design), and `ON DELETE SET NULL` erases the historical type-link entirely. Carrying the URI verbatim avoids both. The aspect spec's open question on "soft-delete vs. hard-delete" lands in favour of soft-delete for the same reason.

## Claim-schema storage and validator cache

The `claim_schema` `JSONB` column is the canonical, in-process source of truth for each type's validator. Compiled `jsonschema::Validator`s live in `AppState`, keyed by `CredentialTypeId`, populated **lazily on first use** and tagged with the row's `updated_at` so a per-request freshness check detects schema changes without any pub/sub infrastructure:

```rust
struct ValidatorCacheEntry {
    validator: Arc<Validator>,
    schema_updated_at: DateTime<Utc>,
}

pub struct AppState {
    // ...
    pub validators: Arc<RwLock<HashMap<CredentialTypeId, ValidatorCacheEntry>>>,
}
```

The cache is empty at startup. The issuance handler — after the *(tenant, issuer, credential type, assignment)* probes pass — already knows the credential type's current `updated_at` (probe (2) reads it from the row, alongside `claim_schema` itself; see *Issuance flow integration* below). It then:

1. Takes the read lock. If an entry exists and `entry.schema_updated_at == row.updated_at`, clones the `Arc<Validator>` and proceeds.
2. Otherwise drops the read lock, takes the write lock, double-checks (another request may have raced), compiles the `claim_schema` from the row probe (no extra DB round-trip), inserts a fresh `ValidatorCacheEntry`, and clones the `Arc<Validator>`.
3. Releases the lock and calls `validator.validate(&claims)`.

Subsequent requests with the same `updated_at` take the read-lock fast path. A schema update bumps `updated_at` on the row; every process notices on its next request for that type, re-compiles once, and resumes serving. Unused credential types are never compiled.

Schema validity is checked at the *write* boundary, not at startup: the management-API `PUT /credential-types/{id}/schema` handler compiles the supplied document *before* it is written, rejecting invalid schemas with HTTP 400. So a broken `claim_schema` in the DB is an exception path (direct SQL, migration mishap, bad seed). Under lazy compile, the first BA request for the affected type fails with HTTP 500 and a structured log; other credential types continue to issue. The blast radius matches the misconfiguration's scope.

Two ergonomic notes about the freshness comparison:

- `updated_at` is bumped by **every** structured-field or blob-upload edit on the row, not just schema changes. A `PUT …/display` edit triggers a redundant re-compile next time the type is issued. The cost is one compile per affected type per change — acceptable given how rare type edits are.
- Retired types never reach this code path: probe (2) has `retired_at IS NULL`, so a retired type's cache entry is simply orphaned. Memory use per stale entry is small; a periodic GC pass is not introduced for now.

Keying by `CredentialTypeId` rather than by `vct` is required by the tenant ownership model: two tenants can carry rows with the same `vct` but divergent schemas, and the cache must distinguish them.

The issuance handler resolves the `CredentialTypeId` from the BA's `(issuer_id, credential_type_id, claims)` request before validation; see *Issuance flow* below.

## OID4VCI metadata projection

An issuer's `credential_configurations_supported` is **exactly** the set of credential types its tenant has assigned to it, as stated in [`aspect-credential-type.md`](aspect-credential-type.md) § *Effect on the protocol surface*. The projection lives in `api_oidc::metadata` and is computed at request time, not cached:

```sql
SELECT ct.*
    FROM credential_types ct
    JOIN issuer_credential_types ict
        ON ict.credential_type_id = ct.id
    WHERE ict.issuer_id = $1
      AND ct.retired_at IS NULL;
```

For each returned row, the handler emits one entry in `credential_configurations_supported`, keyed by `ct.id` (the bs58-prefixed `CredentialTypeId`), with the value shaped per the OID4VCI metadata schema:

```json
{
  "ctype_3p4kxz…": {
    "format":                                    /* swiyu-core profile constant: "vc+sd-jwt" */,
    "vct": "urn:vct:proof-of-residency",
    "cryptographic_binding_methods_supported":   /* swiyu-core profile constant */,
    "credential_signing_alg_values_supported":   /* swiyu-core profile constant */,
    "proof_types_supported":                     /* swiyu-core profile constant */,
    "display": [ /* verbatim from credential_types.display */ ],
    "claims": { /* verbatim from credential_types.claims */ }
  }
}
```

`scope` is deliberately omitted: SWIYU issuance runs through the OID4VCI pre-authorized code grant, where the wallet identifies the offer by the pre-auth code rather than by an OAuth2 scope. Adding `scope` would be decorative metadata with no flow consuming it. If a future profile introduces the authorization-code grant, the projection can mirror `vct` into `scope` (or expose a dedicated `scope` column on `credential_types`) at that point.

Notes:

- `display` and `claims` pass through unmodified: they are stored in the JSONB column already shaped for OID4VCI consumption. The management API rejects malformed uploads at write time.
- `format`, `cryptographic_binding_methods_supported`, `credential_signing_alg_values_supported`, and `proof_types_supported` are sourced from `swiyu-core` profile constants, not from `credential_types` columns. They are the same for every credential type in the SWIYU ecosystem (`vc+sd-jwt` only; ES256 over P-256 for assertion signing; holder-key binding and proof-of-possession tracking the SWIYU wallet). The aspect spec lists them as conceptual `CredentialType` properties because OID4VCI permits per-type variation in general; the SWIYU profile collapses that variation to constants, so the row never had them.
- These four constant-valued fields still appear **per entry** in the projected JSON, not in a top-level metadata block. OID4VCI defines them inside each `credential_configurations_supported` entry and has no "applies to all configurations" carve-out, so a compliant projection inlines the same constant into every entry. The duplication is wire-format-mandated, not an internal-modelling artefact.
- An issuer with zero assignments returns an empty `credential_configurations_supported`. The wallet sees a discoverable issuer with no offerings — which is the correct projection of "active issuer, type catalogue empty".
- Retired credential types are filtered out by the `ct.retired_at IS NULL` predicate. The retire handler performs `DELETE FROM issuer_credential_types WHERE credential_type_id = $1` in the same transaction as the `retired_at` update, so the assignment rows are hard-deleted alongside the retire; the predicate above is defence in depth, not a load-bearing filter.

## Management API

The management API uses the same tenant-authenticated surface as the BA-facing issuance API (per [`impl_auth.md`](impl_auth.md)). The owning tenant is **never in the URL**; it is derived from the API token by `TenantContext`. Cross-tenant access returns `404`, matching the convention established by [`impl-credential-management.md`](impl-credential-management.md).

### Credential-type CRUD

| Verb | Path | Purpose |
|---|---|---|
| `POST` | `/api/v1/credential-types` | Create a credential type. Body carries the full set of structured fields **and** the `claim_schema`. Returns the assigned `credential_type_id`. |
| `GET` | `/api/v1/credential-types` | List the tenant's credential types. Returns structured columns plus URLs to per-blob endpoints; does **not** embed `claim_schema` / `display` / `claims`. Supports `?retired=true` to include retired rows. |
| `GET` | `/api/v1/credential-types/{credential_type_id}` | Fetch one. Same shape as the list element. |
| `PATCH` | `/api/v1/credential-types/{credential_type_id}` | Update a subset of structured fields. Omitted fields are unchanged. Updates to `claim_schema` / `display` / `claims` use the per-blob endpoints instead. |
| `POST` | `/api/v1/credential-types/{credential_type_id}/retire` | Soft-delete: sets `retired_at = now()`, transitively un-assigns the type from every issuer. Already-issued credentials are unaffected. |

`POST /credential-types` couples row creation and initial schema upload in one exchange because a row without a schema cannot be persisted (`claim_schema NOT NULL`). Subsequent edits split structured-field updates from blob uploads, matching the persistence split.

### Per-blob upload / download

| Verb | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/credential-types/{credential_type_id}/schema` | Admin fetch of the JSON Schema document. Tenant-authenticated; the calling tenant must own the row. Returns the same byte-exact body the public endpoint serves. |
| `PUT` | `/api/v1/credential-types/{credential_type_id}/schema` | Replace the schema. Body validated as JSON Schema 2020-12 by attempting to compile a `jsonschema::Validator`; compilation failure is HTTP 400 with the validator's error message. On success the row is updated and both `claim_schema_fetched_at` and `updated_at` are bumped; other processes notice via the per-request `updated_at` freshness check on the next issuance against this type. |
| `GET` / `PUT` | `…/display` | OID4VCI `display` array. PUT validates that the body is a JSON array. Multi-locale arrays are accepted; the system performs no translation, no completeness check across locales, and no fallback synthesis — admins upload whatever locales they want, the wallet picks one per the OID4VCI locale-selection convention. |
| `GET` / `PUT` | `…/claims` | OID4VCI `claims` metadata. PUT validates that the body is a JSON object. |

### Public schema endpoint (verifier dereference)

Verifiers anywhere in the world need to dereference the `credentialSchema` URL embedded in issued credentials, with no relationship to the management surface. That dereference must be **unauthenticated**, but it should not punch a hole in the otherwise uniformly-authenticated `/api/v1/` namespace. The split:

| Verb | Path | Purpose |
|---|---|---|
| `GET` | `/schemas/{credential_type_id}` | Public, **unauthenticated** schema fetch. This is the URL embedded in issued credentials' `credentialSchema` field. Served by the `swiyu-issuer-oidcapi` binary (wallet/verifier-facing surface, alongside `/credential` and `/token`), not by the management API. Returns the document with `Content-Type: application/schema+json`. Cacheable. Authorisation predicate: "row exists and is not retired". |

The two GET endpoints return the same byte-exact body; the management-API GET adds tenant-auth so admins reading via tooling stay in the authenticated `/api/v1/` surface, while the public path is what every wallet-distributed credential references.

The schema document itself is not sensitive — it describes claim *shape*, not who holds credentials, and any holder presenting a credential already supplies the URL. `CredentialTypeId` is bs58 with ~80 bits of entropy, so the public path isn't enumerable.

### Assignment

| Verb | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/issuers/{issuer_id}/credential-types` | List credential types assigned to the named issuer. |
| `POST` | `/api/v1/issuers/{issuer_id}/credential-types/{credential_type_id}` | Assign the type to the issuer. The handler verifies the calling tenant owns both the issuer and the credential type (single SQL probe), then inserts the assignment row. Idempotent: a second call on an existing row is a no-op `200 OK`. |
| `DELETE` | `/api/v1/issuers/{issuer_id}/credential-types/{credential_type_id}` | Un-assign. Removes the assignment row; already-issued credentials are unaffected (per [`aspect-credential-type.md`](aspect-credential-type.md) § *Lifecycle*). Idempotent. |

Failure modes documented in the OpenAPI artefact: `404` (issuer or type unknown to the calling tenant), `409` only for genuinely conflicting state — the assign/un-assign verbs are idempotent and do not raise `409` on the "already in target state" path.

## Issuance flow integration

Validation at the `POST /api/v1/credential-offers` boundary (per [`impl-credential-management.md`](impl-credential-management.md)) gains three SQL probes ahead of claim validation:

1. The calling tenant owns the named issuer (`SELECT 1 FROM issuers WHERE id = $1 AND tenant_id = $caller_tenant`).
2. The calling tenant owns the named credential type, **and** returns its `updated_at` and `claim_schema` for the validator-cache freshness check and possible compile (`SELECT updated_at, claim_schema FROM credential_types WHERE id = $1 AND tenant_id = $caller_tenant AND retired_at IS NULL`).
3. The credential type is currently assigned to that issuer (`SELECT 1 FROM issuer_credential_types WHERE issuer_id = $1 AND credential_type_id = $2`).

Probes (1)–(3) are scoping errors; failure returns `404` (cross-tenant) or `409` (in-tenant but unassigned). Only after all three pass does the handler resolve the validator from `AppState.validators` (read-lock fast path if `entry.schema_updated_at == probe.updated_at`; otherwise compile from the `claim_schema` probe (2) already returned) and call `validator.validate(&claims)`. Validation failure returns `400` with the validator's structured error list.

The issued credential's `credentialSchema` URL is constructed as `{public_base_url}/schemas/{credential_type_id}` — the unauthenticated public endpoint described above. The authenticated `GET /api/v1/credential-types/{credential_type_id}/schema` returns the same byte-exact body for admins; the two paths serve the same document to different audiences.

## Domain-module hand-off

The `vct.rs` compile-time catalogue (per [`impl_domain.md`](impl_domain.md) § *Credential type catalogue*) is removed when this slice lands. References from `api_management::credential_offers`, `api_oidc::credential`, and `api_oidc::metadata` move to `state.credential_types` (the persistence-backed lookup) and `state.validators` (the compiled-validator cache).

The seeded dev credential type is created by an extension of the existing `tenant bootstrap-dev-from-env` flow (see [`impl-tenant-management.md`](impl-tenant-management.md)). The contributor's dev tenant arrives with one credential type and one assignment, replacing the role the compile-time catalogue played in the walking-skeleton.

## Tests

Tests follow the repo's existing layout conventions: `#[cfg(test)]` modules inline with the code under test for unit coverage; `swiyu-issuer/tests/` for cross-module integration coverage via `sqlx::test`. Shared fixtures (e.g. credential-type / assignment seed helpers, validator-cache builders, sample `claim_schema` documents) belong in **`test_support`** and are reused across this slice's tests and any other slice that needs them — no per-test duplication of seed code or sample documents.

- Unit tests in `domain/credential_type.rs` cover the `RevocationMode` enum round-trips, `try_retire` precondition (cannot retire a row already retired), and `try_update_structured` precondition (cannot edit a retired row).
- Unit tests in `state/validators.rs` cover lazy compile on first use, double-check insertion under contention, `updated_at`-driven re-compile on the next issuance after a schema change, and the broken-schema path (a credential type with a malformed `claim_schema` fails its first issuance with HTTP 500 but does not affect issuance of other types).
- Integration tests under `swiyu-issuer/tests/` driving full flows with a real Postgres pool (via `sqlx::test`), using `test_support` fixtures for tenant / issuer / credential-type seeding:
  - Create a credential type, assign it to an issuer, issue a credential through the OIDC flow.
  - Two tenants create rows with the same `vct` but different schemas; the validator cache distinguishes them; cross-tenant access returns `404`.
  - Retire a credential type with an active assignment: the assignment is removed, the OIDC metadata projection drops the entry, already-issued credentials remain valid.
  - `PUT …/schema` with an invalid JSON Schema returns `400` and does not update the row.
  - `PUT …/schema` with a stricter schema rejects subsequent issuance whose claims would have validated under the previous schema.
- Property-style test for the OID4VCI projection: every non-retired credential type assigned to an issuer appears exactly once in `credential_configurations_supported`, keyed by `credential_type_id`.

## Out of scope

- **Per-issuer overrides** of any credential-type property (display, schema, …). Out of scope per [`aspect-credential-type.md`](aspect-credential-type.md) § *Assignment to issuers*.
- **Schema-based validation of `display` / `claims` blob bodies.** OID4VCI defines both structures in prose without a canonical machine-readable schema artefact, so there is nothing authoritative to validate against. `PUT …/display` and `PUT …/claims` validate only the top-level shape (array / object); deeper structural checks are not pursued.
- **Per-credential-type variation of SWIYU-fixed protocol fields** (`format`, `signing_algorithm`, `cryptographic_binding_methods_supported`, `proof_types_supported`). These are SWIYU profile constants; if a future profile relaxes them, they become columns rather than constants. The aspect spec carries them as conceptual properties; the impl deliberately does not.
- **Background refresh** of `claim_schema_source_url`. The column is stored and exposed on read; no fetch loop pulls updates from the canonical source. Operators re-upload via `PUT …/schema` when an upstream schema revises.
- **Schema versioning.** `claim_schema_fetched_at` records when a document was last set, but there is no `claim_schema_version` column and no history of prior schema bodies. The aspect spec captures this under *Open questions — Edit semantics on a type with issued credentials*.
- **Bulk-assignment endpoints** (assign one type to many issuers in one call, or assign many types to one issuer). Single-credential-type assignment only; bulk lands when an operator asks.
- **Templating / standard-type propagation.** Bulk-publishing a "standard" credential type from a cantonal organisation into many tenants' rows is operational tooling, not a domain feature; out of scope per [`aspect-credential-type.md`](aspect-credential-type.md) § *Open questions*.
