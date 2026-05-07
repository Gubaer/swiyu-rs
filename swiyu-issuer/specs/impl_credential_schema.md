# Implementation: credential schema (v0.1.0)

This document captures concrete implementation decisions for credential schema management as of release v0.1.0. For the conceptual model and domain entities see [`aspect-domain.md`](aspect-domain.md). For the endpoint that consumes the schema see [`impl_api_management.md`](impl_api_management.md).

Status: preliminary; living document. Reflects the v0.1.0 walking-skeleton scope — one bundled schema validated at the request boundary, no DB-backed schema storage yet.

## Vocabulary recap

Two terms from [`aspect-domain.md`](aspect-domain.md) the rest of this document depends on.

**`vct`** — the SD-JWT VC type identifier. A URI in the credential's `vct` claim. Identifies *what kind* of credential is being issued.

**`CredentialSchema`** — the JSON Schema document that validates the *claims* of a credential of a given `vct`. **Not** a separate domain entity; stored as a document blob (`JSONB` column) on the `CredentialType` row. The relationship is 1:1 within a row.

## Long-term direction

Three layers, each answering a distinct question.

### Source of truth

For federal types (e.g. a national `ProofOfResidency`), the source of truth is a SWIYU-operated registry serving the JSON Schema (and, for SD-JWT VC, a Type Metadata document keyed by `vct`) at a canonical URL. Many issuers reference the same document.

The issuer is **not** the source of truth for federal schemas. It *is* the source of truth for issuer-private types — for example, the generic `urn:communal:local-residence-id` introduced in v0.1.0, which is authored on behalf of the participating communes (typically by the cantonal e-government organisation operating the issuer).

### Owned copy

Even when the source of truth is external, the issuer owns a copy. Reasons:

- Issuance must not fail because the registry is unreachable.
- We need a stable, byte-exact reference for what was in force at issuance time once schema versioning becomes real.
- Compiling a JSON Schema validator is not free; doing it at load time, not per request, requires a stable in-process copy.

The owned copy lives on the `credential_types` row as a `JSONB` `claim_schema` column, with an optional `claim_schema_source_url` column recording where the canonical copy was fetched from. `claim_schema_source_url` is `NULL` for issuer-private schemas with no external source of truth. A `claim_schema_fetched_at` timestamp accompanies the URL when one is set.

The earlier draft of this document proposed a separate `credential_schemas` table justified by cross-issuer schema sharing for federal standards — many communes referencing one row for a shared `ProofOfResidency` schema. That justification was reversed once the tenant ownership model made it explicit that schemas don't cross the tenant boundary any more than `CredentialType` rows do. See [`aspect-credential-type.md`](aspect-credential-type.md) for the full reasoning.

Why a column on `credential_types` rather than a separate table:

- No cross-tenant sharing of either `CredentialType` or its schema, so a separate row earns no reuse to amortise.
- Schemas are small (single KB to tens of KB). One per `CredentialType` row at the scale described in [`aspect-multi-tenancy.md`](aspect-multi-tenancy.md) (~500 issuers, similar order of types) is bounded and cheap.
- One fewer entity, no FK to maintain, no separate cache abstraction. The `JSONB` column *is* the cache.
- Schema versioning, when it eventually arrives, becomes either an embedded `version` field in the schema document or a `claim_schema_version` column on `credential_types`, rather than a separate versioned-row dance.

Where the column shape grows additional siblings (e.g. SD-JWT VC Type Metadata, which is *not* the JSON Schema validating claims), that metadata sits alongside `claim_schema` as another `JSONB` column on the same row, not in a separate table.

### Compiled validator

A compiled `jsonschema::Validator` per credential type, kept in `AppState` behind an `Arc<HashMap<CredentialTypeId, Arc<Validator>>>`. Built at startup from the `claim_schema` column on `credential_types`; rebuilt when a row's schema column changes. The handler resolves the credential type from the offer's `(tenant_id, credential_type_id)` pair, then does `validator.validate(claims)`. No parsing or compilation in the request path.

Keying by `CredentialTypeId` rather than by `vct` matters under the tenant ownership model: two tenants can carry rows with the same `vct` value but different schema documents, and the validator cache must distinguish them.

### Refresh model (out of scope for v0.1.0)

For the eventual production shape:

- A background task — or an admin-API endpoint — fetches from `claim_schema_source_url`, compares to the stored document, writes the new document into the `claim_schema` column on the relevant `credential_types` row.
- Validators in `AppState` are rebuilt on `credential_types` row change. Postgres `LISTEN`/`NOTIFY` is the natural trigger and is already on the menu in [`aspect-technology.md`](aspect-technology.md).
- Validation always uses the *current* compiled validator. Once schema versioning is real, the issued-credential record stores the schema version it was issued under.

## v0.1.0 shape

The minimum that lets the management API validate `urn:communal:local-residence-id` claims today, without committing to the schemas table or the fetch loop.

### One bundled schema

`swiyu-issuer/schemas/` (top-level in the crate, alongside `migrations/`):

- `urn_communal_local-residence-id.json` — JSON Schema 2020-12. Filename is the `vct` value with `:` replaced by `_`. Deterministic and reversible.

The schema validates the claim shape for the **generic communal local residence ID** — a credential entitling the holder to discounts and services available to residents of a Swiss commune. The asserting commune is carried as claims (`commune_bfs`, `commune_name`) rather than encoded in the `vct`. This allows a single issuer (typically an e-government organisation operating on behalf of multiple communes) to issue under one `vct` for many communes, without per-commune schemas or per-commune issuer DIDs.

The required application claims are:

- `family_name`, `given_name`, `birth_date` — identity binding, matched against the resident register at issuance and against the e-ID at verification.
- `commune_bfs` — BFS number of the asserting commune. Integer.
- `commune_name` — human-readable commune name; includes a canton suffix where ambiguous (e.g. "Buchs SG").
- `valid_until` — calendar-date end of the entitlement; independent of the JWT `exp` claim.

The actual schema is in [`swiyu-issuer/schemas/urn_communal_local-residence-id.json`](../schemas/urn_communal_local-residence-id.json); this spec records the design intent, not the canonical claim list.

### Loading at startup

`api_management::schemas` submodule:

- Embeds bundled schemas at compile time via `include_str!`.
- Exposes a single `load() -> HashMap<Vct, Arc<Validator>>` called once from `AppState::new`.
- Adding a schema in v0.1.0 means appending one tuple to a constant array:

```rust
const BUNDLED_SCHEMAS: &[(&str, &str)] = &[(
    "urn:communal:local-residence-id",
    include_str!("../../../schemas/urn_communal_local-residence-id.json"),
)];
```

A manifest file (`schemas/index.json`) is unnecessary at one schema; revisit when bundled schemas grow past a small handful.

### Validation in the handler

Before insert, the credential-offer handler does:

```text
let validator = state.schemas.get(&payload.vct)
    .ok_or(ApiError::UnknownVct { vct: payload.vct.clone() })?;
validator.validate(&payload.claims)
    .map_err(|errs| ApiError::ClaimsValidationFailed { errors: errs.collect() })?;
```

Both new error variants map to HTTP 400. See [`impl_api_management.md`](impl_api_management.md) for the full `ApiError` table.

### `vct` as a URI

The `vct` is treated as an opaque URI string at the API and persistence layers. The form `urn:communal:local-residence-id` introduced in v0.1.0:

- Uses the `urn` URI scheme (RFC 8141). The `urn` scheme is IANA-registered, in contrast to the earlier draft `vct:` scheme.
- Uses `communal` as the URN namespace identifier. **Not a registered NID** (see *Open* for whether to formalise this).
- Uses a kebab-case namespace-specific string for the credential kind (`local-residence-id`).
- Encodes **no commune-specific information** in the `vct` itself. The asserting commune is carried as `commune_bfs` and `commune_name` claims, so a single issuer (typically an e-government organisation operating on behalf of multiple communes) can use one `vct` for many communes.

Federal types remain free to use whichever URI form SWIYU defines for them (likely an HTTPS URL pointing at the registry). The application does no scheme inspection — `vct` is a string key.

### Schema `$id` as a URI

JSON Schema's `$id` is also a URI. We use a URN form parallel to the `vct` rather than an HTTPS URL: schemas are bundled or DB-resident, not served at a public URL, and an HTTPS `$id` would falsely imply fetchability.

The convention for `$id`:

```
urn:<vct-nss>:schema:<version>
```

For the v0.1.0 schema:

- `vct`: `urn:communal:local-residence-id`
- `$id`: `urn:communal:local-residence-id:schema:v1`

Keeping `vct` and `$id` distinct matters: the `vct` identifies *what kind of credential this is*, the `$id` identifies *this particular schema document version*. They are 1:1 in v0.1.0 but conceptually different, and a future `v2` of the schema will need a distinct `$id`.

## Cargo dependencies

Added to `swiyu-issuer/Cargo.toml`:

```toml
jsonschema = "0.30"
```

Decided over `boon` on the strength of user base and active maintenance. JSON Schema 2020-12 supported.

## Conventions established

- **`vct` is the wire and persistence field name.** No `credential_type` anywhere in code, schema, or JSON. `CredentialType` remains the *domain entity* per [`aspect-domain.md`](aspect-domain.md); `vct` is its identifier field and the wire-level shorthand.
- **Schemas are deployment artifacts, not code.** Top-level `swiyu-issuer/schemas/` directory holds JSON files; Rust modules embed them via `include_str!`.
- **Compile-time embedding at v0.1.0.** No runtime file IO, no config-file lookup. Adding a schema means a code change. Acceptable while the schema list is small and changes via PR.
- **Validators are immutable in process.** Rebuild on schema change is a future feature; v0.1.0 holds them static for the lifetime of the process.

## What is deliberately not in v0.1.0

- The `credential_types` table (with its `claim_schema` `JSONB` column and optional `claim_schema_source_url`). Waits for the slice that introduces real type configuration.
- Fetching from a canonical SWIYU registry URL. Bundled file is the stand-in.
- Schema versioning. One file, one version, no `version` column anywhere yet.
- SD-JWT VC Type Metadata as a first-class concept. The bundled schema validates *claims* only; protocol-level type metadata (display, claim selection, sd-jwt-specific knobs) is the `CredentialType` slice's problem.
- Background refresh task / `LISTEN`/`NOTIFY` rebuild of validators. Static at startup is fine.
- Per-tenant schema overrides. Federal schemas are federal; proprietary schemas are owned by their issuing commune and shipped in this repo until a real authoring flow exists.

## Open

- **Final claim list for `urn:communal:local-residence-id`.** Settled with the cantonal e-government and pilot communes; the schema in `schemas/` is a working draft.
- **URN namespace registration.** `communal` is not an IANA- registered URN NID. Strict RFC 8141 conformance would require either registration or an `urn:x-…` form (the latter is increasingly an anti-pattern). Lean: keep the unregistered NID through pre-production maturity; revisit before going public.
- **Issuer authority for `commune_bfs`.** When the issuer is an e-government organisation rather than the commune itself, the verifier must trust that the issuer is authorised to assert residency for the commune named in `commune_bfs`. The trust framework for this delegation (issuer metadata, Trust Statement scope) is out of v0.1.0 scope but flagged here because the generic `vct` makes the question explicit.
- **Filename convention vs. manifest.** `:` → `_` filename mapping is deterministic but ugly. Revisit when the bundled list grows past a handful, at which point a `schemas/index.json` mapping `vct` → filename is the natural step.
- **DB representation when schemas move out of the bundle.** Whether the SD-JWT VC Type Metadata document (separate from the JSON Schema validating claims) sits alongside `claim_schema` as another `JSONB` column on `credential_types`, or earns its own row in some related table. Triggered by the slice that introduces `credential_types`.
