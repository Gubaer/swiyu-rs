# Plan: Credential Type

Action plan to implement the credential-type concepts in [`aspect-credential-type.md`](aspect-credential-type.md) and the implementation design in [`impl-credential-type.md`](impl-credential-type.md). Each step lands one concrete artifact or one operational change; each step compiles, passes its tests, and can be committed before the next one starts.

## Goals

- Replace the compile-time `domain/vct.rs` catalogue with the DB-backed `CredentialType` aggregate, `credential_types` table, and `issuer_credential_types` assignment table described in [`impl-credential-type.md`](impl-credential-type.md).
- Land the tenant-admin management API for credential-type CRUD, per-blob upload/download (`claim_schema`, `display`, `claims`), and assignment to issuers.
- Surface the per-credential-type JSON Schema document at a public verifier-dereference endpoint on the OIDC public surface.
- Re-route the OID4VCI metadata projection (`credential_configurations_supported`) and the issuance handler's claim validation from the compile-time catalogue to the DB rows.
- Seed the contributor dev tenant with one credential type and one assignment so the dev loop reaches the same fully-issuable state it does today, with no compile-time fallback needed.

## Non-goals

- Per-issuer overrides of any credential-type property (out of scope per [`impl-credential-type.md`](impl-credential-type.md) § *Out of scope*).
- Schema versioning, multi-format credential types, bulk-assignment endpoints, templating, schema-based validation of `display` / `claims` blobs. All deferred per the impl doc's *Out of scope* list.

## Deliverables

1. **Migrations** for `credential_types` and `issuer_credential_types` (SQL files only; no Rust changes).
2. **Domain layer:** `domain/credential_type.rs` (`CredentialType`, `CredentialTypeId`, `RevocationMode`), `domain/issuer_credential_type.rs` (`IssuerCredentialTypeAssignment`), wired into `domain/mod.rs` and `domain/ids.rs`.
3. **Persistence layer:** `persistence/credential_types.rs` (CRUD + per-blob accessors), `persistence/issuer_credential_types.rs` (assign / unassign / list).
4. **Validator cache** in `state/validators.rs` — the `Arc<RwLock<HashMap<CredentialTypeId, ValidatorCacheEntry>>>` with lazy compile-on-first-use, double-checked locking, and per-request `updated_at` freshness check.
5. **Management API handlers** in `api_management/credential_types.rs` for credential-type CRUD, per-blob upload/download, and assignment, plus the OpenAPI updates in `openapi-mgmt.yml`.
6. **Public schema endpoint** in `api_oidc/schemas.rs` serving `GET /schemas/{credential_type_id}` (unauthenticated).
7. **OID4VCI metadata projection** in `api_oidc/metadata.rs` updated to project from `credential_types × issuer_credential_types` rows.
8. **Issuance handler** in `api_oidc/credential.rs` extended with the three scoping probes and the validator-cache lookup.
9. **Tenant bootstrap extension** in the `swiyu-issuer-cli` binary (i.e. the `cli` module of the `swiyu-issuer` crate, with the `src/bin/swiyu-issuer-cli.rs` entry point) so `tenant bootstrap-dev-from-env` seeds one credential type and one assignment for the dev tenant.
10. **Removal of `domain/vct.rs`** and the few references to it across `api_management`, `api_oidc`, and the bundled `schemas/` directory.
11. **Fixtures in `swiyu-issuer/src/test_support/`** (the existing in-crate test-support module, gated by the `test-support` Cargo feature) for credential-type and assignment seeding, reused across this slice's integration tests.

## File layout

```
swiyu-issuer/
├── migrations/
│   ├── NNNN_create_credential_types.sql                — new
│   └── NNNN_create_issuer_credential_types.sql         — new
├── src/
│   ├── domain/
│   │   ├── credential_type.rs                          — new
│   │   ├── issuer_credential_type.rs                   — new
│   │   ├── ids.rs                                      — extended (CredentialTypeId prefix `ctype`)
│   │   ├── mod.rs                                      — extended (re-exports)
│   │   └── vct.rs                                      — REMOVED in final step
│   ├── persistence/
│   │   ├── credential_types.rs                         — new
│   │   ├── issuer_credential_types.rs                  — new
│   │   └── mod.rs                                      — extended
│   ├── state/
│   │   ├── validators.rs                               — new
│   │   └── mod.rs                                      — extended (AppState gains `validators` field)
│   ├── api_management/
│   │   ├── credential_types.rs                         — new (CRUD + per-blob + assignment handlers)
│   │   └── mod.rs                                      — extended (route registration)
│   ├── api_oidc/
│   │   ├── schemas.rs                                  — new (public GET /schemas/{id})
│   │   ├── metadata.rs                                 — extended (project from credential_types × assignments)
│   │   ├── credential.rs                               — extended (probes + validator lookup)
│   │   └── mod.rs                                      — extended (route registration)
│   ├── cli/                                            — extended: bootstrap-dev-from-env seeds credential type + assignment
│   └── test_support/                                   — extended with credential-type & assignment fixtures (gated by the `test-support` Cargo feature)
├── tests/                                              — new integration tests per step
├── openapi-mgmt.yml                                    — extended with credential-type CRUD, per-blob, and assignment paths
├── openapi-oidc.yml                                    — extended with the public GET /schemas/{id} path
└── schemas/                                            — REMOVED in final step (bundled JSON Schema goes away)

swiyu-core/                                             — new submodule with the four OID4VCI profile constants (format / signing alg / binding methods / proof types)
```

## Sequencing

The plan follows an **additive-then-cutover-then-cleanup** pattern:

- Steps 1–4 add the DB tables, domain types, persistence layer, and validator cache. No existing code calls them; the compile-time `vct.rs` catalogue still feeds the OID4VCI projection and the issuance handler.
- Steps 5–8 add the management API surface, the public schema endpoint, and the assignment endpoints. Integration tests seed credential-type rows directly via `test_support`; the OIDC paths still use the old catalogue.
- Step 9 extends `tenant bootstrap-dev-from-env` so a contributor's dev tenant has a credential-type row in the DB at startup.
- Steps 10–11 are the cutover: the metadata projection switches to the DB, then the issuance handler does. After step 11, no production code path reads `vct.rs`.
- Step 12 is cleanup: delete `vct.rs` and the bundled `schemas/` directory.

Each step compiles on its own and passes its own tests; the cutover steps depend on step 9 having seeded the dev tenant, so existing tests keep passing after the catalogue stops being consulted.

## Implementation steps

1. **Migrations for `credential_types` and `issuer_credential_types`.** Add `migrations/NNNN_create_credential_types.sql` and `migrations/NNNN_create_issuer_credential_types.sql` with the DDL from [`impl-credential-type.md`](impl-credential-type.md) § *Persistence schema*. SQL only; no Rust changes; `sqlx migrate run` succeeds on a fresh database. Commit point: `Add credential_types and issuer_credential_types migrations`.

2. **Domain types: `CredentialType`, `CredentialTypeId`, `RevocationMode`.** Add `domain/credential_type.rs` with the struct + enum from [`impl-credential-type.md`](impl-credential-type.md) § *Domain types*; add `domain/issuer_credential_type.rs` with `IssuerCredentialTypeAssignment`. Extend `domain/ids.rs` with `CredentialTypeId` (bs58, prefix `ctype`). Wire re-exports in `domain/mod.rs`. Inline `#[cfg(test)]` modules cover `RevocationMode` enum round-trips, `CredentialTypeId` parse/serialize, and the aggregate's `try_retire` precondition. No callers yet; `cargo build` succeeds, `cargo test` passes the new unit tests. Commit point: `Add CredentialType + IssuerCredentialTypeAssignment domain types`.

3. **Persistence: `credential_types` CRUD and per-blob accessors.** Add `persistence/credential_types.rs` with `insert`, `find`, `list`, `update_structured`, `update_blob` (one per blob column), `retire` (sets `retired_at` + `DELETE FROM issuer_credential_types` in the same transaction). Add `persistence/issuer_credential_types.rs` with `assign`, `unassign`, `list_by_issuer`, `list_by_credential_type`. Wire `persistence/mod.rs`. Add `test_support` fixtures `seed_credential_type`, `seed_assignment` (shared, reusable). Integration tests via `sqlx::test`: round-trip insert/find, list, update, retire (verify cascade), assign/unassign, cross-tenant isolation. Commit point: `Add persistence for credential_types and issuer_credential_types`.

4. **Validator cache in `AppState`.** Add `state/validators.rs` with `ValidatorCacheEntry { validator: Arc<Validator>, schema_updated_at: DateTime<Utc> }` and a thin API: `get_or_compile(id, claim_schema, updated_at) -> Result<Arc<Validator>, _>` that does the read-lock fast path + write-lock double-check + compile flow from [`impl-credential-type.md`](impl-credential-type.md) § *Claim-schema storage and validator cache*. Extend `AppState` to carry the `Arc<RwLock<HashMap<CredentialTypeId, ValidatorCacheEntry>>>` field (empty at startup). Unit tests cover lazy compile on first use, double-check insertion under contention, `updated_at`-driven re-compile, broken-schema path (compile failure surfaces as a typed error). No callers yet. Commit point: `Add lazy validator cache in AppState`.

5. **Management API: credential-type CRUD endpoints.** Add `api_management/credential_types.rs` with `POST /credential-types`, `GET /credential-types`, `GET /credential-types/{id}`, `PATCH /credential-types/{id}`, `POST /credential-types/{id}/retire`. The `POST` handler accepts the full structured-field set plus the `claim_schema` body and rejects an invalid schema by attempting a `jsonschema::Validator` compile. Update `openapi-mgmt.yml` with the new paths and error model. Integration tests use `test_support` to seed tenants and assert: create → fetch → list → patch → retire (and that retire transitively un-assigns). Commit point: `Add management API for credential-type CRUD`.

6. **Management API: per-blob upload/download endpoints.** Add `GET` / `PUT` handlers for `…/schema`, `…/display`, `…/claims` per the table in [`impl-credential-type.md`](impl-credential-type.md) § *Per-blob upload / download*. `PUT …/schema` compiles the body via `jsonschema::Validator::new` before writing and rejects with `400` on failure; on success the row's `claim_schema_fetched_at` and `updated_at` are both bumped. `PUT …/display` and `PUT …/claims` validate only the top-level shape (array / object). The authenticated admin `GET …/schema` returns the document with `Content-Type: application/schema+json`. Update `openapi-mgmt.yml` with the six new paths (GET/PUT × schema / display / claims), request/response shapes, and the `400` invalid-schema error. Integration tests: PUT happy path, PUT invalid-schema rejection, PUT-then-GET round-trip, cross-tenant `404`. Commit point: `Add per-blob upload/download endpoints for credential-type`.

7. **Management API: assignment endpoints.** Add `POST` / `DELETE /api/v1/issuers/{issuer_id}/credential-types/{credential_type_id}` and `GET /api/v1/issuers/{issuer_id}/credential-types`. The assignment handler performs the *(tenant owns issuer) AND (tenant owns credential type)* check in one SQL probe before inserting. Idempotent: second assign call on an existing row returns `200 OK`. Update `openapi-mgmt.yml` with the three assignment paths, the idempotent `200 OK` semantics, and the `404` (issuer or type unknown to the calling tenant) failure mode. Integration tests cover assign, idempotent re-assign, un-assign, idempotent re-un-assign, cross-tenant `404`, list-by-issuer. Commit point: `Add credential-type assignment endpoints`.

8. **Public schema endpoint on `swiyu-issuer-oidcapi`.** Add `api_oidc/schemas.rs` with `GET /schemas/{credential_type_id}` — unauthenticated, predicate "row exists and is not retired", `Content-Type: application/schema+json`, cacheable. Wire the route in the OIDC binary's router. Update `openapi-oidc.yml` with the new path, the `application/schema+json` response shape, and `404` for unknown-or-retired credential types. Integration tests cover: anonymous GET returns the schema, retired credential type returns `404`, body is byte-identical to the management-API admin GET. Commit point: `Add public schema endpoint on OIDC binary`.

9. **Extend `tenant bootstrap-dev-from-env` to seed one credential type + assignment.** In the `cli` module of `swiyu-issuer` (the bootstrap flow invoked by the `swiyu-issuer-cli` binary), after the dev tenant + issuer are created/synced, insert a default **dummy** credential type with `vct = "urn:dummy:dummy-credential"` and a minimal inline JSON Schema accepting two required string claims, `first_name` and `last_name`, then assign it to the dev issuer. The dummy `vct` and schema are obvious-non-production placeholders so a contributor's dev tenant has *something* issuable end-to-end; operators create real credential types via the management API. `--force` overwrites the row's structured fields and re-uploads the schema; without `--force` an existing row is left untouched. Integration test: bootstrap on an empty DB, observe one credential-type row and one assignment row; bootstrap with `--force` after an edit, observe the row is rewritten. Commit point: `Extend tenant bootstrap-dev-from-env to seed dummy credential type and assignment`.

10. **Cutover: OID4VCI metadata projection from DB.** Two sub-actions, landed in one commit so the projection compiles against the new constants:
    1. Add a new submodule in `swiyu-core` (e.g. `oid4vci`, alongside the existing `statuslist`) exporting the four SWIYU-fixed values: the format identifier (`"vc+sd-jwt"`), the credential signing algorithm (`"ES256"`), the cryptographic binding methods supported, and the proof types supported. These belong in `swiyu-core` because they describe the SWIYU profile itself, not the issuer's implementation — any future verifier or test crate consuming SWIYU profile facts will read them from the same place.
    2. Update `api_oidc/metadata.rs` to project `credential_configurations_supported` from the joined `credential_types × issuer_credential_types` rows per [`impl-credential-type.md`](impl-credential-type.md) § *OID4VCI metadata projection*, inlining the four SWIYU profile values from the new `swiyu-core` submodule into every entry.

    Existing metadata-projection tests pass against the dev-seeded credential type. The compile-time `vct.rs` catalogue is **still consulted by the issuance handler** at this step — it is not yet removed. Commit point: `Project OID4VCI metadata from credential_types and assignments`.

11. **Cutover: issuance handler from DB.** Extend the `POST /api/v1/credential-offers` handler in `api_management::credential_offers` (and the OID4VCI `/credential` handler in `api_oidc::credential`) per [`impl-credential-type.md`](impl-credential-type.md) § *Issuance flow integration*: probes (1)–(3) in order, then validator-cache lookup with the read-lock fast path + compile-on-miss. The `claim_schema` returned by probe (2) is what gets compiled on a cache miss, so no extra DB round trip. Existing issuance integration tests pass against the dev-seeded credential type; the `vct.rs` catalogue is no longer consulted by either handler. Commit point: `Route issuance through DB-backed credential types`.

12. **Cleanup: remove `domain/vct.rs` and the bundled `schemas/` directory.** Delete `swiyu-issuer/src/domain/vct.rs` and its `include_str!` references. Delete `swiyu-issuer/schemas/` — it was only consumed by the now-deleted catalogue's `include_str!`; the dev bootstrap from step 9 seeds its own inline dummy schema and does not depend on this directory. Remove the entry under [`impl_domain.md`](impl_domain.md) § *Credential type catalogue* pointing at `impl-credential-type.md` for the now-replaced subsystem, and update any remaining cross-references in `impl_api_management.md` that describe the catalogue rather than the DB-backed cache. Verify with `cargo build && cargo test` that no compile-time-catalogue path remains. Commit point: `Remove vct.rs catalogue and bundled schemas`.

## Validation steps

Split by who is expected to run what.

**Run by the agent after every edit, per `CLAUDE.md`:**

- `cargo fmt --check && cargo clippy -- -D warnings` clean. Non-negotiable; gates the commit point at the end of every step.

**Run by the user (or CI) — the agent does not execute `cargo build` / `cargo test` / `cargo doc` or `docker compose`:**

- `sqlx migrate run` succeeds against a fresh database after step 1.
- After step 4, `cargo test -p swiyu-issuer state::validators` covers lazy compile, double-check, broken-schema, and `updated_at` re-compile.
- After steps 5–8, the management-API and public-schema integration tests pass via `sqlx::test` against a real Postgres pool, using `test_support` fixtures for seeding (no per-test duplicate seed code).
- After step 9, running `docker compose up -d` and waiting for `bootstrap-dev-tenant` to finish results in exactly one `credential_types` row and one `issuer_credential_types` row for the dev tenant.
- After step 10, hitting `GET /.well-known/openid-credential-issuer` on the dev OIDC binary returns `credential_configurations_supported` with the dev type's `credential_type_id` as the key and the SWIYU profile constants inlined for the four fixed protocol fields.
- After step 11, an end-to-end credential offer + issuance round-trip succeeds with the dev seed alone — no compile-time catalogue consulted (verified by deleting `domain/vct.rs` *temporarily* and confirming the build still succeeds before reverting; step 12 is the permanent removal).
- After step 12, `grep -r "vct::CATALOGUE\|domain::vct" swiyu-issuer/src` returns no matches; `swiyu-issuer/schemas/` is gone; the bundled-schema `include_str!` references are gone.

## Decided

The following are locked in by [`impl-credential-type.md`](impl-credential-type.md) (resolved during its review pass; recorded here so the plan does not re-litigate them):

- **`CredentialTypeId` shape:** bs58 newtype with prefix `ctype`, matching the rest of the codebase.
- **Validator cache:** `Arc<RwLock<HashMap<CredentialTypeId, ValidatorCacheEntry>>>`, lazy on first use, per-request `updated_at` freshness check. No Postgres `LISTEN`/`NOTIFY`, no startup pre-compile.
- **Schema endpoint surface split:** authenticated admin `GET /api/v1/credential-types/{id}/schema` on `swiyu-issuer-mgmtapi`; unauthenticated public `GET /schemas/{id}` on `swiyu-issuer-oidcapi`. Both return the same byte-exact document.
- **`default_validity_duration`:** required at credential-type creation; no application-level fallback at issuance.
- **`revocation_mode`:** enforced from day one (the lifecycle handlers reject mismatched verbs with HTTP 409).
- **Locale subset:** management API accepts multi-locale `display` arrays; system performs no translation, no completeness check, no fallback synthesis.
- **Retire semantics:** soft-delete the credential type (`retired_at`), hard-delete its assignment rows in the same transaction. Already-issued credentials are unaffected.
- **`credential_offers.vct` / `issued_credentials.vct`:** stay as opaque strings, not foreign keys.
- **SWIYU-fixed protocol fields** (`format`, `signing_algorithm`, `cryptographic_binding_methods_supported`, `proof_types_supported`): not carried as columns; sourced from `swiyu-core` profile constants at projection time.

## Follow-up work

Captured during implementation; not blocking the plan's commit points but tracked here so the deferral is explicit.

- ~~**`POST /api/v1/issuers/{id}/credential-offers` DTO migration from `vct` to `credential_type_id`.**~~ **Done.** `CreateCredentialOfferRequest` now takes `credential_type_id`; the handler resolves via `find_by_id_for_tenant` and stamps both `credential_type_id` and `vct` onto the offer row (new nullable `credential_offers.credential_type_id` column, no FK per *Decided*). `openapi-mgmt.yml` updated. Legacy offer rows read as `None` and are rejected at issuance.

- ~~**Per-credential-type validity in the OID4VCI `/credential` handler.**~~ **Done.** `CREDENTIAL_VALIDITY_DAYS` deleted; `api_oidc::credential` now looks up the credential type via `offer.credential_type_id`, uses `default_validity_duration` for both the SD-JWT VC `exp` claim and the `issued_credentials.expires_at` column. Retired types are accepted (retirement does not invalidate an in-flight redemption); offers with `credential_type_id = None` (legacy pre-migration rows) fail with an internal error.

- **End-to-end smoke examples target a vct the dev tenant no longer seeds.** `swiyu-issuer/examples/credential_lifecycle_smoke.rs` and `swiyu-issuer/examples/credential_status_lifecycle_smoke.rs` both hard-code `FIXTURE_VCT = "urn:communal:local-residence-id"` — the catalogue's lone entry. After step 9 the dev tenant is seeded with `urn:dummy:dummy-credential`; after step 11 the catalogue is no longer consulted; after step 12 the catalogue source and bundled schema are gone; after the DTO migration above the request body's `vct` field is also gone (now `credential_type_id`). The smokes are therefore broken at JSON deserialization, not just at probe (2). Restoring them needs three changes together: switch the POST body field name to `credential_type_id`, discover the dev tenant's assigned credential type via `GET /api/v1/issuers/{id}/credential-types` (which yields the bs58 id directly), and drop the `FIXTURE_VCT` literal — the wallet still receives `vct` in the issued credential, but the BA-facing smoke no longer needs to spell it.
