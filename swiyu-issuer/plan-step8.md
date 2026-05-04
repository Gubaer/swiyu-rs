# Step 8 — HTTP endpoints (sub-plan)

Companion to `plan.md`. Step 8 wires the issuer-management saga into the public HTTP surface.

## Goal

Four endpoints on the existing `swiyu-issuer/src/api_management/` router, all tenant-scoped via the existing `TenantContext` extractor:

- `POST /api/v1/issuers` — submit a `CreateIssuer` task.
- `GET  /api/v1/issuers` — list the tenant's issuers (cursor-paginated).
- `GET  /api/v1/issuers/{id}` — fetch a single issuer.
- `GET  /api/v1/operation-tasks/{id}` — poll task status.

## Decisions (recommended)

- **POST returns `{task_id, issuer_id}`.** `IssuerId` is generated server-side at submit time and pinned in `task.result_issuer_id` (so the worker's `persist_issuer` step can read it). The BA gets both back from the create call: `task_id` to poll the saga's status, `issuer_id` to fetch the issuer once it exists. `/issuers/{id}` returns 404 while the task is still in progress — standard "not ready yet" semantics for a known-but-not-yet-materialised resource.
- **Cursor-based pagination on list**, mirroring `api_management::credential_offers::list`. Same `ListPageQuery { cursor, limit }`, same encoded cursor format, same `{ items, next_cursor }` envelope.
- **Issuer JSON shape: BA-facing minimum.** Surface `id`, `did`, `state`, `description`, `display_name`. Deliberately *not* exposed: `tenant_id` (the BA already knows their tenant — it's bound to the API token, so echoing it adds noise without information); the three `KeyPairId`s for the `Authorized` / `Authentication` / `Assertion` roles (internal SigningEngine handles the BA cannot act on, so they would be implementation leak); and the legacy fields `signing_key_id`, `logo_uri`, `locale` (ship out with the OIDC migration). The seeded dev issuer (which carries the legacy fields and lacks `state`) is filtered out of the list and returns 404 from `/issuers/{seeded_id}` since its `state` is `None`.
- **Task polling response: full task minus internals.** Surface `id`, `task_type`, `state`, `step`, `attempts`, `next_attempt_at`, `error_code`, `error_message`, `created_at`, `updated_at`, `completed_at`. Omit `input` (BA already has it), `state_data` (internal saga progress, not BA-facing), and `result_issuer_id` (the BA already received `issuer_id` in the response to `POST /api/v1/issuers`, so echoing it on every poll adds nothing).
- **Tenant scoping on every handler** via `TenantContext` extractor; cross-tenant or unknown returns 404.
- **Validation in the POST handler.** `description` and `display_name` must be non-empty after trim, max 255 chars each (matches typical TEXT-column reasonable bound). Stricter rules can land later.

## Substeps

Each substep is a small green-build commit.

- [x] **8.1 — `POST /api/v1/issuers`.** New module `api_management::issuers` (or extend `mod.rs`'s router). Handler signature `async fn create(state, tenant_context, Json(body): Json<CreateIssuerSubmission>)`. Body shape matches `CreateIssuerInput` (description + display_name). Handler: validate → generate `IssuerId` + `TaskId` → build `OperationTask` with `task_type = CreateIssuer`, `state = Pending`, `step = None`, `result_issuer_id = Some(issuer_id)`, `input = serde_json::to_value(body)?` → insert. Returns `201 Created` with `{ task_id, issuer_id }`. Integration tests: happy path (asserts row in `operation_tasks` with the expected shape and that the response carries both ids), validation failures (empty description, missing field, oversized).
- [x] **8.2 — `GET /api/v1/issuers/{id}`.** Handler loads issuer by id (tenant-scoped; cross-tenant or absent → 404), serialises to the target-shape DTO, returns 200. Integration tests: happy path, 404 for unknown id, 404 for cross-tenant id, filters out the seeded legacy issuer (state == None → 404).
- [x] **8.3 — `GET /api/v1/issuers`.** New persistence helper `persistence::issuers::list(conn, &tenant_id, ListPageQuery)` mirroring the credential-offers list. Handler reads `Query<ListIssuersQuery>`, calls list, wraps in cursor envelope. Integration tests: empty list, single page, multi-page with cursor advancement, cross-tenant isolation, legacy issuer filtered out.
- [x] **8.4 — `GET /api/v1/operation-tasks/{id}`.** New persistence helper or reuse `operation_tasks::find_by_id` (already takes `&TenantId`). Handler returns the task DTO. Integration tests: happy path, 404 for unknown id, 404 for cross-tenant id, completed task surfaces terminal `state` and `completed_at`.

## Open questions

- **Pre-allocated `result_issuer_id` and the seeded dev tenant.** New tasks against the seeded dev tenant produce DIDs that get published to the registry (or fail Terminal because partner_id is the placeholder UUID). Tests using the seeded tenant rely on this; v1 docs should call out that the seeded tenant needs a real partner-id before the worker's allocate_did call succeeds.

## Resolved decisions

- **Submission body**: separate `CreateIssuerSubmission` DTO in `api_management::dto`, converting `Into<CreateIssuerInput>` for the task input. Keeps the wire shape free to diverge later (e.g. when `did_method` returns) without churning the worker DTO.
- **`description` / `display_name` length cap**: 255 chars after trim, both fields. API hygiene only; columns stay TEXT.
- **List output includes both `Active` and `Deactivated`** issuers in v1, exposing `state` on the wire. Filtering (e.g. `?state=active`) lands when needed.

## Test strategy

Per endpoint:

- 1 happy-path integration test against a real Postgres pool (`sqlx::test`).
- 1–2 negative tests (404, validation error, cross-tenant).

For 8.1 specifically, the test asserts the resulting `operation_tasks` row has `result_issuer_id` set, `state = Pending`, `step = None`, and `input` round-trips back to the submitted JSON. Confirms 7.6e's prerequisite that `result_issuer_id` is set at submit time.

End-to-end "BA submits → worker drains → `/issuers/{id}` returns the issuer" is covered by the wiremock e2e tests + endpoint integration tests in combination, not via a single mega-test.

## Out of scope

- `PATCH /api/v1/issuers/{id}` (any update flow beyond rotate/deactivate, which are their own task types).
- `DELETE /api/v1/issuers/{id}` (deactivate is the v1 deletion path).
- Operator endpoints for tasks (cancel, force-retry).
- OpenAPI / Swagger schema generation.
