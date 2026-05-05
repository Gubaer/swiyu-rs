# Step 9 — Deactivate issuer (sub-plan)

Companion to `plan.md`. Step 9 adds the `deactivate_issuer` lifecycle operation, end-to-end: domain task type, worker saga, persistence helpers, and HTTP endpoint. The aspect-level choreography is fixed by `specs/aspect-issuer.md` §Deactivate; this plan is the implementation pass.

## Goal

One new endpoint plus the supporting saga:

- `POST /api/v1/issuers/{issuer_id}/deactivate` — submit a `DeactivateIssuer` task. Tenant-scoped via `TenantContext`.
- New `TaskType::DeactivateIssuer` with a four-step saga: `build_deactivation_log` → `publish_log` → `mark_deactivated` → (auto-cancel-offers folded into the same DB transaction as `mark_deactivated`).

After step 9, deactivation is the only registry-touching operation other than `create_issuer` that has shipped. `rotate_keys` stays out of scope.

## Decisions (recommended)

- **In-flight credential offers are auto-cancelled** as part of the saga's terminal local step. Rationale: deactivation is rare; the BA's natural follow-up is to spin up a replacement issuer, so silent cancellation costs little and avoids new error codes on the OIDC redemption surface. The cancel is bulk: every offer with `state = 'pending'` for this issuer transitions to `cancelled` in the same transaction that flips the issuer to `Deactivated`. Already-`issued`, already-`cancelled`, already-`expired` offers are left alone.
- **Idempotency at the HTTP boundary: 200 with the existing task, never 409.** Three submission cases:
  - Issuer is `Active`, no in-flight `DeactivateIssuer` task → insert a new task, return `201 Created` with `{ task_id, issuer_id }`.
  - Issuer is `Active` and a `DeactivateIssuer` task for it is already `Pending`/`InProgress` → return `200 OK` with the *existing* task_id. Treat the duplicate submission as a poll-handle request.
  - Issuer is already `Deactivated` → return `200 OK` with the *completed* task_id (the one that drove the deactivation), if findable; otherwise `200 OK` with no `task_id` (issuer was deactivated by some path that did not leave a task row, e.g. seeded fixture). The shape of the body keeps `task_id: Option<TaskId>` to cover both.
  - Cross-tenant or unknown issuer_id → 404, same as `GET /api/v1/issuers/{id}`.
- **Saga step decomposition** (mirrors `create_issuer`):
  - `build_deactivation_log` — local, terminal-on-failure. Loads the issuer, fetches the current DIDLog tail from the registry (one read), constructs the deactivation entry, signs it with the issuer's current `Authorized` key via the SigningEngine. State-data records the signed entry bytes (or a deterministic-enough handle to rebuild them) so a crash before `publish_log` does not require a second SigningEngine call.
  - `publish_log` — retryable. Same retry/backoff rules as `create_issuer::publish_log`. State-data records `log_published: bool`.
  - `mark_deactivated` — local, terminal-on-failure. Single Postgres transaction: `UPDATE issuers SET state = 'deactivated' WHERE id = $1 AND tenant_id = $2 AND state = 'active'`, plus `UPDATE credential_offers SET state = 'cancelled', cancelled_at = $now, pre_auth_code = NULL WHERE issuer_id = $1 AND tenant_id = $2 AND state = 'pending'`. The state guard on the issuer update makes the step idempotent: a re-run after a crash that already flipped the row is a 0-row update, which is treated as success (the issuer is already in the desired state).
- **DIDLog tail fetch is a saga-time registry read.** `build_deactivation_log` needs the previous entry's hash and version-id to chain the deactivation entry. The registry is authoritative for the DIDLog (spec: `aspect-issuer.md` §"DIDLog: the registry is authoritative"); swiyu-issuer does not keep a local tail pointer. The saga calls a new `RegistryFacade::fetch_log` (or `fetch_log_tail`) at the start of `build_deactivation_log`, picks the last entry, and uses its hash and version-id to build the deactivation entry. A retryable `RegistryError` from the tail fetch is classified the same as `publish_log` retries, *not* terminal — registry transport flakiness on the read shouldn't kill the saga.
- **SigningEngine call site.** The current `Authorized` key signs the deactivation entry. Reuses the same eddsa-jcs-2022 path that `create_issuer::build_initial_log` uses; the 32-vs-64-byte trait fix from before step 7 is already in place.
- **No new IssuerState transitions beyond `Active → Deactivated`.** Reactivation stays unsupported.

## Substeps

Each substep is a small green-build commit.

- [x] **9.1 — Domain: `TaskType::DeactivateIssuer`.** Add the variant to `domain::operation_task::TaskType`, extend `as_str` / `parse`, add `DeactivateIssuerInput { /* empty */ }` and `DeactivateIssuerStateData { log_published: bool }` in `worker/deactivate_issuer/state.rs`. The signed deactivation entry is *not* recorded in state-data: each step that needs it re-derives it deterministically from the current registry tail and the issuer's `Authorized` key, mirroring how `create_issuer::build_initial_log` is described as "idempotent without state-data records: deterministic". Unit tests for round-trip and `parse` round-trip.
- [x] **9.2 — Persistence: `issuers::mark_deactivated` + bulk-cancel offers.** New helper `persistence::issuers::mark_deactivated(conn, &tenant_id, &issuer_id, now) -> Result<MarkOutcome, PersistenceError>` returning `Already | NowDeactivated` so the worker can distinguish first-write from idempotent re-run. New helper `persistence::credential_offers::cancel_all_pending_for_issuer(conn, &tenant_id, &issuer_id, now) -> Result<u64, PersistenceError>` returning the count of cancelled rows. Integration tests: happy path, idempotent re-run is no-op, cross-tenant offers untouched, non-pending offers untouched.
- [x] **9.3 — Worker step: `build_deactivation_log`.** New module `worker/deactivate_issuer/build_deactivation_log.rs`. Loads issuer, fetches the full DIDLog via a new `RegistryFacade::fetch_log(did) -> Result<Vec<LogEntry>, RegistryError>` method (placeholder real-impl in swiyu-registries can land in this same step), takes the last entry as the tail, builds the deactivation entry via a `swiyu-core` helper (new `build_deactivation_entry` if not already there), signs via SigningEngine. Records the signed entry in state-data. Terminal-on-failure for everything except registry transport errors during the tail fetch (those are `Retry`). Unit tests with a mock `RegistryFacade` and `MockSigningEngine`.
- [x] **9.4 — Worker step: `publish_log` for deactivation.** Either a new module `worker/deactivate_issuer/publish_log.rs` or extract the existing `create_issuer::publish_log` into a shared helper if the only difference is the input source. Lean: separate file, share whatever crate-private helpers are reasonable, keep the per-task-type executor obvious. The step treats a registry-side "already deactivated" error response as `Done` (flips `log_published = true` and advances) — this happens on saga resume after a crash between `publish_log` success and `mark_deactivated`. Mapping the registry's concrete error shape to this branch lands when we see it during integration testing. Unit tests follow the same shape as `create_issuer::publish_log` tests, plus one test asserting the "already-deactivated → Done" branch.
- [x] **9.5 — Worker step: `mark_deactivated`.** New module `worker/deactivate_issuer/mark_deactivated.rs`. Opens one Postgres transaction, calls 9.2's two persistence helpers, commits. `StepOutcome::Done` on success (whether `Already` or `NowDeactivated`). `StepOutcome::Terminal` on persistence error — there is no retry path for a local DB failure during this step. Integration test with a real pool: pre-populates pending + issued + cancelled offers, runs the step, asserts only pending ones flipped and the issuer is now `Deactivated`.
- [x] **9.6 — Worker dispatch wiring.** Extend `worker/dispatch.rs` to route `TaskType::DeactivateIssuer` through the new step sequence. e2e test under `tests/worker_e2e.rs` (new file `worker_deactivate_e2e.rs`) using the wiremock harness: submit a deactivate task, drain, assert registry got the deactivation entry, assert local `issuers` row is `Deactivated`, assert pending offers were cancelled.
- [x] **9.7 — HTTP endpoint: `POST /api/v1/issuers/{issuer_id}/deactivate`.** New handler `api_management::issuers::deactivate`. Resolves issuer (404 if absent / cross-tenant / `state == None` legacy row), checks for an existing in-flight or completed `DeactivateIssuer` task for this issuer, returns one of the three responses described in Decisions. New persistence helper `operation_tasks::find_latest_by_type_and_issuer(conn, &tenant_id, &issuer_id, TaskType::DeactivateIssuer)` to power the lookup. Integration tests: fresh deactivation (201 + new task_id), already-pending (200 + same task_id), already-deactivated (200 + completed task_id or null), cross-tenant (404), unknown id (404), legacy seeded issuer (404).
- [ ] **9.8 — OpenAPI.** Document the new endpoint in `openapi.yml`, including the polymorphic 200/201 response and the `task_id: nullable` field.

## Spec updates that ride along

These touch `swiyu-issuer/specs/` and should land alongside the code commits, not as a separate doc-only blob.

- `aspect-issuer.md` §Open: resolve the in-flight-credential-offers question (answer: auto-cancel) and move the bullet from "Open" to a short paragraph in §Deactivate.
- `impl-issuer.md`: add the `DeactivateIssuer` task-type step decomposition, mirroring the existing `CreateIssuer` section. Document the idempotency-on-resubmit decision (200 with existing task_id) so future endpoint decisions have a precedent.
- `aspect-issuer.md` or `aspect-persistence.md`: short note that deactivation triggers a bulk pending-offer cancel, so `cancelled_at` on offers can be set by a saga rather than only by the explicit cancel endpoint.

## Open questions

- **Tail-fetch caching across retries.** A `Retry` from `publish_log` re-runs `publish_log` only, so the tail fetched in `build_deactivation_log` does not need to be refreshed. But a `Retry` from the tail fetch itself (inside `build_deactivation_log`) will retry the whole step. Acceptable for v1; revisit if registry latency makes it painful.
- **Registry's concrete "already deactivated" error shape.** The decision is to treat it as success (see Resolved decisions and substep 9.4); the open part is which HTTP status / error body / `RegistryError` variant the SWIYU registry actually emits. Pin down during integration testing of 9.4 / 9.6 and update the mapping then.

## Resolved decisions

- **In-flight offers**: auto-cancel as part of the saga's terminal local step. (See Decisions.)
- **HTTP idempotency**: 200 with existing task_id, not 409. (See Decisions.)
- **No new domain state transitions** beyond `Active → Deactivated`.
- **Tail fetch is a saga-time read** from the registry, not a persisted local pointer. Confirmed.
- **Registry endpoint shape for the tail read**: full `fetch_log(did) -> Vec<LogEntry>`. Caller slices to take the last entry. Matches future verifier needs that want the full chain.
- **Registry "already deactivated" response on saga resume**: treat as success in the `publish_log` step (flip `log_published = true` and advance to `mark_deactivated`). Concrete error-shape mapping lands during integration testing.

## Test strategy

Per substep, the integration-test strategy is the same as steps 7 and 8: unit tests inline with each step module (mocks for SigningEngine and RegistryFacade), persistence-layer integration tests against a real pool (`sqlx::test`), one wiremock-backed e2e test that drains the saga end-to-end.

For 9.7 specifically:

- Fresh deactivation: assert the response is 201, body has both `task_id` and `issuer_id`, the new `operation_tasks` row has `task_type = 'deactivate_issuer'`, `state = 'pending'`, `step = NULL`, `result_issuer_id = Some(issuer_id)`.
- Already-pending: insert a `Pending` `DeactivateIssuer` task for the issuer, submit again, assert 200 and the same `task_id` comes back.
- Already-deactivated with traceable task: deactivate via the saga in a fixture, submit again, assert 200 and the *completed* task's `task_id` comes back.
- Already-deactivated without traceable task: directly UPDATE the issuer row to `Deactivated`, submit, assert 200 and `task_id == null`.
- Cross-tenant: 404.
- Pre-condition test for the seeded legacy issuer (state `None`): 404.

## Out of scope

- `POST /api/v1/issuers/{id}/rotate-keys`. Lands in step 10.
- Reactivation. Permanently out of scope per spec.
- Bulk deactivation across multiple issuers in one call.
- Operator-side cancel/force-retry of `DeactivateIssuer` tasks.
- Push-style notification on terminal state — polling-only stays the v1 contract.
