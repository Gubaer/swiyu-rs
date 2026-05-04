# Step 7 — Worker (sub-plan)

Companion to `plan.md`. Step 7 implements the task-dispatching worker described in `swiyu-issuer/specs/impl-issuer.md` (Worker section). Step 6 — the real `IdentifierRegistryClient` — is now in place, so this slice can wire the worker against a concrete async registry client and the existing `SigningEngine`.

## Goal

A single `tokio::spawn`-ed worker, owned by the `issuer-mgmt` binary, that picks up `OperationTask` rows in submission order and runs the per-step `CreateIssuer` choreography to completion. State-data-driven idempotency for crash recovery; exponential-backoff-with-full-jitter retry for transient registry failures; 24h wall-clock cap from `created_at` to terminal failure.

## Scope

In:

- New `swiyu-issuer/src/worker/` module: dispatch loop, backoff helper, per-step executors for `CreateIssuer`, in-tree integration tests with a wiremock-backed registry.
- New eddsa-jcs-2022 signing-input helper in `swiyu-core` (value-object code only, no I/O). Produces the 64-byte concatenation that `SigningEngine::sign` accepts after the previous slice.
- Small registry-facade trait inside swiyu-issuer so the worker can be unit-tested against in-memory mocks while integration tests hit the real `IdentifierRegistryClient` through wiremock.
- Wiring in `issuer-mgmt`'s `main` to launch the worker alongside the HTTP server, reading registry config from the existing env vars.

Out (deferred to later slices):

- `RotateKeys`, `DeactivateIssuer` task types — same task model, but each is its own slice once the substrate is in.
- Multi-worker dispatch (the existing `acquire_next` already uses `FOR UPDATE SKIP LOCKED`, so this is a future flip rather than a redesign).
- Operator admin endpoints (cancel / force-retry / inspect `state_data`).
- Postgres `LISTEN`/`NOTIFY` low-latency wakeup; v1 polls.
- Step 8 (HTTP endpoints). The worker reads from the table directly, so it does not depend on the management API.

## Substeps

Each substep is a small, green-build commit. Order picked so the substrate lands before the I/O paths and tests catch regressions early.

- [x] **7.1 — eddsa-jcs-2022 signing-input helper in swiyu-core.** Already exists as `swiyu_core::didlog::eddsa_jcs_2022_hash(document, proof_config) -> [u8; 64]` (extracted during the step-5 slice). Used by `swiyu-didtool/src/cmd/proof.rs` and `swiyu-core/src/didlog/verify.rs`; tests at `swiyu-core/src/didlog/mod.rs:746` cover layout and JCS key-order independence. The worker will call this directly and pass the 64 bytes to `SigningEngine::sign(authorized_kid, &hash)`.
- [x] **7.2 — `worker/` module skeleton + backoff helper.** `swiyu-issuer/src/worker/mod.rs` + `worker/backoff.rs` with `backoff_delay(attempts, rng) -> Duration` (full-jitter exponential, 1-min base, 1-hour ceiling) and `is_past_cap(created_at, now) -> bool` (24-hour wall-clock budget). Eight unit tests with a `FixedRng` test double. Commit: `1939fc6`.
- [ ] **7.3 — Step-outcome wiring: `state_data` typed structs + advance/retry/terminal paths.** `worker::create_issuer::state` defines `CreateIssuerInput` (deserialised from `task.input`; v1 shape: `{ description: String, display_name: String }` with `#[serde(deny_unknown_fields)]`; DID method and DID-document customisation excluded for v1) and `CreateIssuerStateData` (deserialised from `task.state_data`, with all fields optional to support the resume-after-crash path). `worker::dispatch::apply_outcome` maps `StepOutcome::{Done,Retry,Terminal}` to the existing persistence calls (`advance_step`, `schedule_retry`, `mark_failed`); the 24h-cap check from `worker::backoff::is_past_cap` lives here, routing a `Retry` past the cap to `mark_failed` instead of `schedule_retry`. Unit tests on the mapping; the persistence calls themselves are already covered by step 3's tests.
- [x] **7.4 — Registry-facade trait inside swiyu-issuer.** `worker::registry::RegistryFacade` with two methods (`allocate_did`, `publish_log_entry`) matching the shapes the worker needs. Concrete `IdentifierRegistry` wraps `swiyu_registries::identifier::IdentifierRegistryClient`. Native async-in-trait (Rust 2024) with explicit `+ Send` bounds; consumed via generics (`<R: RegistryFacade>`) rather than `&dyn` because `impl Future` is not object-safe. Mock impls land in 7.6 alongside the executors that need them. The `swiyu-registries` crate stays untouched.
- [x] **7.5 — Tenant model + `partner_id` (pre-slice for 7.6).** Migration `20260516_000011_tenant_partner_id.sql` adds the nullable `partner_id` column and backfills the seeded dev tenant `4Mk7yK5pQR7sN3` with the all-zero nil UUID as a "must be re-onboarded" flag. `domain/tenant.rs` defines `Tenant { id, partner_id: Option<String> }`. `persistence/tenants.rs` exposes `find_by_id`. 4 integration tests (`tests/tenants_persistence.rs`) cover with-partner-id, without-partner-id, unknown-tenant, and the seeded dev tenant's placeholder.
- [ ] **7.6 — `CreateIssuer` step executors (no dispatch loop yet).** `worker::create_issuer::execute_<step>` for `allocate_did`, `generate_keys`, `build_initial_log`, `publish_log`, `persist_issuer`. Each takes `&CreateIssuerStateData` plus the dependencies it needs (registry facade, signing engine, db pool, tenant) and returns `StepOutcome`. `execute_allocate_did` loads the tenant via `persistence::tenants::find_by_id` and reads `partner_id`; if `None`, returns `Terminal { error_code: "tenant_missing_partner_id" }`. Idempotency checks per `impl-issuer.md` (Step idempotency). Unit tests per step against in-memory mocks. The `build_initial_log` step internally calls swiyu-core's `build_initial_entry` (already there), then `eddsa_jcs_2022_hash`, then `SigningEngine::sign`, then `append_proof`. The `publish_log` step serialises the finalised entry to a single JSONL line and calls `RegistryFacade::publish_log_entry`.
- [ ] **7.7 — Dispatch loop.** `Worker::run(mut self, shutdown: CancellationToken)`: loop invoking `acquire_next`, dispatching to the per-task-type executor, applying the outcome, sleeping briefly when no task is runnable. Cooperative shutdown via `tokio_util::sync::CancellationToken` (or `tokio::sync::watch`). Unit tests covering: idle-loop wakes up on cancel; one happy-path task drives all five steps to completion; retry path increments `attempts` and writes `next_attempt_at`; cap-exceeded path transitions to `Failed` instead of scheduling another retry.
- [ ] **7.8 — End-to-end integration test.** `swiyu-issuer/tests/worker_create_issuer.rs` with a real Postgres pool (`sqlx::test`) and a wiremock-backed `IdentifierRegistryClient`. Three flows: (a) happy path — task lands in `Completed`, issuer row inserted, three `KeyPairId`s recorded, `state_data` carries `assigned_did` and the published-entry signal; (b) retry-on-503 — first `publish_log` attempt 503s, second succeeds; assert `attempts` increment and `next_attempt_at` movement; (c) resume-after-crash — pre-populate a task with `state_data.assigned_did` already set and assert the worker skips `allocate_did`.
- [ ] **7.9 — Wire the worker into `issuer-mgmt` startup.** Read `SWIYU_REGISTRY_URL` and `SWIYU_REGISTRY_ACCESS_TOKEN` (`partner_id` now comes from the tenant, not env). Build `IdentifierRegistryClient`, build `DevSigningEngine`, hand both to `Worker::new`, `tokio::spawn(worker.run(shutdown))`. Wire `shutdown` to `tokio::signal::ctrl_c` alongside the HTTP server's existing shutdown plumbing. Manual smoke against the SWIYU integration registry is the v1 acceptance gate (no automated test for this substep).

## Decisions (recommended)

- **Per-step executor indirection.** Match against `task.task_type` first, then against `step` strings. v1 has one task type, so this is a small `match`; introducing a `dyn TaskExecutor` trait isn't worth it until `RotateKeys` lands.
- **Registry facade trait.** Define inside swiyu-issuer (not in swiyu-registries). Keeps the registry crate consumer-agnostic and lets the worker keep its mocks local.
- **eddsa-jcs-2022 helper placement.** swiyu-core. The 64-byte signing-input is value-object code shared across `did:tdw` and `did:webvh`; it has no business in swiyu-issuer.
- **`partner_id` is a tenant attribute** (column on `tenants`, not an env var, not on `CreateIssuerInput`). Worker loads the tenant in `execute_allocate_did` and fails Terminal if `partner_id` is unset. `SWIYU_REGISTRY_ACCESS_TOKEN` stays global for v1.
- **`CreateIssuerInput` v1 shape.** `{ description: String, display_name: String }` with `#[serde(deny_unknown_fields)]`. DID method hard-coded to `did:tdw` 0.3 inside the worker until `did:webvh` is testable end-to-end. No DID-document customisation (services, alsoKnownAs).
- **Shutdown signal: `tokio_util::sync::CancellationToken`.** Standard tokio idiom; cooperative; pairs naturally with the dispatch-loop's poll sleep via `tokio::select!`.

## Open questions

- **What goes into `state_data` for `publish_log`?** The `IdentifierRegistryClient::publish_log_entry` returns `()` (no entry hash). The plan's earlier sketch had a `published_log_hash` field; with the actual client there is no such hash to record. Idempotency of the step then relies on a boolean `state_data.log_published == true` flag instead. Resolve in 7.6 — the simplest read is "if `log_published == true`, treat as `Done`."
- **`fetch_log` in v1?** The other agent shipped it. The worker doesn't need it for `CreateIssuer`; verifier-side flows do. Leave it unused by the worker.

## Risks / heads-up

- **`allocate_did` is not idempotent at the registry.** A worker crash between the registry returning a fresh identifier and the state-data write produces an orphan allocation at the registry. The plan accepts this; cleanup is out of scope.
- **Orphan keys in `DevSigningEngine`.** Symmetric: a crash between `generate_keypair` and the `state_data.key_ids` write leaks a private-key row in `signing_engine_dev_keypairs`. Acceptable in v1; production-tier engines will add a periodic cleanup job.
- **24h cap is measured from `created_at`.** Already on `OperationTask`; `acquire_next` returns it. No new persistence work needed.
- **Eddsa-jcs-2022 over `eddsa-rdfc-2022` — `did:tdw` 0.3 uses `eddsa-jcs-2022`.** Confirm against `swiyu-didtool/src/cmd/proof.rs` (the existing local-signing path) before pinning the test vector in 7.1.

## Test strategy summary

- Unit tests per step function, against in-memory mocks of `RegistryFacade` and using `DevSigningEngine` against a `sqlx::test`-managed Postgres.
- One end-to-end integration test (`tests/worker_create_issuer.rs`) covering happy path + retry + resume-after-crash, with wiremock standing in for the registry.
- No automated test for the binary-startup wiring; manual smoke against the SWIYU integration registry is the v1 gate.

## Out of scope (already noted in plan.md / impl-issuer.md, repeated here for clarity)

- Operator admin endpoints, callback URLs, multi-worker dispatch, OIDC binary migration, per-task-type backoff configurability.
