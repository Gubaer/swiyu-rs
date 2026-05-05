# Step 10 — Rotate keys (sub-plan)

Companion to `plan.md`. Step 10 adds the `rotate_keys` lifecycle operation, end-to-end: domain task type, worker saga, persistence helpers, and HTTP endpoint. The aspect-level choreography is fixed by `specs/aspect-issuer.md` §"Rotate keys"; this plan is the implementation pass.

## Goal

One new endpoint plus the supporting saga:

- `POST /api/v1/issuers/{issuer_id}/rotate-keys` — submit a `RotateKeys` task. Body specifies the non-empty subset of `{authorized, authentication, assertion}` to rotate. Tenant-scoped via `TenantContext`.
- New `TaskType::RotateKeys` with a four-step saga: `generate_new_keys` → `build_rotation_log` → `publish_log` → `swap_keys`.

After step 10, every registry-touching lifecycle operation (create, rotate, deactivate) is on the task model — the v1 contract from `aspect-issuer.md` §"v1 scope" is met.

## Decisions (recommended)

- **Submission body shape.** `{ "roles": ["authorized", "authentication", "assertion"] }`. Strings are lowercase snake-case forms of `KeyRole`, plus the sentinel `"all"` as a shorthand for the full set. Validation rules: the array must be non-empty (`400 invalid_input` otherwise; matches `aspect-issuer.md` §"Rotate keys" — empty subset is forbidden); unknown role names are `400`; duplicates are tolerated and de-duplicated server-side; `"all"` must appear alone (mixing `"all"` with a concrete role name is `400` since the combination is redundant and likely a client bug). Server-side, `["all"]` expands to the full three-role set before the saga starts.
- **Idempotency at the HTTP boundary: 200 with the existing task for in-flight, 201 for fresh.** Four submission cases:
  - Issuer is `Active`, no in-flight `RotateKeys` task → insert a new task, return `201 Created` with `{ task_id, issuer_id }`.
  - Issuer is `Active` and a `RotateKeys` task for it is already `Pending`/`InProgress` → return `200 OK` with the *existing* task_id. Treat the duplicate submission as a poll-handle request, same as deactivate.
  - Issuer is `Active` and the only prior `RotateKeys` tasks for it are terminal (`Failed` or `Completed`) → insert a new task. Rotation is repeatable; previous-task lookup gates only on the in-flight set.
  - Issuer is `Deactivated` → `409 Conflict` with code `issuer_deactivated`. Unlike deactivate, rotation has no idempotent re-target semantics; rotating a deactivated issuer is a logic error.
  - Cross-tenant or unknown issuer_id → `404`, same as `GET /api/v1/issuers/{id}`. Legacy seeded issuer (`state IS NULL`) → `404`.
- **Saga step decomposition** (mirrors `create_issuer`'s split between key generation and log construction):
  - `generate_new_keys` — local, terminal-on-failure (except SigningEngine backend errors → `Retry`). For each role in `input.roles`, call `engine.generate_keypair(role)`. Carry forward unchanged ids for non-rotated roles. Record `new_key_triple: KeyTriple` in state-data so a crash before `build_rotation_log` does not strand the freshly minted keys (a re-run sees the populated triple and skips the engine call). The `KeyTriple` shape is the one already defined in `worker/create_issuer/state.rs`; reuse via re-export rather than duplicate the type.
  - `build_rotation_log` — local, terminal-on-failure (registry tail-fetch errors are `Retry`, same discipline as deactivate's). Loads the issuer, fetches the current DIDLog tail, builds the rotation entry whose `updateKeys` carries the multikey of the *new* Authorized key and whose embedded DID document carries verification methods for the *new* Authentication and Assertion keys, signs with the **outgoing** Authorized private key (from `issuer.authorized_key_id`, *not* `state.new_key_triple.authorized`). Discards the entry; re-derived deterministically by `publish_log`.
  - `publish_log` — retryable. Same retry/backoff rules as `create_issuer::publish_log` and `deactivate_issuer::publish_log`. State-data records `log_published: bool`. Saga-resume after a successful PUT but failed `swap_keys`: `publish_log` re-runs, fetches the log, observes that the registry tail's `updateKeys` already references the new Authorized key (i.e. the rotation was already published), and short-circuits to `Done` with `log_published: true` — same defensive pattern as deactivate's `BuildError::AlreadyDeactivated` short-circuit. Concrete detection: compare the registry tail's `updateKeys[0]` to the multikey form of `state.new_key_triple.authorized`'s public key.
  - `swap_keys` — local, terminal-on-failure (DB transient errors → `Retry`, mirroring `mark_deactivated`'s classification). Single Postgres `UPDATE issuers SET authorized_key_id = $1, authentication_key_id = $2, assertion_key_id = $3 WHERE id = $4 AND tenant_id = $5 AND state = 'active'`. Idempotent on re-run: if the row's three key columns already match `state.new_key_triple`, return `SwapOutcome::Already`; otherwise `NowSwapped`. Both shapes report `StepOutcome::Done`.
- **DIDLog tail fetch is a saga-time read,** identical to deactivate. No persisted local tail pointer.
- **The signing key is the outgoing Authorized key.** Per spec §"Rotate keys" step 4: even when `Authorized` is itself rotated, the *old* `Authorized` signs the rotation entry. The new Authorized key only signs the *next* entry. The build-step takes the signing key id from `issuer.authorized_key_id` (the row's current value) and the new keys from `state.new_key_triple` (the next-entry payload); never confuse the two.
- **Old-key deletion is out of scope for step 10.** The spec marks it optional. Lean for v1: keep old keys around. A future cleanup slice can add a `delete_old_keys` step or a periodic reaper. Verifiers fetching public keys from the DIDLog do not need the SigningEngine to retain old keys; the registry's log carries the history.
- **No new IssuerState transitions.** The issuer stays `Active` throughout the rotation.

## Substeps

Each substep is a small green-build commit.

- [x] **10.1 — Domain: `TaskType::RotateKeys`.** Add the variant to `domain::operation_task::TaskType`, extend `as_str` / `parse`, add `RotateKeysInput { roles: Vec<KeyRole> }` and `RotateKeysStateData { new_key_triple: Option<KeyTriple>, log_published: bool }` in `worker/rotate_keys/state.rs`. The wire shape carries the `"all"` sentinel; the deserialiser expands it into the three concrete `KeyRole`s before the value lands in `RotateKeysInput`, so worker code only ever sees concrete roles. Re-export `KeyTriple` from `worker/create_issuer` rather than duplicate the type. Unit tests for round-trip, `parse` round-trip, empty-roles rejection at the deserialiser level (or as a domain-side validator), unknown-role rejection, `["all"]` expands to the full set, `["all", "authorized"]` is rejected.
- [x] **10.2 — Persistence: `issuers::swap_key_triple`.** New helper `persistence::issuers::swap_key_triple(conn, &tenant_id, &issuer_id, &new_triple) -> Result<SwapOutcome, PersistenceError>` returning `Already | NowSwapped`. Idempotency via comparing the row's current key columns to `new_triple` after a 0-row UPDATE. Integration tests: happy path (Active → swapped), idempotent re-run, cross-tenant returns NotFound, deactivated issuer returns NotFound (state guard), legacy state-NULL row returns NotFound.
- [ ] **10.3 — Worker step: `generate_new_keys`.** New module `worker/rotate_keys/generate_new_keys.rs`. Reads `state.new_key_triple` for the resume short-circuit; otherwise calls `engine.generate_keypair` for each role in `input.roles` and constructs the new triple by overlaying onto the issuer's current triple. Records the result in state-data via `StepResult::state_data_patch`. Engine backend errors → `Retry`; other engine errors → `Terminal`. Unit tests with `MockSigningEngine`.
- [ ] **10.4 — Worker step: `build_rotation_log`.** New module `worker/rotate_keys/build_rotation_log.rs` plus a shared `worker/rotate_keys/log_builder.rs` (mirrors `deactivate_issuer/log_builder.rs`). The shared helper takes `&Issuer`, `&KeyTriple` (new), `&[DIDLogEntry]` (tail), `&S` (engine), and `now`; returns the signed rotation entry as `Value`. Build via `DIDLogEntry::new_rotation` (new `swiyu-core` constructor — see *Spec updates that ride along*) or a hand-rolled assembly if the constructor lands later. Sign with `issuer.authorized_key_id` (outgoing). Unit tests with mocks; cover the "Authorized is itself rotated" case to confirm the *outgoing* key is used.
- [ ] **10.5 — Worker step: `publish_log`.** New module `worker/rotate_keys/publish_log.rs`. Re-fetches log, calls the shared `build_rotation_entry`, PUTs. On the saga-resume short-circuit, detects "already rotated" by comparing the registry tail's `updateKeys[0]` to the multikey of `state.new_key_triple.authorized`. Unit tests follow the `deactivate_issuer::publish_log` shape, plus one test asserting the "already-rotated → Done" branch.
- [ ] **10.6 — Worker step: `swap_keys`.** New module `worker/rotate_keys/swap_keys.rs`. Acquires a connection, calls 10.2's helper. Maps `PersistenceError::Db` → `Retry`, structural errors → `Terminal`, mirroring `mark_deactivated`. Integration test against a real pool: pre-populate Active issuer; run the step; assert the row's three key columns match the new triple.
- [ ] **10.7 — Worker dispatch wiring.** Extend `worker/runner.rs` to route `TaskType::RotateKeys` through the new step sequence. e2e test under `tests/worker_rotate_keys_e2e.rs` using the wiremock harness: pre-populate Active issuer + initial keys; submit a rotate task that rotates all three roles; drain; assert registry got the rotation PUT (body has new updateKeys), local issuer row's three key columns are the new triple.
- [ ] **10.8 — HTTP endpoint: `POST /api/v1/issuers/{issuer_id}/rotate-keys`.** New handler `api_management::issuers::rotate_keys`. Resolves issuer (404 cases as deactivate). Validates the `roles` array (non-empty, known names, deduplicated, `"all"` only when alone). 409 on Deactivated. Re-uses `persistence::operation_tasks::find_latest_by_type_and_issuer` from step 9 with `TaskType::RotateKeys`; only treats `Pending`/`InProgress` as the duplicate-submission case (terminal prior tasks fall through to fresh-insert). Integration tests: fresh rotation (201 + new task_id, body shape matches `RotateKeysInput`), `["all"]` expands server-side and produces a 201 with all three roles in the persisted task input, in-flight task (200 + same task_id), prior completed task (201 + new task_id), deactivated issuer (409), empty roles (400), unknown role (400), `["all", "authorized"]` mixed (400), cross-tenant (404), legacy seeded issuer (404).
- [ ] **10.9 — OpenAPI.** Document the new endpoint in `openapi.yml`: request body schema (`RotateKeysSubmission` with the non-empty `roles` array), polymorphic 200/201 response (`task_id`, `issuer_id`), 409 for deactivated. Extend the `task_type` enum and the `step` description on `GetOperationTaskResponse` to cover the new four step names.

## Spec updates that ride along

These touch `swiyu-issuer/specs/` and should land alongside the code commits, not as a separate doc-only blob.

- `impl-issuer.md`: add the `RotateKeys` task-type step decomposition, mirroring the `CreateIssuer` and `DeactivateIssuer` sections. Highlight the outgoing-Authorized signing rule for entries that rotate Authorized itself.
- `aspect-issuer.md` §"v1 scope": once step 10 ships, drop the "v1 implements only `create_issuer`" caveat — all three operations are on the task model.
- (If a `swiyu-core` `DIDLogEntry::new_rotation` constructor is added) `swiyu-core`'s `didlog/mod.rs` doc and `swiyu-core/specs/didlog.md` get a paragraph for it, mirroring `new_genesis` / `new_deactivation`.

## Open questions

- **DID format inconsistency** (also flagged in `plan.md` §Open issues). Rotation entries don't add new pain here — `registry_identifier` from step 9 still applies — but it's a reminder that a real fix is overdue.
- **Old-key deletion timing.** If we ever do delete old keys, the safest moment is *after* the rotation entry has been verifiably propagated (e.g. observable in a fetched log on a later run). Out of scope for step 10; flagged for a future cleanup slice.

## Resolved decisions

- **Submission body**: `{ "roles": [...] }`, non-empty, lowercase snake-case role names plus the sentinel `"all"`. `"all"` may only appear alone; mixing with concrete role names is `400`.
- **HTTP idempotency**: 200 with existing task_id only for in-flight tasks; terminal prior tasks do not block a fresh submission.
- **Deactivated issuer**: 409, not 404. Distinguishes "rotation makes no sense here" from "no such resource".
- **Outgoing Authorized signs**: even when Authorized is rotated, the old key signs the rotation entry. Matches spec §"Rotate keys" step 4.
- **No old-key deletion in v1.**
- **No new domain state transitions** beyond the row's three key columns.
- **`swiyu-core::DIDLogEntry::new_rotation` constructor**: add to swiyu-core, mirroring `new_deactivation`. Shape: takes previous `version_id`, previous DID doc, the new `KeyTriple`, the outgoing Authorized multikey (for `updateKeys`), and the `version_time`. Lands as a dedicated swiyu-core-only commit on the swiyu-issuer branch, then cherry-picked to whichever master-bound branch is active — same workflow as `new_deactivation` and `into_entries` did during step 9.

## Test strategy

Per substep, the integration-test strategy is the same as steps 7–9: unit tests inline with each step module (mocks for SigningEngine and RegistryFacade), persistence-layer integration tests against a real pool (`sqlx::test`), one wiremock-backed e2e test that drains the saga end-to-end.

For 10.7 (e2e) specifically:

- Rotate all three roles: assert registry got one PUT, the body's `updateKeys` carries the new Authorized multikey, the issuer row's three key columns are the new triple.
- Rotate a single role (e.g. only `authentication`): assert the issuer row's `authorized_key_id` and `assertion_key_id` are unchanged, only `authentication_key_id` is new. Registry got one PUT.
- Resume after a crash between `publish_log` success and `swap_keys`: pre-populate state-data with `log_published: true`, run the worker, assert it skips re-publish and goes straight to `swap_keys`.

## Out of scope

- Old-key deletion from the SigningEngine.
- Rotation-on-deactivated re-activation. Deactivation stays terminal.
- Bulk rotation across multiple issuers in one call.
- Rotation that changes the DID method (e.g. `did:tdw` → `did:webvh`). v1 stays did:tdw 0.3.
- Operator-side cancel/force-retry of `RotateKeys` tasks.
