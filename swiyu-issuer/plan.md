# Issuer-management slice — work in progress

Scratchpad to resume the slice in a fresh session. Authoritative spec lives in `swiyu-issuer/specs/aspect-issuer.md` and `swiyu-issuer/specs/impl-issuer.md`.

## Status snapshot

- **Working branch:** `swiyu-issuer`, tip at `6791618 Bump swiyu-issuer to v0.1.4`. One commit ahead of `origin/swiyu-issuer` (the bump).
- **Master:** `0c2e780 Update README and core specs for trust rename and From/TryFrom` on `origin/master`; one local-only commit on top (`5f1aca5 Bump swiyu-core and swiyu-didtool to 0.2.2`).
- **Last formal tag:** `swiyu-issuer-v0.1.3` on `c82f742` (the merge commit that integrated master's From/TryFrom refactorings into the slice). Pushed to `origin` only.
- **Cargo.toml:** swiyu-issuer is `0.1.4` (post-tag bump).
- **Tests:** workspace fully green (`cargo fmt --check`, `cargo clippy -p swiyu-issuer --all-targets -- -D warnings`, full integration tests with `DATABASE_URL` set).

## Working conventions

- Run integration tests with: `DATABASE_URL=postgres://swiyu_issuer:swiyu_issuer@localhost:5433/swiyu_issuer cargo test -p swiyu-issuer`. Postgres comes from `swiyu-issuer/docker-compose.yml`.
- Each working commit verified by `cargo fmt --check && cargo clippy -p swiyu-issuer --all-targets -- -D warnings` and the relevant test suite before reporting work as done.
- Commits that only touch `swiyu-core` and `swiyu-didtool` are committed on the swiyu-issuer branch and cherry-picked to whichever master-bound branch is active (e.g. `refactorings`); swiyu-issuer-only commits stay on the branch.
- Spec docs use prose-paragraphs-on-one-line (per `LESSONS-LEARNED.md`); doc comments reference fields with bare backticks.
- Push to `origin` (Bitbucket) only; the `github` remote stays untouched per user preference.

## Step plan

The slice is the issuer-management API: BA can create / list / get / deactivate issuers and trigger key rotations. swiyu-issuer maintains DIDLogs in the SWIYU Identifier Registry as a side effect.

- [x] **Step 1 — Domain: operation-task family.** `OperationTask`, `TaskId`, `TaskState`, `TaskType`, `StepResult`, `StepOutcome`.
- [x] **Step 2 — Domain: `IssuerState` + `Issuer` extensions.** New fields as `Option<…>` (expand-contract); legacy `signing_key_id` survives.
- [x] **Step 3 — Persistence: `operation_tasks` migration + module.** `insert`, `find_by_id`, `acquire_next` (FOR UPDATE SKIP LOCKED), `advance_step` (Rust-side state-data merge), `schedule_retry`, `mark_failed`, `mark_completed`.
- [x] **Step 4 — Persistence: `issuers` schema extension + module updates.** Five new nullable columns; `signing_key_id` relaxed to nullable. `Issuer.signing_key_id` now `Option<String>`.
- [x] **Step 5 — Extract DIDLog construction to `swiyu-core`.** `DIDLogEntry::new_genesis`, `LogParameters::new_tdw_minimal/new_webvh_minimal`, and the `entry_edits::{strip_proof_slot, set_version_id, append_proof}` mutators.
- [x] **Step 6 — Real `IdentifierRegistryClient` in `swiyu-registries`.** Async client with `allocate_did`, `publish_log_entry`, `fetch_log`. Failure classification via `RegistryError::is_retryable()`.
- [x] **Step 7 — Worker.** `swiyu-issuer/src/worker/` module with `tokio::spawn`-ed dispatch loop. Per-step execution for `create_issuer`: `allocate_did` → `generate_keys` → `build_initial_log` → `publish_log` → `persist_issuer`. Exponential backoff with full jitter, 24h wall-clock cap. State-data-driven idempotency for crash recovery. `SigningEngine::sign` takes `&[u8]` (not `&[u8; 32]`) so eddsa-jcs-2022's 64-byte signing input goes through.
- [x] **Step 8 — HTTP endpoints.** `POST /api/v1/issuers`, `GET /api/v1/issuers`, `GET /api/v1/issuers/{issuer_id}`, `GET /api/v1/operation-tasks/{task_id}`. Tenant from token via `TenantContext`. See `plan-step8.md` for the substep breakdown.
- [x] **Step 9 — Deactivate issuer.** `POST /api/v1/issuers/{issuer_id}/deactivate` plus the `DeactivateIssuer` task type and saga (`build_deactivation_log` → `publish_log` → `mark_deactivated`). Bulk-cancels pending offers in the same DB transaction that flips the row. See `plan-step9.md`.
- [ ] **Step 10 — Rotate keys.** `POST /api/v1/issuers/{id}/rotate-keys` and the `RotateKeys` task type. Same overall shape as deactivate: build new entry chained on the registry tail, sign with current Authorized key, publish, atomically swap the local key triple. Deferred until prioritised.

## Open issues

- **DIDLog caching.** Whether swiyu-issuer keeps a local copy of the DIDLog for offline operation. Default lean: no — fetch on demand. Confirmed in step 9 (deactivate's `build_deactivation_log` fetches the tail at saga time).
- **Registry's "already deactivated" error shape.** Step 9.4 currently catches the resume case via `BuildError::AlreadyDeactivated` (registry tail inspection). The PUT-side error response (some 4xx with a body identifying the DID as already deactivated) is a second place to land that branch; concrete shape lands during integration testing against the SWIYU registry.

## Useful pointers

- swiyu-registries' `IdentifierRegistryClient` exposes `allocate_did`, `publish_log_entry`, and `fetch_log`. swiyu-issuer's `worker::registry::RegistryFacade` adapter parses fetch_log's JSONL body into `Vec<DIDLogEntry>` via `DIDLog::try_from_jsonl().map(DIDLog::into_entries)`.
- `signing_engine_dev_keypairs`, `operation_tasks`, and the post-migration `issuers` columns are all in place. The dev seeded row from migrations 0001/0004 still has `state IS NULL` and is hidden from the BA-facing endpoints (returns 404 from get/deactivate, filtered out of list).
- swiyu-core was refactored on master to use `From` / `TryFrom` / `FromStr` instead of inherent `to_json` / `try_from_json` / `parse` methods. Merged into swiyu-issuer at `c82f742`; six call-site fixes folded into the merge commit.
- The `.worktrees/master` worktree is set up for cross-cutting work that needs to ship via master.
