# Issuer-management slice — work in progress

Scratchpad to resume the slice in a fresh session. Authoritative spec lives in `swiyu-issuer/specs/aspect-issuer.md` and `swiyu-issuer/specs/impl-issuer.md`.

## Status snapshot

- **Working branch:** `swiyu-issuer`. Last commit: `987873a Extract DIDLog construction to swiyu-core`.
- **Master:** `f95f687 Extract DIDLog construction to swiyu-core` (cherry-pick of step 5). Pushed to both `origin` (Bitbucket) and `github`.
- **Last formal tag:** `swiyu-issuer-v0.1.2` on `07e885e` (before the issuer-management slice). Current `Cargo.toml` is at `0.1.3`.
- **Tests:** workspace fully green (`cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` with `DATABASE_URL` set for integration tests).

## Working conventions

- Run integration tests with: `DATABASE_URL=postgres://swiyu_issuer:swiyu_issuer@localhost:5433/swiyu_issuer cargo test --workspace`. Postgres comes from `swiyu-issuer/docker-compose.yml`.
- Each working commit verified by `cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings` and the full test suite.
- Commits that only touch `swiyu-core` and `swiyu-didtool` are cherry-picked to master and pushed; swiyu-issuer-only commits stay on the branch.
- Spec docs use prose-paragraphs-on-one-line (per `LESSONS-LEARNED.md`); doc comments reference fields with bare backticks.

## Step plan

The slice is the issuer-management API: BA can create / list / get / deactivate issuers and trigger key rotations. swiyu-issuer maintains DIDLogs in the SWIYU Identifier Registry as a side effect.

- [x] **Step 1 — Domain: operation-task family.** `OperationTask`, `TaskId`, `TaskState`, `TaskType`, `StepResult`, `StepOutcome`. (`247bb5c`)
- [x] **Step 2 — Domain: `IssuerState` + `Issuer` extensions.** New fields as `Option<…>` (expand-contract); legacy `signing_key_id` survives. (`1ef312d`)
- [x] **Step 3 — Persistence: `operation_tasks` migration + module.** `insert`, `find_by_id`, `acquire_next` (FOR UPDATE SKIP LOCKED), `advance_step` (Rust-side state-data merge), `schedule_retry`, `mark_failed`, `mark_completed`. 9 integration tests. (`f7282e7`)
- [x] **Step 4 — Persistence: `issuers` schema extension + module updates.** Five new nullable columns; `signing_key_id` relaxed to nullable. `Issuer.signing_key_id` now `Option<String>`. New `insert(conn, &Issuer)`. 4 integration tests. (`97dde91`)
- [x] **Merge master into swiyu-issuer** (`b5f8599`) — keeps the branches in sync and makes the next cherry-pick conflict-free.
- [x] **Step 5 — Extract DIDLog construction to `swiyu-core`.** New `swiyu-core/src/diddoc/builder.rs` (`build_initial_did_doc`) and `swiyu-core/src/didlog/build.rs` (`build_initial_entry`, `strip_proof_slot`, `set_version_id`, `append_proof`). swiyu-didtool consumes via thin wrappers. (`987873a` on swiyu-issuer; cherry-picked to master as `f95f687`.)
- [ ] **Step 6 — Real `IdentifierRegistryClient` in `swiyu-registries`.** Replace the placeholder in `swiyu-registries/src/identifier/mod.rs` with the actual async client used by the worker:
  - `allocate_did(partner_id) -> Did`
  - `publish_log_entry(did, signed_entry) -> EntryHash`
  - Configuration via constructor args (`SWIYU_REGISTRY_URL`, `SWIYU_PARTNER_ID` come from swiyu-issuer's binary at runtime; the crate stays env-agnostic).
  - Failure classification via `RegistryError::is_retryable()` — already in place in `swiyu-registries/src/common/error.rs`.
  - Reuse the registry-call shapes from `swiyu-didtool/src/swiyu/`.
- [ ] **Step 7 — Worker.** New `swiyu-issuer/src/worker/` module. Single `tokio::spawn`-ed dispatch loop alongside `issuer-mgmt`. Per-step execution for `create_issuer`: `allocate_did` → `generate_keys` → `build_initial_log` → `publish_log` → `persist_issuer`. Exponential backoff with full jitter, 24h wall-clock cap. State-data-driven idempotency for crash recovery. **Blocked on the SigningEngine 32-vs-64-byte issue below.**
- [ ] **Step 8 — HTTP endpoints.** `POST /api/v1/issuers` (submit task), `GET /api/v1/issuers`, `GET /api/v1/issuers/{issuer_id}`, `GET /api/v1/operation-tasks/{task_id}`. Tenant from token via `TenantContext`, never URL. Endpoints for `rotate_keys` / `deactivate_issuer` ship in subsequent slices.

## Heads-up before step 7: SigningEngine signs 32 bytes, eddsa-jcs-2022 needs 64

Surfaced during step-5 inventory.

- Current `SigningEngine::sign(id, input: &[u8; 32])` — fixed 32-byte input, treated as message for Ed25519, as digest for ECDSA P-256.
- The eddsa-jcs-2022 cryptosuite (used by DataIntegrity proofs in DIDLog entries) signs the **64-byte concatenation** of two SHA-256 hashes (proof config + document) as the Ed25519 message. Pre-hashing to 32 bytes would be wrong (it would change the cryptosuite and break verifiers).
- Fix: loosen the trait API to accept `&[u8]` (or split into `sign_message` / `sign_digest`). Required for step 7 to drive proof construction through the engine.
- Touches: `swiyu-issuer/specs/aspect-key-management.md`, `swiyu-issuer/specs/impl-key-management.md`, the trait in `swiyu-issuer/src/domain/signing_engine/mod.rs`, the `DevSigningEngine` (and any future `HsmSigningEngine`/`VaultSigningEngine`).

Tackle this as a small slice **before** starting step 7.

## Open issues parked in `aspect-issuer.md`

- **In-flight credential offers on deactivate.** What happens to `pending` offers belonging to an issuer at deactivation. Cancel? Reject redemption with a specific error?
- **DIDLog caching.** Whether swiyu-issuer keeps a local copy of the DIDLog for offline operation. Default lean: no — fetch on demand.

## Useful pointers

- Current branch is 49+ commits ahead of `origin/swiyu-issuer`. Push up to whatever point is comfortable before resuming, or keep working locally and push at the next natural milestone.
- swiyu-registries has only the `IdentifierRegistryClient` placeholder so far (constructor + getters; no real HTTP calls). The skeleton compiles and is wired into the workspace.
- `signing_engine_dev_keypairs` and `operation_tasks` tables exist; `issuers` has the new columns. The dev seeded row from migration 0004 still works under the expand-contract scheme.
- swiyu-didtool's `cmd/proof.rs` still does Ed25519 signing locally with `&SigningKey`; that path doesn't need to change for the cherry-pick scope. swiyu-issuer's worker will need a different path through the SigningEngine once the 32-vs-64 trait change is in place.
