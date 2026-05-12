# Implementation: Issuer

This document describes how the issuer aspect (see [`aspect-issuer.md`](aspect-issuer.md)) is realised inside the `swiyu-issuer` crate. It is incremental — sections will be added as we work through the design. Endpoints (HTTP shapes, error codes, OpenAPI) live in [`impl_api_management.md`](impl_api_management.md); this document covers the domain types, persistence schema, worker, and registry interaction that the endpoints sit on top of.

## Module layout

New code added by this slice:

- `swiyu-issuer/src/domain/issuer.rs` — revised `Issuer` aggregate with the key-triple, lifecycle state, and required identification fields.
- `swiyu-issuer/src/domain/operation_task/` — `OperationTask` aggregate, task state, task type, classification helpers.
- `swiyu-issuer/src/persistence/issuers.rs` — extended with insert/update/find for the new columns.
- `swiyu-issuer/src/persistence/operation_tasks.rs` — new persistence module for the task queue.
- `swiyu-issuer/src/worker/` — task-dispatching worker, runs as a `tokio::spawn`-ed task alongside the management API server.
- `swiyu-issuer/src/api_management/` — new handlers for `POST /api/v1/issuers`, `GET /api/v1/issuers`, `GET /api/v1/issuers/{id}`, plus task polling endpoints. Wired into the existing `router(state)`.

The HTTP client for the SWIYU Identifier Registry lives in a separate workspace crate, [`swiyu-registries`](../../swiyu-registries/), not inside `swiyu-issuer`. It is shared infrastructure: a future verifier service, an async-friendly variant of `swiyu-didtool`, and the eventual Status- and Trust-Registry clients all live there too. swiyu-issuer pulls it in as a dependency with the `identifier` feature enabled.

DIDLog entry construction (the bytes to sign and POST) is extracted from `swiyu-didtool` into `swiyu-core` and consumed from there. See [DIDLog construction](#didlog-construction) below.

## Domain types

### `Issuer`

The current `Issuer` struct (`signing_key_id: String` pointing into the legacy `swiyu-didtool` keystore) is replaced by:

```rust
pub struct Issuer {
    pub id: IssuerId,
    pub tenant_id: TenantId,
    pub did: String,
    pub state: IssuerState,
    pub authorized_key_id: KeyPairId,
    pub authentication_key_id: KeyPairId,
    pub assertion_key_id: KeyPairId,
    pub display_name: String,
    pub description: String,
}

pub enum IssuerState {
    Active,
    Deactivated,
}
```

Reads access the three `KeyPairId`s as named fields rather than a map keyed by `KeyRole`. The flat layout matches the always-three-keys invariant of [`aspect-issuer.md`](aspect-issuer.md) and avoids the awkwardness of `HashMap<KeyRole, KeyPairId>` lookups that are statically guaranteed to succeed.

A small helper resolves a `KeyRole` to the matching field for the cases (DIDLog construction, signing) where the role is known dynamically:

```rust
impl Issuer {
    pub fn key_id_for_role(&self, role: KeyRole) -> KeyPairId {
        match role {
            KeyRole::Authorized => self.authorized_key_id,
            KeyRole::Authentication => self.authentication_key_id,
            KeyRole::Assertion => self.assertion_key_id,
        }
    }
}
```

### `OperationTask`

```rust
pub struct OperationTask {
    pub id: TaskId,
    pub tenant_id: TenantId,
    pub task_type: TaskType,
    pub state: TaskState,
    pub step: Option<String>,
    pub attempts: u32,
    pub next_attempt_at: Option<DateTime<Utc>>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub input: serde_json::Value,
    pub state_data: serde_json::Value,
    pub result_issuer_id: Option<IssuerId>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

pub enum TaskState {
    Pending,
    InProgress,
    Completed,
    Failed,
}

pub enum TaskType {
    CreateIssuer,
    // RotateKeys, DeactivateIssuer in subsequent slices
}
```

`input` carries the original request body so the worker can re-derive parameters after a crash. `state_data` carries intermediate results that must survive worker crashes — the assigned DID after `allocate_did`, the published-entry hash after `publish_log`, etc. Both are typed as `serde_json::Value` at the persistence boundary; the worker deserialises into typed structs internally.

### `TaskId`

New ID newtype following the project bs58/prefix convention used for `IssuerId`, `TenantId`, etc. (per [`domain/ids.rs`](../src/domain/ids.rs)). Prefix: `task`. Tasks are user-visible and may appear in management-API responses, so the bs58/prefix scheme applies (in contrast to `KeyPairId`, which is engine-internal and uses UUIDs).

### Step classification

Step retryability is encoded as a small enum returned by the per-step execution functions, not stored on the task row:

```rust
pub enum StepOutcome {
    Done(StepResult),
    Retry { error_code: String, error_message: String },
    Terminal { error_code: String, error_message: String },
}
```

`StepResult` carries the data the next step needs (e.g. the assigned DID after `allocate_did`); the worker writes it into `state_data` before advancing.

## Persistence schema

Two migration files: one extending `issuers`, one creating `operation_tasks`.

### Migration: `issuers` extension

```sql
-- New required identification fields and key-triple columns.
ALTER TABLE issuers
    ADD COLUMN state TEXT NOT NULL DEFAULT 'active',
    ADD COLUMN description TEXT,
    ADD COLUMN authorized_key_id UUID,
    ADD COLUMN authentication_key_id UUID,
    ADD COLUMN assertion_key_id UUID;

-- The seeded dev issuer (from migration 0004) has signing_key_id set
-- but no key-triple columns and no description. It stays nullable for
-- the duration of v0.1.x; the OIDC binary continues to use
-- signing_key_id for that one fixture row. New issuers created through
-- the task flow populate the new columns; signing_key_id stays NULL.
-- The signing_key_id column is removed in a later slice once the OIDC
-- binary has migrated to KeyPairId-based signing.
--
-- The logo_uri and locale columns (also added by migration 0004) are
-- no longer part of the Issuer domain model. They stay in the table
-- for now because the OIDC metadata handler still reads them; they
-- will be dropped together with signing_key_id once the OIDC binary
-- is migrated.
```

### Migration: `operation_tasks`

```sql
CREATE TABLE operation_tasks (
    id TEXT PRIMARY KEY,                       -- bare bs58 of TaskId
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    task_type TEXT NOT NULL,                   -- 'create_issuer'
    state TEXT NOT NULL,                       -- 'pending' | 'in_progress' | 'completed' | 'failed'
    step TEXT,
    attempts INT NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ,
    error_code TEXT,
    error_message TEXT,
    input JSONB NOT NULL,
    state_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    result_issuer_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX operation_tasks_dispatch
    ON operation_tasks (next_attempt_at NULLS FIRST, created_at)
    WHERE state IN ('pending', 'in_progress');

CREATE INDEX operation_tasks_tenant
    ON operation_tasks (tenant_id, created_at DESC);
```

The `dispatch` partial index keeps the worker's "find next runnable task" query fast even as completed/failed rows accumulate.

## Worker

A single `tokio::spawn`-ed task launched by `swiyu-issuer-mgmtapi` at startup. The worker code lives in `swiyu-issuer/src/worker/` so it is reachable from the binary's `main` and from integration tests.

### Dispatch loop (sketch)

```rust
loop {
    let next = persistence::operation_tasks::acquire_next(&pool, now()).await?;
    match next {
        Some(task) => execute(task, &deps).await,
        None => sleep_until_next_runnable_or_poll_interval().await,
    }
}
```

`acquire_next` is a single SQL statement that atomically picks the oldest runnable task (state in {`pending`, `in_progress`}, `next_attempt_at IS NULL OR next_attempt_at <= now()`) and stamps it as `in_progress`. Single-worker for v1, so no `FOR UPDATE SKIP LOCKED` is strictly needed, but the query is written that way to make the future multi-worker switch a non-event.

Dispatch is **polling-based** (a short sleep on the empty path; default 1s). Postgres `LISTEN`/`NOTIFY` for low-latency wake-up on new task insertion is a possible future optimisation, but the expected v1 task volume does not justify the extra wiring.

### Per-step execution

Each `task_type` resolves to an executor that maps the current `step` to a step function. For `CreateIssuer`:

```rust
match step {
    None | Some("allocate_did") => execute_allocate_did(...).await,
    Some("generate_keys")        => execute_generate_keys(...).await,
    Some("build_initial_log")    => execute_build_initial_log(...).await,
    Some("publish_log")          => execute_publish_log(...).await,
    Some("persist_issuer")       => execute_persist_issuer(...).await,
    Some(other) => terminal_failure("invalid step: {other}"),
}
```

Each step function returns `StepOutcome`. The worker then:

1. On `StepOutcome::Done(result)`: writes `result` into `state_data`, advances `step` to the next, resets `attempts` to 0, schedules the worker to pick the task up immediately.
2. On `StepOutcome::Retry`: increments `attempts`, computes `next_attempt_at = now() + backoff(attempts)`, records `error_code`/`error_message`. If the cumulative elapsed time exceeds the cap, escalates to `Failed` instead.
3. On `StepOutcome::Terminal`: marks the task `Failed` with the error.

### Backoff

Exponential with full jitter: `delay = random_between(0, base * 2^attempts)`, with `base = 1m` and `max = 1h`. Maximum elapsed wall-clock per task: **24 hours**, hard-coded for v1. The cap is measured from `created_at`; once the task has been alive for 24 hours and is still not in a terminal state, the next failed step transitions it to `Failed` instead of scheduling another retry.

### Crash recovery

If the worker is restarted, the next dispatch loop iteration picks up tasks whose state is `in_progress` and whose `next_attempt_at` is null or past, just like it would for a `pending` task. The `state_data` JSONB carries everything done so far, so each step function is safe to re-enter — see [Step idempotency](#step-idempotency).

### Step idempotency

Each step function checks `state_data` first to see whether the side effect it would produce has already happened:

- `allocate_did`: if `state_data.assigned_did` is set, treat as `Done` immediately. Otherwise call the registry and record the assigned DID.
- `generate_keys`: if `state_data.key_ids` is set, treat as `Done`. Otherwise generate a new triple and record the three `KeyPairId`s. (Caveat: a worker crash *after* `SigningEngine.generate_keypair` returned but *before* `state_data` was written leaves an orphan key in the engine. Acceptable; orphans cost nothing in the dev engine and can be cleaned up by a periodic job in production.)
- `build_initial_log`: deterministic and local; no external side effects. Always re-run; cheap.
- `publish_log`: if `state_data.published_log_hash` is set, treat as `Done`. Otherwise POST to the registry, recording the hash on success.
- `persist_issuer`: if an issuer row with the task's `result_issuer_id` already exists, treat as `Done`. Otherwise insert the row.

### Why hand-rolled

The Rust ecosystem has competent job-queue crates ([`apalis`](https://crates.io/crates/apalis) is the most mature; [`sqlxmq`](https://crates.io/crates/sqlxmq) is the closest `sqlx`-native option). They don't fit cleanly here because our task is a **saga**, not a single-shot job: ordered steps, intermediate results that must survive a worker crash, and per-step idempotency across an HTTP boundary that cannot be replayed.

Mapping the saga onto a job queue forces an unattractive choice — either replay the whole choreography on retry (re-allocating DIDs and republishing log entries, even when those side effects already succeeded), or split it into chained per-step jobs and lose the unified "task" abstraction the business application polls. Either way the saga substrate is ours to write; the library would own only the dispatch loop and retry timer (under 100 lines combined), at the cost of an imposed schema and an extra dependency.

Pure-FSM crates (`statig`, `rust-fsm`) do not apply: our FSM has four BA-facing states; the complexity is in persistence and step orchestration, not the transition graph. Mature workflow / saga engines do not exist in Rust today.

We revisit if any of the following becomes real: multi-task concurrency demands beyond `SELECT ... FOR UPDATE SKIP LOCKED`; a dozen task types sharing retry/backoff machinery; operator visibility needs that grow past direct DB inspection.

## Registry interaction

The HTTP client for the SWIYU Identifier Registry lives in the [`swiyu-registries`](../../swiyu-registries/) workspace crate, under `swiyu-registries::identifier::IdentifierRegistryClient`. swiyu-issuer pulls it in as a dependency:

```toml
swiyu-registries = { path = "../swiyu-registries", features = ["identifier"], default-features = false }
```

The client is async (`reqwest` + `tokio`), in contrast to `swiyu-didtool`'s existing blocking client which lives in its own crate. They are not consolidated — the runtime difference is real, and migrating `swiyu-didtool` to share this crate is its own (later) slice.

### Operations used by v1

- `allocate_did(partner_id) -> Did` — POSTs to the registry's allocation endpoint; returns the assigned DID.
- `publish_log_entry(did, signed_entry) -> EntryHash` — POSTs the signed initial DIDLog entry; returns the registry's accepted-entry identifier.

A `fetch_log` operation will be added when read-side flows (verifier, rotation, deactivation) need it.

### Configuration

The client is constructed in the `swiyu-issuer-mgmtapi` startup path from environment variables:

- `SWIYU_IDENTIFIER_REGISTRY_URL` — base URL of the SWIYU Identifier Registry.
- `SWIYU_ACCESS_TOKEN` — bearer token for the registry API.
- `SWIYU_PARTNER_ID` — the issuer's partner-id at the registry.

These mirror the variables already used by `swiyu-didtool` and stay in swiyu-issuer's binary configuration; the swiyu-registries crate exposes a constructor that accepts them as arguments and is itself env-agnostic.

### Failure classification

The client returns the shared `swiyu_registries::common::RegistryError` (variants: `Transport`, `HttpStatus { status, body }`, `Decode`). The error carries an `is_retryable()` method used directly by the worker's step functions to choose between `StepOutcome::Retry` and `StepOutcome::Terminal`:

- `Transport` → retryable.
- `HttpStatus` with `status == 429` or `status >= 500` → retryable.
- `HttpStatus` with any other 4xx → terminal.
- `Decode` → terminal (unexpected response shape; waiting will not help).

## DIDLog construction

The byte-level construction of DIDLog entries (initial entry, rotation entry, deactivation entry) is extracted from `swiyu-didtool` into `swiyu-core` and consumed from both crates. The extracted code is value-object-only (no I/O, no async), so it lives naturally in the shared crate.

The HTTP client stays per-consumer: `swiyu-didtool` continues to use blocking `reqwest`; `swiyu-issuer` gets the async variant.

The extraction itself is its own slice, ordered before the issuer-management work that depends on it.

## Endpoints

Defined in [`impl_api_management.md`](impl_api_management.md). This spec deliberately does not duplicate request/response shapes; it describes the substrate they sit on.

The endpoints exposed by this slice:

- `POST /api/v1/issuers` — submit a `CreateIssuer` task; returns a `task_id`.
- `GET /api/v1/issuers` — list issuers belonging to the tenant.
- `GET /api/v1/issuers/{issuer_id}` — fetch a single issuer.
- `GET /api/v1/operation-tasks/{task_id}` — poll task state.

The owning tenant is **never in the URL**. It is derived from the API token by the existing `TenantContext` extractor (see [`impl_api_management.md`](impl_api_management.md) and [`impl_auth.md`](impl_auth.md)). This matches the convention already in place for credential-offer endpoints; cross-tenant access returns `404`.

Endpoints for `rotate_keys` and `deactivate_issuer` ship in subsequent slices.

## Tests

- Unit tests inside the worker module exercising each step function against in-memory mocks of the registry client and the SigningEngine.
- Integration tests under `swiyu-issuer/tests/` driving full task choreographies with a real Postgres pool (via `sqlx::test`) and a stubbed registry. Each task type gets its own happy-path test plus retry-on-registry-failure and resume-after-crash variants.
- Specifics (helper builders, stubbing strategy for the registry client) settle during the first implementation pass.

## Out of scope for v1

- **Operator admin endpoints** for tasks (cancel, force-retry, inspect `state_data`). Operators interact with `operation_tasks` directly via DB.
- **Callback URLs** for terminal-state notification. Polling is the only delivery mechanism in v1.
- **Multi-worker dispatch.** The single in-process worker is enough for the expected volume; multi-worker `SELECT ... FOR UPDATE SKIP LOCKED` lands when needed.
- **Migration of the OIDC binary off `signing_key_id`.** The legacy column stays nullable; the OIDC binary continues to use the `swiyu-didtool` keystore for the seeded dev row.
- **Per-task-type backoff configurability.** The 24-hour cap and the `1m`/`1h` backoff curve are global. Per-task-type tuning (e.g. faster backoff for `rotate_keys`) lands when needed.
