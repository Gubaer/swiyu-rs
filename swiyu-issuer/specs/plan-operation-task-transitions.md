# Plan: move `OperationTask` state transitions to the aggregate

Apply the "state transitions as methods on the aggregate" convention (see [`impl_domain.md`](impl_domain.md), *Conventions*) to `OperationTask`. Today every transition runs as a direct SQL `UPDATE` in `persistence/operation_tasks.rs`; the aggregate has no `try_*` methods. This is the last remaining violation of the convention after the `Issuer::try_deactivate` refactor (commit `53a0117`).

The work splits into three phases that ship as separate commits. Each commit leaves the workspace green on `cargo fmt --check && cargo clippy -- -D warnings && cargo test`.

## Outcome at the end

- `OperationTask` carries domain-level transition methods covering every lifecycle move: `try_complete`, `try_fail`, and `try_acquire` (the queue-pop transition).
- `persistence/operation_tasks.rs` exposes a `find_next_acquirable_for_update` lookup and narrow writers; the precondition guards in `mark_completed` / `mark_failed` are gone (the aggregate enforces them).
- The worker dispatch loop loads under `FOR UPDATE` (or `FOR UPDATE SKIP LOCKED` for the queue pop), runs the domain transition, persists, commits.
- `OperationTask` is the only aggregate left with a *non-state* operation that still routes through persistence directly: `advance_step` (JSON patch into `state_data`) and `schedule_retry` (bump `next_attempt_at`). These are saga-data accumulation, not state transitions in the DDD sense, and stay as-is per Phase 3 below.

## Phase 1 — Terminal transitions

**Goal:** `mark_completed` and `mark_failed` route through aggregate methods.

Files:

- `domain/operation_task.rs` — add `OperationTask::try_complete(now)` and `OperationTask::try_fail(error_code, error_message, now)`. Both are legal only from `TaskState::InProgress`; both stamp `completed_at` (or `error_*`) onto the in-memory aggregate. Returns `Result<(), DomainError>`.
- `persistence/operation_tasks.rs` — drop the `state IS NOT terminal` precondition guard from `mark_completed` and `mark_failed`; they become narrow writers that persist whatever the aggregate already holds. Renaming to `set_completed_state` / `set_failed_state` would be cleaner but spreads to call sites — keep current names.
- Worker dispatch (`worker/runner.rs`, plus the per-saga error landings) — at every terminal landing, replace `persistence::operation_tasks::mark_failed(...)` with `task.try_fail(...)?; persistence::operation_tasks::mark_failed(&mut tx, &task)`. Same for `mark_completed`.

Tests:

- Unit tests on `OperationTask::try_complete` / `try_fail`: legal from `InProgress`, illegal from `Pending` / `Completed` / `Failed`, error fields stamped correctly, `completed_at` stamped from `now`.
- Existing dispatch integration tests (`tests/dispatch.rs`) stay green — externally observable behaviour is identical.

Acceptance: `cargo test --workspace` green; no clippy warnings; the convention now holds for terminal transitions.

**Commit:** "Move OperationTask terminal transitions to the aggregate (refactoring)"

## Phase 2 — `acquire_next` (the queue-pop)

**Goal:** the queue pop routes through the aggregate while preserving `FOR UPDATE SKIP LOCKED` semantics.

Today: `acquire_next` runs one atomic statement that combines "find next eligible" with "claim it":

```sql
UPDATE operation_tasks
SET state = 'in_progress', ...
WHERE id = (
    SELECT id FROM operation_tasks
    WHERE state IN ('pending', 'in_progress')
    AND ...
    ORDER BY ...
    LIMIT 1
    FOR UPDATE SKIP LOCKED
)
RETURNING ...
```

Two option for the port:

**Option A — Exempt and document.** Keep `acquire_next` as a queue primitive; document in `impl_domain.md` that it's an exception because the queue-pop semantics combine selection and claim into one atomic statement.

**Option B — Full split.**
- `find_next_acquirable_for_update(conn) -> Option<OperationTask>` — returns the next eligible row holding a `FOR UPDATE SKIP LOCKED` lock.
- `OperationTask::try_acquire(now)` — `Pending → InProgress` *or* `InProgress → InProgress` (re-acquisition after retry), bumps `attempts`.
- `set_acquired(conn, &task)` — writes the result back.

Option B preserves SKIP LOCKED as long as the SELECT keeps the modifier; the row lock is held until the surrounding transaction commits, so concurrent workers see the row as locked and skip it. Cost: two round-trips instead of one per worker poll. Negligible at a 1 s poll cadence.

Lean: **Option B**, for full convention compliance. Open question for the user.

Files (option B):

- `domain/operation_task.rs` — `OperationTask::try_acquire(now)` enforcing the state machine and the attempt-counter bump.
- `persistence/operation_tasks.rs` — replace `acquire_next` with `find_next_acquirable_for_update` (SELECT + SKIP LOCKED) and `set_acquired` (UPDATE without state guard).
- Worker dispatch — refactor the poll loop to load → `try_acquire` → `set_acquired` → commit.

Tests:

- Unit tests on `try_acquire`: `Pending → InProgress` first pickup, `InProgress → InProgress` re-acquisition (`attempts` increments), illegal from `Completed` / `Failed`.
- Existing concurrency tests in `tests/dispatch.rs` (multiple workers race for the same task, expect one to win and the others to skip) must still pass.

Risk: medium. The worker dispatch loop is the system's nervous system. The most likely regression is forgetting the `InProgress → InProgress` re-acquisition case in `try_acquire`, which would silently break retry. The existing `dispatch.rs` integration tests cover this — verify they fail before the fix and pass after.

Acceptance: `cargo test --workspace` green; concurrency tests in `tests/dispatch.rs` pass; the convention now holds for every `OperationTask` lifecycle transition.

**Commit:** "Move OperationTask acquire_next through the aggregate (refactoring)"

## Phase 3 — `advance_step` and `schedule_retry` (skip, recommended)

`advance_step` merges a JSON patch into `state_data`; `schedule_retry` bumps `next_attempt_at` and possibly increments `attempts`. Neither is a *state* transition; they are saga-data accumulation. Pulling them into aggregate methods (`task.merge_state_data(patch)`, `task.schedule_retry(when)`) is mostly cosmetic.

**Recommendation: skip.** The convention applies to lifecycle state, not to data writes. Mention in `impl_domain.md` that these are deliberately persistence-side helpers, not aggregate methods.

If included, follow the same shape as Phase 1: aggregate method that mutates the in-memory representation, narrow persistence writer that persists it. Single commit.

## Sequencing rationale

Phase 1 ships first because it's the highest value and lowest risk: the same shape as `Issuer::try_deactivate`, mechanical to apply. Phase 2 ships second because it's the only structurally interesting change (the SKIP LOCKED preservation). Phase 3 is optional and ships last if at all.

The phases are independent — Phase 2 does not depend on Phase 1, and vice versa. Order is recommendation, not requirement. If Phase 2 turns out to be a problem (concurrency regression), Phase 1 still ships independently with no rollback risk.

## Open questions

1. **`acquire_next`: option A (exempt) or option B (full split)?** Lean B for full convention compliance.
2. **Phase 3: include or skip?** Lean skip — `advance_step` and `schedule_retry` are not lifecycle transitions.
3. **Naming.** Keep `mark_completed` / `mark_failed` as-is (smaller blast radius) or rename to `set_completed_state` / `set_failed_state` for consistency with `Issuer::set_state`?

## Total

Two to three commits, each green on `cargo fmt --check && cargo clippy -- -D warnings && cargo test`. Estimated effort: ~half a day for Phase 1, ~half a day for Phase 2 (including the concurrency-test verification step), ~1 hour for Phase 3 if included.
