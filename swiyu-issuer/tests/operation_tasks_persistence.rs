//! Integration tests for `persistence::operation_tasks`.
//!
//! Each test runs against a freshly created Postgres database created
//! by `sqlx::test`; migrations are applied automatically. Requires
//! `DATABASE_URL` to point to a Postgres instance whose user has
//! `CREATEDB` privilege.

use chrono::Duration;
use serde_json::{Map, json};
use sqlx::PgPool;

use swiyu_issuer::domain::{IssuerId, OperationTask, TaskId, TaskState, TaskType, TenantId};
use swiyu_issuer::persistence::{PersistenceError, operation_tasks};

use swiyu_issuer::test_support::persistence::operation_tasks as test_operation_tasks;
use swiyu_issuer::test_support::persistence::tenants::insert_test_tenant;
use swiyu_issuer::test_support::time::now_micros;

fn fixture_task(tenant_id: TenantId) -> OperationTask {
    OperationTask {
        input: json!({"display_name": "Test Issuer"}),
        ..test_operation_tasks::pending(&tenant_id, TaskType::CreateIssuer)
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn insert_and_find_round_trips(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let task = fixture_task(tenant_id.clone());

    let mut conn = pool.acquire().await.unwrap();
    operation_tasks::insert(&mut conn, &task).await.unwrap();

    let loaded = operation_tasks::find_by_id(&mut conn, &tenant_id, &task.id)
        .await
        .unwrap();
    assert_eq!(loaded.id, task.id);
    assert_eq!(loaded.tenant_id, task.tenant_id);
    assert_eq!(loaded.task_type, TaskType::CreateIssuer);
    assert_eq!(loaded.state, TaskState::Pending);
    assert_eq!(loaded.input, task.input);
    assert!(loaded.step.is_none());
    assert_eq!(loaded.attempts, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn find_by_id_is_tenant_scoped(pool: PgPool) {
    let tenant_a = TenantId::generate();
    let tenant_b = TenantId::generate();
    insert_test_tenant(&pool, &tenant_a).await;
    insert_test_tenant(&pool, &tenant_b).await;
    let task = fixture_task(tenant_a);

    let mut conn = pool.acquire().await.unwrap();
    operation_tasks::insert(&mut conn, &task).await.unwrap();

    let cross_tenant = operation_tasks::find_by_id(&mut conn, &tenant_b, &task.id).await;
    assert!(matches!(cross_tenant, Err(PersistenceError::NotFound)));
}

#[sqlx::test(migrations = "./migrations")]
async fn find_next_acquirable_then_set_acquired_marks_in_progress(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let task = fixture_task(tenant_id.clone());
    {
        let mut conn = pool.acquire().await.unwrap();
        operation_tasks::insert(&mut conn, &task).await.unwrap();
    }

    let now = now_micros();
    let mut tx = pool.begin().await.unwrap();
    let mut found = operation_tasks::find_next_acquirable_for_update(&mut tx, now)
        .await
        .unwrap()
        .expect("a runnable task");
    assert_eq!(found.id, task.id);
    assert_eq!(found.state, TaskState::Pending);

    // Mirror what the worker does: drive the in-memory transition,
    // then persist via set_acquired.
    found.try_acquire(now).unwrap();
    operation_tasks::set_acquired(&mut tx, &found)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let mut conn = pool.acquire().await.unwrap();
    let loaded = operation_tasks::find_by_id(&mut conn, &tenant_id, &task.id)
        .await
        .unwrap();
    assert_eq!(loaded.state, TaskState::InProgress);
    // Pending → InProgress leaves attempts at 0; the bump happens on
    // re-acquisition, not on first pickup.
    assert_eq!(loaded.attempts, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn find_next_acquirable_returns_none_when_no_runnable_tasks(pool: PgPool) {
    let mut tx = pool.begin().await.unwrap();
    let now = now_micros();
    let found = operation_tasks::find_next_acquirable_for_update(&mut tx, now)
        .await
        .unwrap();
    assert!(found.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn find_next_acquirable_skips_tasks_whose_retry_timer_is_in_the_future(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let now = now_micros();
    let mut task = fixture_task(tenant_id);
    task.state = TaskState::InProgress;
    task.next_attempt_at = Some(now + Duration::hours(1));

    {
        let mut conn = pool.acquire().await.unwrap();
        operation_tasks::insert(&mut conn, &task).await.unwrap();
    }

    let mut tx = pool.begin().await.unwrap();
    let found = operation_tasks::find_next_acquirable_for_update(&mut tx, now)
        .await
        .unwrap();
    assert!(
        found.is_none(),
        "task with future next_attempt_at should be skipped"
    );
    drop(tx);

    // Once the timer has passed, the task becomes acquirable.
    let later = now + Duration::hours(2);
    let mut tx = pool.begin().await.unwrap();
    let found = operation_tasks::find_next_acquirable_for_update(&mut tx, later)
        .await
        .unwrap();
    assert_eq!(found.unwrap().id, task.id);
}

#[sqlx::test(migrations = "./migrations")]
async fn set_acquired_persists_in_progress_increment_on_reacquire(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let now = now_micros();
    let mut task = fixture_task(tenant_id.clone());
    // Simulate state after one failed attempt: still InProgress with
    // next_attempt_at in the past so the SELECT picks it up again.
    task.state = TaskState::InProgress;
    task.attempts = 0;
    task.next_attempt_at = Some(now - Duration::seconds(1));

    {
        let mut conn = pool.acquire().await.unwrap();
        operation_tasks::insert(&mut conn, &task).await.unwrap();
    }

    let mut tx = pool.begin().await.unwrap();
    let mut found = operation_tasks::find_next_acquirable_for_update(&mut tx, now)
        .await
        .unwrap()
        .expect("retry timer has passed");
    found.try_acquire(now).unwrap();
    operation_tasks::set_acquired(&mut tx, &found)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let mut conn = pool.acquire().await.unwrap();
    let loaded = operation_tasks::find_by_id(&mut conn, &tenant_id, &task.id)
        .await
        .unwrap();
    assert_eq!(loaded.state, TaskState::InProgress);
    assert_eq!(
        loaded.attempts, 1,
        "InProgress → InProgress acquire bumps attempts"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn find_next_acquirable_skip_locked_lets_second_worker_pass(pool: PgPool) {
    // Two concurrent transactions both call
    // find_next_acquirable_for_update against a single runnable task.
    // The first holds the lock; the second must see the row as
    // unavailable because of FOR UPDATE SKIP LOCKED.
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let task = fixture_task(tenant_id);
    {
        let mut conn = pool.acquire().await.unwrap();
        operation_tasks::insert(&mut conn, &task).await.unwrap();
    }

    let now = now_micros();
    let mut tx_a = pool.begin().await.unwrap();
    let found_a = operation_tasks::find_next_acquirable_for_update(&mut tx_a, now)
        .await
        .unwrap();
    assert!(found_a.is_some(), "first transaction picks the task");

    let mut tx_b = pool.begin().await.unwrap();
    let found_b = operation_tasks::find_next_acquirable_for_update(&mut tx_b, now)
        .await
        .unwrap();
    assert!(
        found_b.is_none(),
        "second transaction must skip the row locked by tx_a"
    );

    // Release tx_a's lock; the row is acquirable again afterwards.
    drop(tx_a);
    let mut tx_c = pool.begin().await.unwrap();
    let found_c = operation_tasks::find_next_acquirable_for_update(&mut tx_c, now)
        .await
        .unwrap();
    assert!(
        found_c.is_some(),
        "row visible again after the holding transaction rolls back"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn advance_step_merges_state_data_and_resets_attempts(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let mut task = fixture_task(tenant_id.clone());
    task.attempts = 3;
    task.error_code = Some("transient".into());
    task.error_message = Some("registry timed out".into());
    task.state_data = json!({"assigned_did": "did:tdw:example:abc"});

    let mut conn = pool.acquire().await.unwrap();
    operation_tasks::insert(&mut conn, &task).await.unwrap();

    let mut patch = Map::new();
    patch.insert("published_log_hash".into(), json!("0xdeadbeef"));

    let now = now_micros();
    operation_tasks::advance_step(&mut conn, &task.id, Some("persist_issuer"), &patch, now)
        .await
        .unwrap();

    let loaded = operation_tasks::find_by_id(&mut conn, &tenant_id, &task.id)
        .await
        .unwrap();
    assert_eq!(loaded.step.as_deref(), Some("persist_issuer"));
    assert_eq!(loaded.attempts, 0);
    assert!(loaded.error_code.is_none());
    assert!(loaded.error_message.is_none());
    // Pre-existing key preserved, new key merged in.
    assert_eq!(
        loaded.state_data["assigned_did"],
        json!("did:tdw:example:abc")
    );
    assert_eq!(loaded.state_data["published_log_hash"], json!("0xdeadbeef"));
}

#[sqlx::test(migrations = "./migrations")]
async fn schedule_retry_records_backoff_and_error_without_bumping_attempts(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let mut task = fixture_task(tenant_id.clone());
    task.attempts = 4;
    let mut conn = pool.acquire().await.unwrap();
    operation_tasks::insert(&mut conn, &task).await.unwrap();

    let now = now_micros();
    let next = now + Duration::minutes(2);
    operation_tasks::schedule_retry(
        &mut conn,
        &task.id,
        next,
        "registry_unavailable",
        "503 from registry",
        now,
    )
    .await
    .unwrap();

    let loaded = operation_tasks::find_by_id(&mut conn, &tenant_id, &task.id)
        .await
        .unwrap();
    // schedule_retry no longer bumps attempts — the increment lives
    // in OperationTask::try_acquire, applied on the next pickup.
    assert_eq!(loaded.attempts, 4);
    assert_eq!(loaded.next_attempt_at, Some(next));
    assert_eq!(loaded.error_code.as_deref(), Some("registry_unavailable"));
    assert_eq!(loaded.error_message.as_deref(), Some("503 from registry"));
}

#[sqlx::test(migrations = "./migrations")]
async fn set_terminal_state_persists_failed_state_with_error_pair(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let mut task = fixture_task(tenant_id.clone());
    let mut conn = pool.acquire().await.unwrap();
    operation_tasks::insert(&mut conn, &task).await.unwrap();

    let now = now_micros();
    // Simulate the in-memory mutation that `OperationTask::try_fail`
    // performs in the worker, then persist via `set_terminal_state`.
    task.state = TaskState::Failed;
    task.error_code = Some("exhausted".into());
    task.error_message = Some("retry cap hit".into());
    task.next_attempt_at = None;
    task.updated_at = now;
    task.completed_at = Some(now);

    operation_tasks::set_terminal_state(&mut conn, &task)
        .await
        .unwrap();

    let loaded = operation_tasks::find_by_id(&mut conn, &tenant_id, &task.id)
        .await
        .unwrap();
    assert_eq!(loaded.state, TaskState::Failed);
    assert_eq!(loaded.error_code.as_deref(), Some("exhausted"));
    assert_eq!(loaded.error_message.as_deref(), Some("retry cap hit"));
    assert_eq!(loaded.completed_at, Some(now));
    assert!(loaded.next_attempt_at.is_none());
}

// Inserts an `operation_tasks` row by hand so individual columns can hold
// values the typed `insert()` would reject. Used by the decode-failure
// tests below to drive sqlx's Decode path with adversarial inputs.
async fn insert_raw_task_row(
    pool: &PgPool,
    tenant_id: &TenantId,
    task_id: &str,
    task_type: &str,
    state: &str,
    attempts: i32,
) {
    let now = now_micros();
    sqlx::query(
        r#"
        INSERT INTO operation_tasks (
            id, tenant_id, task_type, state,
            attempts, input, state_data,
            created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)
        "#,
    )
    .bind(task_id)
    .bind(tenant_id.bare())
    .bind(task_type)
    .bind(state)
    .bind(attempts)
    .bind(json!({}))
    .bind(json!({}))
    .bind(now)
    .execute(pool)
    .await
    .unwrap();
}

// Walks the std::error::Error source chain looking for `needle` in any
// Display string. Used by the decode-failure tests so they assert on the
// preserved detail without locking in sqlx's exact wrapping format.
fn error_chain_contains(err: &dyn std::error::Error, needle: &str) -> bool {
    let mut current: Option<&dyn std::error::Error> = Some(err);
    while let Some(e) = current {
        if e.to_string().contains(needle) {
            return true;
        }
        current = e.source();
    }
    false
}

#[sqlx::test(migrations = "./migrations")]
async fn find_by_id_surfaces_decode_error_for_bogus_state_column(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let task_id = TaskId::generate();
    insert_raw_task_row(
        &pool,
        &tenant_id,
        task_id.bare(),
        "create_issuer",
        "bogus",
        0,
    )
    .await;

    let mut conn = pool.acquire().await.unwrap();
    let err = operation_tasks::find_by_id(&mut conn, &tenant_id, &task_id)
        .await
        .expect_err("decode of state='bogus' must fail");

    assert!(
        matches!(err, PersistenceError::Db(_)),
        "expected Db(_) wrapping a sqlx ColumnDecode, got {err:?}"
    );
    assert!(
        error_chain_contains(&err, "bogus"),
        "error chain must surface the offending value: {err:?}"
    );
    assert!(
        error_chain_contains(&err, "task state"),
        "error chain must name what failed to decode: {err:?}"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn find_by_id_surfaces_decode_error_for_bogus_task_type_column(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let task_id = TaskId::generate();
    insert_raw_task_row(
        &pool,
        &tenant_id,
        task_id.bare(),
        "compress_log",
        "pending",
        0,
    )
    .await;

    let mut conn = pool.acquire().await.unwrap();
    let err = operation_tasks::find_by_id(&mut conn, &tenant_id, &task_id)
        .await
        .expect_err("decode of task_type='compress_log' must fail");

    assert!(
        error_chain_contains(&err, "compress_log"),
        "error chain must surface the offending value: {err:?}"
    );
    assert!(
        error_chain_contains(&err, "task type"),
        "error chain must name what failed to decode: {err:?}"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn find_by_id_surfaces_decode_error_for_negative_attempts(pool: PgPool) {
    // The `attempts` column is INTEGER (i32) but the field is u32. The
    // `#[sqlx(try_from = "i32")]` attribute on `OperationTask::attempts`
    // rejects negatives at decode time; this test pins that invariant.
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let task_id = TaskId::generate();
    insert_raw_task_row(
        &pool,
        &tenant_id,
        task_id.bare(),
        "create_issuer",
        "pending",
        -1,
    )
    .await;

    let mut conn = pool.acquire().await.unwrap();
    let err = operation_tasks::find_by_id(&mut conn, &tenant_id, &task_id)
        .await
        .expect_err("decode of attempts=-1 must fail (u32 cannot hold a negative)");

    assert!(matches!(err, PersistenceError::Db(_)), "got {err:?}");
}

#[sqlx::test(migrations = "./migrations")]
async fn find_by_id_surfaces_decode_error_for_invalid_id_column(pool: PgPool) {
    // The `id` column stores the bare base58 body. A non-base58
    // character must be rejected at Decode time by the `from_bare`
    // validator wired into the `define_id!` macro's Decode impl.
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    // Insert a row whose id contains 'O' (excluded from the Bitcoin
    // base58 alphabet). The query filter still matches because both
    // sides use the same string.
    let bad_id = "Obviously_not_b58";
    insert_raw_task_row(&pool, &tenant_id, bad_id, "create_issuer", "pending", 0).await;

    // Round-trip the bad id through TaskId by skipping validation —
    // we need a TaskId value to call find_by_id with, but cannot
    // construct one through `from_bare`. Use a raw SELECT instead.
    let mut conn = pool.acquire().await.unwrap();
    let result: Result<OperationTask, sqlx::Error> = sqlx::query_as::<_, OperationTask>(
        r#"
        SELECT id, tenant_id, task_type, state, step,
               attempts, next_attempt_at,
               error_code, error_message,
               input, state_data,
               result_issuer_id,
               created_at, updated_at, completed_at
        FROM operation_tasks
        WHERE id = $1
        "#,
    )
    .bind(bad_id)
    .fetch_one(&mut *conn)
    .await;

    let err = result.expect_err("decode of id='Obviously_not_b58' must fail");
    let err_chain: &dyn std::error::Error = &err;
    assert!(
        error_chain_contains(err_chain, "non-base58")
            || error_chain_contains(err_chain, "identifier"),
        "error chain must explain the rejected id: {err:?}"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn set_terminal_state_persists_completed_state_with_result_issuer_id(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let mut task = fixture_task(tenant_id.clone());
    let result_issuer_id = IssuerId::generate();
    task.result_issuer_id = Some(result_issuer_id.clone());

    let mut conn = pool.acquire().await.unwrap();
    operation_tasks::insert(&mut conn, &task).await.unwrap();

    let now = now_micros();
    // Simulate the in-memory mutation that `OperationTask::try_complete`
    // performs in the worker, then persist via `set_terminal_state`.
    task.state = TaskState::Completed;
    task.error_code = None;
    task.error_message = None;
    task.next_attempt_at = None;
    task.updated_at = now;
    task.completed_at = Some(now);

    operation_tasks::set_terminal_state(&mut conn, &task)
        .await
        .unwrap();

    let loaded = operation_tasks::find_by_id(&mut conn, &tenant_id, &task.id)
        .await
        .unwrap();
    assert_eq!(loaded.state, TaskState::Completed);
    assert_eq!(loaded.result_issuer_id, Some(result_issuer_id));
    assert_eq!(loaded.completed_at, Some(now));
}
