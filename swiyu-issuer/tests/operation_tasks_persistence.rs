//! Integration tests for `persistence::operation_tasks`.
//!
//! Each test runs against a freshly created Postgres database created
//! by `sqlx::test`; migrations are applied automatically. Requires
//! `DATABASE_URL` to point to a Postgres instance whose user has
//! `CREATEDB` privilege.

use chrono::{DateTime, Duration, Timelike, Utc};
use serde_json::{Map, json};
use sqlx::PgPool;

// Postgres TIMESTAMPTZ stores microsecond precision; `Utc::now()` returns
// nanoseconds. Test timestamps are truncated to microseconds so a roundtrip
// through the DB compares equal.
fn now_micros() -> DateTime<Utc> {
    let t = Utc::now();
    let nanos = t.nanosecond();
    t.with_nanosecond(nanos - (nanos % 1_000)).unwrap()
}

use swiyu_issuer::domain::{IssuerId, OperationTask, TaskId, TaskState, TaskType, TenantId};
use swiyu_issuer::persistence::{PersistenceError, operation_tasks};

async fn insert_test_tenant(pool: &PgPool, tenant_id: &TenantId) {
    sqlx::query("INSERT INTO tenants (id) VALUES ($1)")
        .bind(tenant_id.bare())
        .execute(pool)
        .await
        .unwrap();
}

fn fixture_task(tenant_id: TenantId) -> OperationTask {
    let now = now_micros();
    OperationTask {
        id: TaskId::generate(),
        tenant_id,
        task_type: TaskType::CreateIssuer,
        state: TaskState::Pending,
        step: None,
        attempts: 0,
        next_attempt_at: None,
        error_code: None,
        error_message: None,
        input: json!({"display_name": "Test Issuer"}),
        state_data: json!({}),
        result_issuer_id: None,
        created_at: now,
        updated_at: now,
        completed_at: None,
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
async fn acquire_next_picks_pending_task_and_marks_in_progress(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let task = fixture_task(tenant_id.clone());
    let mut conn = pool.acquire().await.unwrap();
    operation_tasks::insert(&mut conn, &task).await.unwrap();

    let now = now_micros();
    let acquired = operation_tasks::acquire_next(&mut conn, now).await.unwrap();
    let acquired = acquired.expect("a runnable task");
    assert_eq!(acquired.id, task.id);
    assert_eq!(acquired.state, TaskState::InProgress);
}

#[sqlx::test(migrations = "./migrations")]
async fn acquire_next_returns_none_when_no_runnable_tasks(pool: PgPool) {
    let mut conn = pool.acquire().await.unwrap();
    let now = now_micros();
    let acquired = operation_tasks::acquire_next(&mut conn, now).await.unwrap();
    assert!(acquired.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn acquire_next_skips_tasks_whose_retry_timer_is_in_the_future(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let now = now_micros();
    let mut task = fixture_task(tenant_id);
    task.state = TaskState::InProgress;
    task.next_attempt_at = Some(now + Duration::hours(1));

    let mut conn = pool.acquire().await.unwrap();
    operation_tasks::insert(&mut conn, &task).await.unwrap();

    let acquired = operation_tasks::acquire_next(&mut conn, now).await.unwrap();
    assert!(
        acquired.is_none(),
        "task with future next_attempt_at should be skipped"
    );

    // Once the timer has passed, the task becomes acquirable.
    let later = now + Duration::hours(2);
    let acquired = operation_tasks::acquire_next(&mut conn, later)
        .await
        .unwrap();
    assert_eq!(acquired.unwrap().id, task.id);
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
async fn schedule_retry_records_backoff_and_error(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let task = fixture_task(tenant_id.clone());
    let mut conn = pool.acquire().await.unwrap();
    operation_tasks::insert(&mut conn, &task).await.unwrap();

    let now = now_micros();
    let next = now + Duration::minutes(2);
    operation_tasks::schedule_retry(
        &mut conn,
        &task.id,
        4,
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
