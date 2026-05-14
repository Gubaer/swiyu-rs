//! Integration tests for `worker::outcome::apply`.
//!
//! Exercises the four StepOutcome → persistence-call paths against a
//! real Postgres pool. Migrations and a clean database are provided
//! by `sqlx::test`; requires `DATABASE_URL` to point to a Postgres
//! instance whose user has `CREATEDB` privilege.

use chrono::Duration;
use serde_json::{Map, json};
use sqlx::PgPool;

use swiyu_issuer::domain::{OperationTask, StepOutcome, StepResult, TaskState, TaskType, TenantId};
use swiyu_issuer::persistence::operation_tasks;
use swiyu_issuer::test_support::persistence::operation_tasks as test_operation_tasks;
use swiyu_issuer::test_support::persistence::tenants::insert_test_tenant;
use swiyu_issuer::test_support::time::now_micros;
use swiyu_issuer::test_support::worker::ConstantRng;
use swiyu_issuer::worker::outcome;

fn task_with_age(tenant_id: &TenantId, age: Duration, attempts: u32) -> OperationTask {
    let created_at = now_micros() - age;
    OperationTask {
        state: TaskState::InProgress,
        step: Some("allocate_did".into()),
        attempts,
        input: json!({"description": "x", "display_name": "X"}),
        created_at,
        updated_at: created_at,
        ..test_operation_tasks::pending(tenant_id, TaskType::CreateIssuer)
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn done_advances_step_and_merges_patch(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let mut task = task_with_age(&tenant_id, Duration::seconds(10), 0);
    test_operation_tasks::insert(&pool, &task).await;

    let mut patch = Map::new();
    patch.insert(
        "assigned_did_url".into(),
        json!("https://reg.example/api/v1/did/abc/did.jsonl"),
    );
    patch.insert("assigned_identifier".into(), json!("abc"));

    let mut conn = pool.acquire().await.unwrap();
    let mut rng = ConstantRng(0);
    outcome::apply(
        &mut conn,
        &mut task,
        Some("generate_keys"),
        StepOutcome::Done(StepResult {
            state_data_patch: patch,
        }),
        now_micros(),
        &mut rng,
    )
    .await
    .unwrap();

    let loaded = operation_tasks::find_by_id(&mut conn, &tenant_id, &task.id)
        .await
        .unwrap();
    assert_eq!(loaded.step.as_deref(), Some("generate_keys"));
    assert_eq!(loaded.attempts, 0);
    assert!(loaded.next_attempt_at.is_none());
    assert!(loaded.error_code.is_none());
    assert!(loaded.error_message.is_none());
    assert_eq!(
        loaded.state_data["assigned_did_url"],
        "https://reg.example/api/v1/did/abc/did.jsonl",
    );
    assert_eq!(loaded.state_data["assigned_identifier"], "abc");
}

#[sqlx::test(migrations = "./migrations")]
async fn retry_within_cap_schedules_next_attempt_without_bumping_attempts(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let mut task = task_with_age(&tenant_id, Duration::hours(1), 2);
    test_operation_tasks::insert(&pool, &task).await;

    let now = now_micros();
    let mut conn = pool.acquire().await.unwrap();
    let mut rng = ConstantRng(u64::MAX);
    outcome::apply(
        &mut conn,
        &mut task,
        None,
        StepOutcome::Retry {
            error_code: "registry_5xx".into(),
            error_message: "503 from registry".into(),
        },
        now,
        &mut rng,
    )
    .await
    .unwrap();

    let loaded = operation_tasks::find_by_id(&mut conn, &tenant_id, &task.id)
        .await
        .unwrap();
    assert_eq!(loaded.state, TaskState::InProgress);
    // schedule_retry leaves attempts alone; the bump happens on the
    // next try_acquire when the worker picks the task back up.
    assert_eq!(loaded.attempts, 2);
    let next = loaded.next_attempt_at.expect("next_attempt_at set");
    assert!(next >= now);
    // The just-failed attempt was task.attempts + 1 = 3, so the
    // backoff ceiling is 60_000 << 3 = 480_000 ms = 8 min.
    assert!(next <= now + Duration::minutes(8) + Duration::seconds(1));
    assert_eq!(loaded.error_code.as_deref(), Some("registry_5xx"));
    assert_eq!(loaded.error_message.as_deref(), Some("503 from registry"));
}

#[sqlx::test(migrations = "./migrations")]
async fn retry_past_cap_marks_failed(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let mut task = task_with_age(&tenant_id, Duration::hours(25), 17);
    test_operation_tasks::insert(&pool, &task).await;

    let now = now_micros();
    let mut conn = pool.acquire().await.unwrap();
    let mut rng = ConstantRng(0);
    outcome::apply(
        &mut conn,
        &mut task,
        None,
        StepOutcome::Retry {
            error_code: "registry_5xx".into(),
            error_message: "503 from registry".into(),
        },
        now,
        &mut rng,
    )
    .await
    .unwrap();

    let loaded = operation_tasks::find_by_id(&mut conn, &tenant_id, &task.id)
        .await
        .unwrap();
    assert_eq!(loaded.state, TaskState::Failed);
    assert!(loaded.next_attempt_at.is_none());
    assert!(loaded.completed_at.is_some());
    assert_eq!(loaded.error_code.as_deref(), Some("registry_5xx"));
    assert_eq!(loaded.error_message.as_deref(), Some("503 from registry"));
}

#[sqlx::test(migrations = "./migrations")]
async fn terminal_marks_failed_immediately(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let mut task = task_with_age(&tenant_id, Duration::seconds(10), 0);
    test_operation_tasks::insert(&pool, &task).await;

    let now = now_micros();
    let mut conn = pool.acquire().await.unwrap();
    let mut rng = ConstantRng(0);
    outcome::apply(
        &mut conn,
        &mut task,
        None,
        StepOutcome::Terminal {
            error_code: "invalid_input".into(),
            error_message: "description must be non-empty".into(),
        },
        now,
        &mut rng,
    )
    .await
    .unwrap();

    let loaded = operation_tasks::find_by_id(&mut conn, &tenant_id, &task.id)
        .await
        .unwrap();
    assert_eq!(loaded.state, TaskState::Failed);
    assert!(loaded.next_attempt_at.is_none());
    assert!(loaded.completed_at.is_some());
    assert_eq!(loaded.error_code.as_deref(), Some("invalid_input"));
    assert_eq!(
        loaded.error_message.as_deref(),
        Some("description must be non-empty"),
    );
}
