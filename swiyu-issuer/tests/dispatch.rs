//! Integration tests for `worker::dispatch::apply_outcome`.
//!
//! Exercises the four StepOutcome → persistence-call paths against a
//! real Postgres pool. Migrations and a clean database are provided
//! by `sqlx::test`; requires `DATABASE_URL` to point to a Postgres
//! instance whose user has `CREATEDB` privilege.

use chrono::{DateTime, Duration, Timelike, Utc};
use rand_core::RngCore;
use serde_json::{Map, json};
use sqlx::PgPool;

use swiyu_issuer::domain::{
    OperationTask, StepOutcome, StepResult, TaskId, TaskState, TaskType, TenantId,
};
use swiyu_issuer::persistence::operation_tasks;
use swiyu_issuer::worker::dispatch;

// Postgres TIMESTAMPTZ stores microsecond precision; truncate so a
// roundtrip through the DB compares equal to the value we passed in.
fn now_micros() -> DateTime<Utc> {
    let t = Utc::now();
    let nanos = t.nanosecond();
    t.with_nanosecond(nanos - (nanos % 1_000)).unwrap()
}

struct FixedRng(u64);

impl RngCore for FixedRng {
    fn next_u32(&mut self) -> u32 {
        self.0 as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.0
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let bytes = self.0.to_le_bytes();
            let take = chunk.len().min(bytes.len());
            chunk[..take].copy_from_slice(&bytes[..take]);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

async fn insert_test_tenant(pool: &PgPool, tenant_id: &TenantId) {
    sqlx::query("INSERT INTO tenants (id) VALUES ($1)")
        .bind(tenant_id.bare())
        .execute(pool)
        .await
        .unwrap();
}

async fn insert_task(pool: &PgPool, task: &OperationTask) {
    let mut conn = pool.acquire().await.unwrap();
    operation_tasks::insert(&mut conn, task).await.unwrap();
}

fn task_with_age(tenant_id: TenantId, age: Duration, attempts: u32) -> OperationTask {
    let now = now_micros();
    let created_at = now - age;
    OperationTask {
        id: TaskId::generate(),
        tenant_id,
        task_type: TaskType::CreateIssuer,
        state: TaskState::InProgress,
        step: Some("allocate_did".into()),
        attempts,
        next_attempt_at: None,
        error_code: None,
        error_message: None,
        input: json!({"description": "x", "display_name": "X"}),
        state_data: json!({}),
        result_issuer_id: None,
        created_at,
        updated_at: created_at,
        completed_at: None,
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn done_advances_step_and_merges_patch(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let task = task_with_age(tenant_id.clone(), Duration::seconds(10), 0);
    insert_task(&pool, &task).await;

    let mut patch = Map::new();
    patch.insert("assigned_did".into(), json!("did:tdw:reg.example:abc"));
    patch.insert("assigned_identifier".into(), json!("abc"));

    let mut conn = pool.acquire().await.unwrap();
    let mut rng = FixedRng(0);
    dispatch::apply_outcome(
        &mut conn,
        &task,
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
    assert_eq!(loaded.state_data["assigned_did"], "did:tdw:reg.example:abc");
    assert_eq!(loaded.state_data["assigned_identifier"], "abc");
}

#[sqlx::test(migrations = "./migrations")]
async fn retry_within_cap_increments_attempts_and_schedules(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let task = task_with_age(tenant_id.clone(), Duration::hours(1), 2);
    insert_task(&pool, &task).await;

    let now = now_micros();
    let mut conn = pool.acquire().await.unwrap();
    let mut rng = FixedRng(u64::MAX);
    dispatch::apply_outcome(
        &mut conn,
        &task,
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
    assert_eq!(loaded.attempts, 3);
    let next = loaded.next_attempt_at.expect("next_attempt_at set");
    assert!(next >= now);
    // attempts becomes 3 -> ceiling = 60_000 << 3 = 480_000 ms = 8 min.
    assert!(next <= now + Duration::minutes(8) + Duration::seconds(1));
    assert_eq!(loaded.error_code.as_deref(), Some("registry_5xx"));
    assert_eq!(loaded.error_message.as_deref(), Some("503 from registry"));
}

#[sqlx::test(migrations = "./migrations")]
async fn retry_past_cap_marks_failed(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let task = task_with_age(tenant_id.clone(), Duration::hours(25), 17);
    insert_task(&pool, &task).await;

    let now = now_micros();
    let mut conn = pool.acquire().await.unwrap();
    let mut rng = FixedRng(0);
    dispatch::apply_outcome(
        &mut conn,
        &task,
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
    let task = task_with_age(tenant_id.clone(), Duration::seconds(10), 0);
    insert_task(&pool, &task).await;

    let now = now_micros();
    let mut conn = pool.acquire().await.unwrap();
    let mut rng = FixedRng(0);
    dispatch::apply_outcome(
        &mut conn,
        &task,
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
