#![allow(dead_code)] // not every test module pulls in every helper

use chrono::Utc;
use serde_json::json;
use sqlx::PgPool;

use swiyu_issuer::domain::{OperationTask, TaskId, TaskState, TaskType, TenantId};
use swiyu_issuer::persistence;

/// Baseline `OperationTask` fixture for tests. Returns a Pending task
/// with no `step`, no `attempts`, no `result_issuer_id`, and empty
/// `input` / `state_data`. Callers override the fields they actually
/// care about via struct-update syntax:
/// `OperationTask { state, input, ..common::operation_tasks::pending(t, ty) }`.
pub fn pending(tenant_id: &TenantId, task_type: TaskType) -> OperationTask {
    let now = Utc::now();
    OperationTask {
        id: TaskId::generate(),
        tenant_id: tenant_id.clone(),
        task_type,
        state: TaskState::Pending,
        step: None,
        attempts: 0,
        next_attempt_at: None,
        error_code: None,
        error_message: None,
        input: json!({}),
        state_data: json!({}),
        result_issuer_id: None,
        created_at: now,
        updated_at: now,
        completed_at: None,
    }
}

pub async fn insert(pool: &PgPool, task: &OperationTask) {
    let mut conn = pool.acquire().await.unwrap();
    persistence::operation_tasks::insert(&mut conn, task)
        .await
        .unwrap();
}

pub async fn wait_for_state(
    pool: &PgPool,
    tenant_id: &TenantId,
    task_id: &TaskId,
    target: TaskState,
    timeout: std::time::Duration,
) -> OperationTask {
    let start = std::time::Instant::now();
    loop {
        let mut conn = pool.acquire().await.unwrap();
        let task = persistence::operation_tasks::find_by_id(&mut conn, tenant_id, task_id)
            .await
            .unwrap();
        if task.state == target {
            return task;
        }
        if start.elapsed() >= timeout {
            panic!(
                "wait_for_state timed out after {:?}: target={:?}, last={:?}",
                timeout, target, task.state,
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}
