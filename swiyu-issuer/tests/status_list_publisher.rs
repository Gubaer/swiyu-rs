//! Integration tests for `worker::StatusListPublisher::run_round`.
//!
//! Drives single rounds against a real Postgres pool (`sqlx::test`)
//! and the real `DevSigningEngine`, with `MockStatusRegistry` standing
//! in for the SWIYU Status Registry.

#[path = "common/mod.rs"]
mod common;
use common::fixtures::SAMPLE_STATUS_REGISTRY_URL;
use common::rng::ConstantRng;

use std::sync::Arc;

use chrono::Utc;
use sqlx::PgPool;

use swiyu_issuer::domain::StatusListId;
use swiyu_issuer::worker::StatusListPublisher;
use swiyu_issuer::worker::test_support::{
    CreateStatusListEntryCall, MockStatusRegistry, UpdateStatusListEntryCall,
};
use swiyu_registries::status::StatusListEntry;

async fn fetch_publish_state(pool: &PgPool, list_id: &StatusListId) -> (i64, i64, i32) {
    sqlx::query_as::<_, (i64, i64, i32)>(
        "SELECT published_version, committed_version, publish_attempts \
         FROM status_lists WHERE id = $1",
    )
    .bind(list_id.bare())
    .fetch_one(pool)
    .await
    .unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn happy_path_bumps_published_version_and_clears_state(pool: PgPool) {
    let secret_engine = common::oauth::test_engine();
    let (_issuer, list, engine) = common::status_lists::seed_dirty_environment(
        &pool,
        &secret_engine,
        SAMPLE_STATUS_REGISTRY_URL,
    )
    .await;
    let list_id = list.id.clone();
    let target = list.committed_version;

    let registry = MockStatusRegistry::new();
    registry.enqueue_update(UpdateStatusListEntryCall::Ok);

    let (_token_server, providers) =
        common::oauth::build_provider_setup(&pool, Arc::clone(&secret_engine)).await;
    let mut publisher = StatusListPublisher::new(
        pool.clone(),
        engine,
        registry,
        providers,
        Box::new(ConstantRng(0)),
    );
    publisher.run_round(list).await.unwrap();

    let (published, committed, attempts) = fetch_publish_state(&pool, &list_id).await;
    assert_eq!(published as u64, target);
    assert_eq!(committed as u64, target);
    assert_eq!(attempts, 0);
    let next: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT next_publish_attempt_at FROM status_lists WHERE id = $1")
            .bind(list_id.bare())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(next.is_none(), "next_publish_attempt_at clears on success");
}

#[sqlx::test(migrations = "./migrations")]
async fn retryable_failure_increments_attempts_and_schedules_retry(pool: PgPool) {
    let secret_engine = common::oauth::test_engine();
    let (_issuer, list, engine) = common::status_lists::seed_dirty_environment(
        &pool,
        &secret_engine,
        SAMPLE_STATUS_REGISTRY_URL,
    )
    .await;
    let list_id = list.id.clone();

    let registry = MockStatusRegistry::new();
    registry.enqueue_update(UpdateStatusListEntryCall::HttpStatus {
        status: 503,
        body: "service unavailable".into(),
    });

    let (_token_server, providers) =
        common::oauth::build_provider_setup(&pool, Arc::clone(&secret_engine)).await;
    let mut publisher = StatusListPublisher::new(
        pool.clone(),
        engine,
        registry,
        providers,
        Box::new(ConstantRng(u64::MAX)),
    );
    let err = publisher.run_round(list).await.unwrap_err();
    assert!(format!("{err}").contains("503"));

    let (published, _committed, attempts) = fetch_publish_state(&pool, &list_id).await;
    assert_eq!(published, 0, "published_version stays put on failure");
    assert_eq!(attempts, 1);
    let last_error: Option<String> =
        sqlx::query_scalar("SELECT last_publish_error FROM status_lists WHERE id = $1")
            .bind(list_id.bare())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(last_error.unwrap().contains("503"));
    let next: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT next_publish_attempt_at FROM status_lists WHERE id = $1")
            .bind(list_id.bare())
            .fetch_one(&pool)
            .await
            .unwrap();
    let next = next.expect("retry path stamps next_publish_attempt_at");
    assert!(
        next > Utc::now(),
        "next_publish_attempt_at is in the future"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn terminal_failure_records_error_and_long_retry(pool: PgPool) {
    let secret_engine = common::oauth::test_engine();
    let (_issuer, list, engine) = common::status_lists::seed_dirty_environment(
        &pool,
        &secret_engine,
        SAMPLE_STATUS_REGISTRY_URL,
    )
    .await;
    let list_id = list.id.clone();

    let registry = MockStatusRegistry::new();
    registry.enqueue_update(UpdateStatusListEntryCall::HttpStatus {
        status: 403,
        body: "forbidden".into(),
    });

    let (_token_server, providers) =
        common::oauth::build_provider_setup(&pool, Arc::clone(&secret_engine)).await;
    let mut publisher = StatusListPublisher::new(
        pool.clone(),
        engine,
        registry,
        providers,
        Box::new(ConstantRng(0)),
    );
    let err = publisher.run_round(list).await.unwrap_err();
    assert!(format!("{err}").contains("403"));

    let (published, _committed, attempts) = fetch_publish_state(&pool, &list_id).await;
    assert_eq!(published, 0);
    assert_eq!(attempts, 1);
    let next: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT next_publish_attempt_at FROM status_lists WHERE id = $1")
            .bind(list_id.bare())
            .fetch_one(&pool)
            .await
            .unwrap();
    let next = next.expect("terminal path stamps a long retry");
    // Long retry is ~1 hour; assert it's at least 5 minutes out so we
    // do not get fooled by the short backoff path on a flaky clock.
    assert!(next > Utc::now() + chrono::Duration::minutes(5));
}

#[sqlx::test(migrations = "./migrations")]
async fn conditional_update_no_ops_when_concurrent_worker_is_ahead(pool: PgPool) {
    let secret_engine = common::oauth::test_engine();
    let (_issuer, list, engine) = common::status_lists::seed_dirty_environment(
        &pool,
        &secret_engine,
        SAMPLE_STATUS_REGISTRY_URL,
    )
    .await;
    let list_id = list.id.clone();
    let target = list.committed_version;

    // Pre-stamp published_version past the target. A concurrent worker
    // would have done this; our run should observe and leave the row
    // alone (no row regression, no additional state change).
    sqlx::query("UPDATE status_lists SET published_version = $1 WHERE id = $2")
        .bind((target as i64) + 5)
        .bind(list_id.bare())
        .execute(&pool)
        .await
        .unwrap();

    let registry = MockStatusRegistry::new();
    registry.enqueue_update(UpdateStatusListEntryCall::Ok);

    let (_token_server, providers) =
        common::oauth::build_provider_setup(&pool, Arc::clone(&secret_engine)).await;
    let mut publisher = StatusListPublisher::new(
        pool.clone(),
        engine,
        registry,
        providers,
        Box::new(ConstantRng(0)),
    );
    // run_round still returns Ok(()) — our conditional UPDATE is a
    // no-op rather than an error.
    publisher.run_round(list).await.unwrap();

    let (published, _committed, _attempts) = fetch_publish_state(&pool, &list_id).await;
    assert_eq!(
        published,
        (target as i64) + 5,
        "concurrent worker's higher published_version is preserved",
    );
}

// Suppress an unused-import warning when only some imports happen to
// be used by the test set above.
#[allow(dead_code)]
fn _phantom(_: CreateStatusListEntryCall, _: StatusListEntry) {}
