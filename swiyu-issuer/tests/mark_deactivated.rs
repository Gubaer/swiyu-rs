//! Integration tests for `worker::deactivate_issuer::mark_deactivated`.
//!
//! Runs against a freshly created Postgres database via `sqlx::test`;
//! migrations apply automatically. Requires `DATABASE_URL` to point
//! to a Postgres instance whose user has `CREATEDB` privilege.

use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use sqlx::PgPool;

use swiyu_issuer::domain::{
    CredentialOffer, CredentialOfferState, Issuer, IssuerId, IssuerState, PreAuthCode, StepOutcome,
    TenantId,
};
use swiyu_issuer::persistence::{credential_offers, issuers};
use swiyu_issuer::worker::deactivate_issuer::mark_deactivated::execute_mark_deactivated;

#[path = "common/mod.rs"]
mod common;
use common::tenants::insert_test_tenant;

async fn insert_test_issuer(pool: &PgPool, tenant_id: &TenantId) -> IssuerId {
    let issuer = Issuer {
        did: "did:tdw:scid:example.com:fixture".into(),
        ..common::issuers::active_with_keys(tenant_id)
    };
    let id = issuer.id.clone();
    common::issuers::insert(pool, &issuer).await;
    id
}

fn pending_offer(tenant_id: &TenantId, issuer_id: &IssuerId) -> CredentialOffer {
    CredentialOffer::new(
        tenant_id.clone(),
        issuer_id.clone(),
        "https://example.com/vct/test".into(),
        json!({"first_name": "Anna"}),
        PreAuthCode::generate(),
        Utc::now() + Duration::hours(1),
    )
}

/// Postgres `TIMESTAMPTZ` keeps microsecond precision while
/// `Utc::now()` produces nanoseconds, so direct equality on
/// round-tripped timestamps fails. Round to micros up front.
fn now_with_postgres_precision() -> DateTime<Utc> {
    let micros = Utc::now().timestamp_micros();
    DateTime::from_timestamp_micros(micros).unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn happy_path_deactivates_issuer_and_cancels_pending_offers(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let target_issuer = insert_test_issuer(&pool, &tenant_id).await;
    let bystander_issuer = insert_test_issuer(&pool, &tenant_id).await;

    let mut conn = pool.acquire().await.unwrap();

    let target_pending_a = pending_offer(&tenant_id, &target_issuer);
    let target_pending_b = pending_offer(&tenant_id, &target_issuer);

    let mut target_issued = pending_offer(&tenant_id, &target_issuer);
    target_issued.state = CredentialOfferState::Issued;
    target_issued.issued_at = Some(now_with_postgres_precision());
    target_issued.pre_auth_code = None;

    let mut target_cancelled = pending_offer(&tenant_id, &target_issuer);
    target_cancelled.state = CredentialOfferState::Cancelled;
    target_cancelled.cancelled_at = Some(now_with_postgres_precision());
    target_cancelled.pre_auth_code = None;

    // Pending offer on a different issuer in the same tenant — must
    // be untouched after deactivating only the target issuer.
    let bystander_pending = pending_offer(&tenant_id, &bystander_issuer);

    for offer in [
        &target_pending_a,
        &target_pending_b,
        &target_issued,
        &target_cancelled,
        &bystander_pending,
    ] {
        credential_offers::insert(&mut conn, offer).await.unwrap();
    }

    let now = now_with_postgres_precision();
    let outcome = execute_mark_deactivated(&pool, &tenant_id, &target_issuer, now).await;
    match outcome {
        StepOutcome::Done(result) => assert!(result.state_data_patch.is_empty()),
        other => panic!("expected Done, got {other:?}"),
    }

    let target_state = issuers::find_by_id(&mut conn, &target_issuer)
        .await
        .unwrap()
        .unwrap()
        .state;
    assert_eq!(target_state, Some(IssuerState::Deactivated));

    let bystander_state = issuers::find_by_id(&mut conn, &bystander_issuer)
        .await
        .unwrap()
        .unwrap()
        .state;
    assert_eq!(bystander_state, Some(IssuerState::Active));

    let loaded_a =
        credential_offers::find_by_id(&mut conn, &tenant_id, &target_issuer, &target_pending_a.id)
            .await
            .unwrap();
    assert_eq!(loaded_a.state, CredentialOfferState::Cancelled);
    assert_eq!(loaded_a.cancelled_at, Some(now));
    assert!(loaded_a.pre_auth_code.is_none());

    let loaded_b =
        credential_offers::find_by_id(&mut conn, &tenant_id, &target_issuer, &target_pending_b.id)
            .await
            .unwrap();
    assert_eq!(loaded_b.state, CredentialOfferState::Cancelled);

    let loaded_issued =
        credential_offers::find_by_id(&mut conn, &tenant_id, &target_issuer, &target_issued.id)
            .await
            .unwrap();
    assert_eq!(loaded_issued.state, CredentialOfferState::Issued);
    assert_eq!(loaded_issued.issued_at, target_issued.issued_at);

    let loaded_cancelled =
        credential_offers::find_by_id(&mut conn, &tenant_id, &target_issuer, &target_cancelled.id)
            .await
            .unwrap();
    assert_eq!(loaded_cancelled.state, CredentialOfferState::Cancelled);
    // Bulk-cancel does not reset the timestamp on already-cancelled rows.
    assert_eq!(loaded_cancelled.cancelled_at, target_cancelled.cancelled_at);

    let loaded_bystander = credential_offers::find_by_id(
        &mut conn,
        &tenant_id,
        &bystander_issuer,
        &bystander_pending.id,
    )
    .await
    .unwrap();
    assert_eq!(loaded_bystander.state, CredentialOfferState::Pending);
    assert!(loaded_bystander.pre_auth_code.is_some());
}

#[sqlx::test(migrations = "./migrations")]
async fn idempotent_rerun_after_already_deactivated(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer_id = insert_test_issuer(&pool, &tenant_id).await;

    // First run: flip the row.
    let first =
        execute_mark_deactivated(&pool, &tenant_id, &issuer_id, now_with_postgres_precision())
            .await;
    assert!(matches!(first, StepOutcome::Done(_)));

    // Second run on a row already in the desired state: still Done,
    // empty patch (the saga records nothing in state-data for this
    // step). Persistence layer's MarkOutcome::Already drives this.
    let second =
        execute_mark_deactivated(&pool, &tenant_id, &issuer_id, now_with_postgres_precision())
            .await;
    match second {
        StepOutcome::Done(result) => assert!(result.state_data_patch.is_empty()),
        other => panic!("expected Done on idempotent re-run, got {other:?}"),
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn unknown_issuer_is_terminal(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let unknown_issuer = IssuerId::generate();

    let outcome = execute_mark_deactivated(
        &pool,
        &tenant_id,
        &unknown_issuer,
        now_with_postgres_precision(),
    )
    .await;

    match outcome {
        StepOutcome::Terminal { error_code, .. } => {
            assert_eq!(error_code, "mark_deactivated_failed");
        }
        other => panic!("expected Terminal, got {other:?}"),
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn cross_tenant_caller_is_terminal(pool: PgPool) {
    let tenant_owner = TenantId::generate();
    let tenant_other = TenantId::generate();
    insert_test_tenant(&pool, &tenant_owner).await;
    insert_test_tenant(&pool, &tenant_other).await;
    let issuer_id = insert_test_issuer(&pool, &tenant_owner).await;

    let outcome = execute_mark_deactivated(
        &pool,
        &tenant_other,
        &issuer_id,
        now_with_postgres_precision(),
    )
    .await;

    match outcome {
        StepOutcome::Terminal { error_code, .. } => {
            assert_eq!(error_code, "mark_deactivated_failed");
        }
        other => panic!("expected Terminal, got {other:?}"),
    }

    // The owner's view of the issuer is unaffected by the failed call.
    let mut conn = pool.acquire().await.unwrap();
    let state = issuers::find_by_id(&mut conn, &issuer_id)
        .await
        .unwrap()
        .unwrap()
        .state;
    assert_eq!(state, Some(IssuerState::Active));
}
