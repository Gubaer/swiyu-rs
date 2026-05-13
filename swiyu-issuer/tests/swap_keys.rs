//! Integration tests for `worker::rotate_keys::swap_keys`.
//!
//! Runs against a freshly created Postgres database via `sqlx::test`;
//! migrations apply automatically. Requires `DATABASE_URL` to point
//! to a Postgres instance whose user has `CREATEDB` privilege.

use chrono::Utc;
use sqlx::PgPool;

use swiyu_issuer::domain::{Issuer, IssuerId, IssuerState, KeyPairId, StepOutcome, TenantId};
use swiyu_issuer::persistence::issuers;
use swiyu_issuer::worker::create_issuer::KeyTriple;
use swiyu_issuer::worker::deactivate_issuer::mark_deactivated::execute_mark_deactivated;
use swiyu_issuer::worker::rotate_keys::state::RotateKeysStateData;
use swiyu_issuer::worker::rotate_keys::swap_keys::execute_swap_keys;

#[path = "common/mod.rs"]
mod common;
use common::tenants::insert_test_tenant;

async fn insert_active_issuer(pool: &PgPool, tenant_id: &TenantId) -> Issuer {
    let issuer = Issuer {
        did: "did:tdw:scid:example.com:fixture".into(),
        ..common::issuers::active_with_keys(tenant_id)
    };
    common::issuers::insert(pool, &issuer).await;
    issuer
}

fn state_with_triple(triple: KeyTriple) -> RotateKeysStateData {
    RotateKeysStateData {
        new_key_triple: Some(triple),
        didlog_published: true,
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn happy_path_swaps_all_three_keys(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer = insert_active_issuer(&pool, &tenant_id).await;

    let new_triple = KeyTriple {
        authorized: KeyPairId::generate(),
        authentication: KeyPairId::generate(),
        assertion: KeyPairId::generate(),
    };
    let state = state_with_triple(new_triple);

    let outcome = execute_swap_keys(&pool, &tenant_id, &issuer.id, &state).await;
    match outcome {
        StepOutcome::Done(result) => assert!(result.state_data_patch.is_empty()),
        other => panic!("expected Done, got {other:?}"),
    }

    let mut conn = pool.acquire().await.unwrap();
    let loaded = issuers::find_by_id(&mut conn, &issuer.id)
        .await
        .unwrap()
        .unwrap();
    let triple = state.new_key_triple.as_ref().unwrap();
    assert_eq!(loaded.authorized_key_id, Some(triple.authorized));
    assert_eq!(loaded.authentication_key_id, Some(triple.authentication));
    assert_eq!(loaded.assertion_key_id, Some(triple.assertion));
    assert_eq!(loaded.state, Some(IssuerState::Active));
}

#[sqlx::test(migrations = "./migrations")]
async fn happy_path_swaps_only_one_role(pool: PgPool) {
    // Single-role rotation: the caller assembles a triple where
    // two ids are unchanged. The persistence guard's "any column
    // distinct" check still triggers for the one column that does
    // change, and the row ends up exactly as requested.
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer = insert_active_issuer(&pool, &tenant_id).await;

    let new_authentication = KeyPairId::generate();
    let new_triple = KeyTriple {
        authorized: issuer.authorized_key_id.unwrap(),
        authentication: new_authentication,
        assertion: issuer.assertion_key_id.unwrap(),
    };
    let state = state_with_triple(new_triple);

    let outcome = execute_swap_keys(&pool, &tenant_id, &issuer.id, &state).await;
    assert!(matches!(outcome, StepOutcome::Done(_)));

    let mut conn = pool.acquire().await.unwrap();
    let loaded = issuers::find_by_id(&mut conn, &issuer.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.authorized_key_id, issuer.authorized_key_id);
    assert_eq!(loaded.authentication_key_id, Some(new_authentication));
    assert_eq!(loaded.assertion_key_id, issuer.assertion_key_id);
}

#[sqlx::test(migrations = "./migrations")]
async fn idempotent_rerun_after_already_swapped(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer = insert_active_issuer(&pool, &tenant_id).await;

    let new_triple = KeyTriple {
        authorized: KeyPairId::generate(),
        authentication: KeyPairId::generate(),
        assertion: KeyPairId::generate(),
    };
    let state = state_with_triple(new_triple);

    // First run: swap.
    let first = execute_swap_keys(&pool, &tenant_id, &issuer.id, &state).await;
    assert!(matches!(first, StepOutcome::Done(_)));

    // Second run on a row already carrying the triple: still Done,
    // empty patch. The persistence helper's `Already` outcome.
    let second = execute_swap_keys(&pool, &tenant_id, &issuer.id, &state).await;
    match second {
        StepOutcome::Done(result) => assert!(result.state_data_patch.is_empty()),
        other => panic!("expected Done on idempotent re-run, got {other:?}"),
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn missing_new_key_triple_is_terminal(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer = insert_active_issuer(&pool, &tenant_id).await;

    let state = RotateKeysStateData::default();
    let outcome = execute_swap_keys(&pool, &tenant_id, &issuer.id, &state).await;

    match outcome {
        StepOutcome::Terminal { error_code, .. } => {
            assert_eq!(error_code, "missing_state");
        }
        other => panic!("expected Terminal, got {other:?}"),
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn unknown_issuer_is_terminal(pool: PgPool) {
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let unknown = IssuerId::generate();

    let new_triple = KeyTriple {
        authorized: KeyPairId::generate(),
        authentication: KeyPairId::generate(),
        assertion: KeyPairId::generate(),
    };
    let state = state_with_triple(new_triple);

    let outcome = execute_swap_keys(&pool, &tenant_id, &unknown, &state).await;
    match outcome {
        StepOutcome::Terminal { error_code, .. } => {
            assert_eq!(error_code, "swap_keys_failed");
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
    let issuer = insert_active_issuer(&pool, &tenant_owner).await;

    let new_triple = KeyTriple {
        authorized: KeyPairId::generate(),
        authentication: KeyPairId::generate(),
        assertion: KeyPairId::generate(),
    };
    let state = state_with_triple(new_triple);

    let outcome = execute_swap_keys(&pool, &tenant_other, &issuer.id, &state).await;
    match outcome {
        StepOutcome::Terminal { error_code, .. } => {
            assert_eq!(error_code, "swap_keys_failed");
        }
        other => panic!("expected Terminal, got {other:?}"),
    }

    // Owner's view is unaffected.
    let mut conn = pool.acquire().await.unwrap();
    let loaded = issuers::find_by_id(&mut conn, &issuer.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.authorized_key_id, issuer.authorized_key_id);
}

#[sqlx::test(migrations = "./migrations")]
async fn deactivated_issuer_is_terminal(pool: PgPool) {
    // Someone deactivated the issuer mid-rotation. The state guard
    // in swap_key_triple rejects the swap.
    let tenant_id = TenantId::generate();
    insert_test_tenant(&pool, &tenant_id).await;
    let issuer = insert_active_issuer(&pool, &tenant_id).await;
    execute_mark_deactivated(&pool, &tenant_id, &issuer.id, Utc::now()).await;

    let new_triple = KeyTriple {
        authorized: KeyPairId::generate(),
        authentication: KeyPairId::generate(),
        assertion: KeyPairId::generate(),
    };
    let state = state_with_triple(new_triple);

    let outcome = execute_swap_keys(&pool, &tenant_id, &issuer.id, &state).await;
    match outcome {
        StepOutcome::Terminal { error_code, .. } => {
            assert_eq!(error_code, "swap_keys_failed");
        }
        other => panic!("expected Terminal, got {other:?}"),
    }
}
