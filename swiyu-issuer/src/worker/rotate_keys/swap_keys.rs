//! `swap_keys` step executor.
//!
//! The saga's terminal local step. Atomically swaps the issuer
//! row's three key-id columns to `state.new_key_triple`. The
//! state guard `state = 'active'` rejects swaps against a
//! `Deactivated` issuer or the legacy state-NULL row.
//!
//! Idempotency comes from the persistence helper: re-running the
//! step after a crash that already swapped the row sees
//! `SwapOutcome::Already` and treats it as success. The variant
//! is observable via `tracing` for ops debugging.
//!
//! Error classification mirrors `mark_deactivated`:
//! `PersistenceError::Db` (transient connection / acquire failures)
//! routes to `Retry`; structural errors (`DataIntegrity`,
//! `UniqueViolation`, `NotFound`) route to `Terminal`. `NotFound`
//! from `swap_key_triple` means either the issuer was deleted
//! between earlier saga steps and this one (vanishingly rare) or
//! its state moved out of `Active` (e.g. someone deactivated it
//! mid-rotation) — neither is safe to retry.

use sqlx::PgPool;
use tracing::debug;

use crate::domain::{IssuerId, StepOutcome, StepResult, TenantId};
use crate::persistence::{self, PersistenceError};

use super::state::RotateKeysStateData;

pub async fn execute_swap_keys(
    pool: &PgPool,
    tenant_id: &TenantId,
    issuer_id: &IssuerId,
    state: &RotateKeysStateData,
) -> StepOutcome {
    let new_triple = match state.new_key_triple.as_ref() {
        Some(t) => t,
        None => {
            return StepOutcome::Terminal {
                error_code: "missing_state".into(),
                error_message: "state_data missing new_key_triple".into(),
            };
        }
    };

    let mut conn = match pool.acquire().await {
        Ok(c) => c,
        Err(e) => return retry_on_db("acquire connection", e.to_string()),
    };

    let outcome = match persistence::issuers::swap_key_triple(
        &mut conn,
        tenant_id,
        issuer_id,
        &new_triple.authorized,
        &new_triple.authentication,
        &new_triple.assertion,
    )
    .await
    {
        Ok(o) => o,
        Err(e) => return outcome_for_persistence_error("swap_key_triple", e),
    };

    debug!(outcome = ?outcome, "issuer key triple swapped locally");

    StepOutcome::Done(StepResult::default())
}

fn outcome_for_persistence_error(operation: &'static str, e: PersistenceError) -> StepOutcome {
    match e {
        PersistenceError::Db(err) => retry_on_db(operation, err.to_string()),
        PersistenceError::NotFound => StepOutcome::Terminal {
            error_code: "swap_keys_failed".into(),
            error_message: format!("{operation}: not found"),
        },
        PersistenceError::DataIntegrity { details } => StepOutcome::Terminal {
            error_code: "swap_keys_failed".into(),
            error_message: format!("{operation}: data integrity: {details}"),
        },
        PersistenceError::UniqueViolation { what } => StepOutcome::Terminal {
            error_code: "swap_keys_failed".into(),
            error_message: format!("{operation}: unique violation: {what}"),
        },
        PersistenceError::Encryption(err) => StepOutcome::Terminal {
            error_code: "swap_keys_failed".into(),
            error_message: format!("{operation}: secret encryption: {err}"),
        },
    }
}

fn retry_on_db(operation: &str, message: String) -> StepOutcome {
    StepOutcome::Retry {
        error_code: "swap_keys_failed".into(),
        error_message: format!("{operation}: {message}"),
    }
}
