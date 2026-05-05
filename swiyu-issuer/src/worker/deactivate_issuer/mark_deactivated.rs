//! `mark_deactivated` step executor.
//!
//! The saga's terminal local step. Inside one Postgres transaction:
//!   1. Flip the issuer row's `state` from `active` to `deactivated`
//!      (or observe that it is already `deactivated`).
//!   2. Bulk-cancel every still-pending credential offer for that
//!      issuer.
//!
//! Idempotency comes from the persistence helpers: re-running the
//! step after a crash that already flipped the row sees
//! `MarkOutcome::Already` and the bulk-cancel touches zero rows.
//! Both shapes are reported as `StepOutcome::Done`. The variant is
//! observable via `tracing` for ops debugging.
//!
//! Error classification mirrors `create_issuer::persist_issuer`:
//! `PersistenceError::Db` (transient connection / acquire failures)
//! routes to `Retry`; structural errors (`DataIntegrity`,
//! `UniqueViolation`, `NotFound`) route to `Terminal`. `NotFound`
//! from `mark_deactivated` means the issuer row was deleted between
//! earlier saga steps and this one — vanishingly rare and not safe
//! to retry.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tracing::debug;

use crate::domain::{IssuerId, StepOutcome, StepResult, TenantId};
use crate::persistence::{self, PersistenceError};

pub async fn execute_mark_deactivated(
    pool: &PgPool,
    tenant_id: &TenantId,
    issuer_id: &IssuerId,
    now: DateTime<Utc>,
) -> StepOutcome {
    let mut tx = match pool.begin().await {
        Ok(t) => t,
        Err(e) => return retry_on_db("begin", e.to_string()),
    };

    let mark_outcome =
        match persistence::issuers::mark_deactivated(&mut tx, tenant_id, issuer_id).await {
            Ok(o) => o,
            Err(e) => return outcome_for_persistence_error("mark_deactivated", e),
        };

    let cancelled = match persistence::credential_offers::cancel_all_pending_for_issuer(
        &mut tx, tenant_id, issuer_id, now,
    )
    .await
    {
        Ok(n) => n,
        Err(e) => return outcome_for_persistence_error("cancel_all_pending_for_issuer", e),
    };

    if let Err(e) = tx.commit().await {
        return retry_on_db("commit", e.to_string());
    }

    debug!(
        outcome = ?mark_outcome,
        cancelled_offers = cancelled,
        "issuer deactivated locally",
    );

    StepOutcome::Done(StepResult::default())
}

fn outcome_for_persistence_error(operation: &'static str, e: PersistenceError) -> StepOutcome {
    match e {
        PersistenceError::Db(err) => retry_on_db(operation, err.to_string()),
        PersistenceError::NotFound => StepOutcome::Terminal {
            error_code: "mark_deactivated_failed".into(),
            error_message: format!("{operation}: not found"),
        },
        PersistenceError::DataIntegrity { details } => StepOutcome::Terminal {
            error_code: "mark_deactivated_failed".into(),
            error_message: format!("{operation}: data integrity: {details}"),
        },
        PersistenceError::UniqueViolation { what } => StepOutcome::Terminal {
            error_code: "mark_deactivated_failed".into(),
            error_message: format!("{operation}: unique violation: {what}"),
        },
    }
}

fn retry_on_db(operation: &str, message: String) -> StepOutcome {
    StepOutcome::Retry {
        error_code: "mark_deactivated_failed".into(),
        error_message: format!("{operation}: {message}"),
    }
}
