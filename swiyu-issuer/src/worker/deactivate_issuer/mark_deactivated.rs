//! Flips the issuer row from `Active` to `Deactivated` and
//! bulk-cancels its still-pending credential offers for a
//! `DeactivateIssuer` task.
//!
//! The saga's terminal local step, dispatched after
//! [`super::publish_didlog`] commits. Idempotent on resume because
//! the in-memory state machine in
//! [`Issuer::try_deactivate`](crate::domain::Issuer::try_deactivate)
//! reports
//! [`MarkOutcome::Already`](crate::domain::MarkOutcome::Already) when
//! re-run against a row that is already `Deactivated`, and
//! [`persistence::credential_offers::cancel_all_pending_for_issuer`]
//! then matches zero rows.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tracing::debug;

use crate::domain::{DomainError, IssuerId, IssuerState, StepOutcome, StepResult, TenantId};
use crate::persistence::{self, PersistenceError};

/// Executes the step inside one Postgres transaction:
///   1. Load the issuer row under a `SELECT … FOR UPDATE` row lock.
///   2. Run [`Issuer::try_deactivate`](crate::domain::Issuer::try_deactivate)
///      (the domain-level state transition — also the sole source of
///      idempotency for the `Active → Deactivated` flip).
///   3. Persist the new state via [`persistence::issuers::set_state`].
///   4. Bulk-cancel every still-pending credential offer for that
///      issuer.
///
/// Both
/// [`MarkOutcome::NowDeactivated`](crate::domain::MarkOutcome::NowDeactivated)
/// and [`MarkOutcome::Already`](crate::domain::MarkOutcome::Already)
/// produce [`StepOutcome::Done`]; the variant is observable via
/// `tracing` for ops debugging.
///
/// Error classification mirrors `create_issuer::persist_issuer`:
/// [`PersistenceError::Db`] (transient connection / acquire failures)
/// routes to [`StepOutcome::Retry`]; structural errors
/// ([`PersistenceError::DataIntegrity`],
/// [`PersistenceError::UniqueViolation`],
/// [`PersistenceError::NotFound`]) route to [`StepOutcome::Terminal`].
/// Two extra terminal cases come from the domain layer: a missing
/// issuer row (deleted between earlier saga steps and this one —
/// vanishingly rare) and a [`DomainError::StateTransitionNotAllowed`]
/// from the legacy `state IS NULL` fixture row.
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

    let mut issuer =
        match persistence::issuers::find_by_id_for_update_for_tenant(&mut tx, tenant_id, issuer_id)
            .await
        {
            Ok(Some(issuer)) => issuer,
            Ok(None) => {
                return StepOutcome::Terminal {
                    error_code: "mark_deactivated_failed".into(),
                    error_message: "find_by_id_for_update_for_tenant: not found".into(),
                };
            }
            Err(e) => return outcome_for_persistence_error("find_by_id_for_update_for_tenant", e),
        };

    let mark_outcome = match issuer.try_deactivate() {
        Ok(o) => o,
        Err(DomainError::StateTransitionNotAllowed) => {
            return StepOutcome::Terminal {
                error_code: "mark_deactivated_failed".into(),
                error_message:
                    "try_deactivate: state transition not allowed (legacy state=NULL row?)".into(),
            };
        }
        Err(e) => {
            return StepOutcome::Terminal {
                error_code: "mark_deactivated_failed".into(),
                error_message: format!("try_deactivate: {e}"),
            };
        }
    };

    // Always issue the UPDATE — on `Already` it's a no-op write
    // against the row we already hold a `FOR UPDATE` lock on, so
    // the cost is negligible and the code stays branchless.
    if let Err(e) =
        persistence::issuers::set_state(&mut tx, tenant_id, issuer_id, IssuerState::Deactivated)
            .await
    {
        return outcome_for_persistence_error("set_state", e);
    }

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
