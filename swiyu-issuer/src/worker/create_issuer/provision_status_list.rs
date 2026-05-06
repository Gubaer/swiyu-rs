//! `provision_status_list` step executor.
//!
//! Inserts the issuer's first `status_lists` row using the registry
//! coordinates recorded by `create_status_list_entry`, and re-points
//! `issuers.current_status_list_id` at it. Idempotent on resume: a
//! second invocation observing `issuers.current_status_list_id`
//! already set returns immediately.

use sqlx::PgPool;

use crate::domain::{IssuerId, StepOutcome, StepResult};
use crate::persistence::{self, PersistenceError};
use crate::worker::create_issuer::CreateIssuerStateData;

pub async fn execute_provision_status_list(
    pool: &PgPool,
    issuer_id: &IssuerId,
    state: &CreateIssuerStateData,
) -> StepOutcome {
    let mut conn = match pool.acquire().await {
        Ok(c) => c,
        Err(e) => return retry_on_db("acquire connection", e.to_string()),
    };

    match persistence::status_lists::current_for_issuer(&mut conn, issuer_id).await {
        Ok(Some(_)) => return StepOutcome::Done(StepResult::default()),
        Ok(None) => {}
        Err(e) => return outcome_for_persistence_error("current_for_issuer", e),
    }

    let entry_id = match state.status_list_registry_entry_id.as_deref() {
        Some(s) => s,
        None => {
            return StepOutcome::Terminal {
                error_code: "missing_state".into(),
                error_message: "state_data missing status_list_registry_entry_id".into(),
            };
        }
    };
    let registry_url = match state.status_list_registry_url.as_deref() {
        Some(s) => s,
        None => {
            return StepOutcome::Terminal {
                error_code: "missing_state".into(),
                error_message: "state_data missing status_list_registry_url".into(),
            };
        }
    };

    match persistence::status_lists::provision_for_issuer(
        &mut conn,
        issuer_id,
        Some(entry_id),
        Some(registry_url),
    )
    .await
    {
        Ok(_) => StepOutcome::Done(StepResult::default()),
        Err(e) => outcome_for_persistence_error("provision_for_issuer", e),
    }
}

fn outcome_for_persistence_error(operation: &'static str, e: PersistenceError) -> StepOutcome {
    match e {
        PersistenceError::Db(err) => retry_on_db(operation, err.to_string()),
        PersistenceError::NotFound => StepOutcome::Terminal {
            error_code: "provision_status_list_failed".into(),
            error_message: format!("{operation}: not found"),
        },
        PersistenceError::DataIntegrity { details } => StepOutcome::Terminal {
            error_code: "provision_status_list_failed".into(),
            error_message: format!("{operation}: data integrity: {details}"),
        },
        PersistenceError::UniqueViolation { what } => StepOutcome::Terminal {
            error_code: "provision_status_list_failed".into(),
            error_message: format!("{operation}: unique violation: {what}"),
        },
    }
}

fn retry_on_db(operation: &str, message: String) -> StepOutcome {
    StepOutcome::Retry {
        error_code: "provision_status_list_failed".into(),
        error_message: format!("{operation}: {message}"),
    }
}
