//! Step 7 (final) of the `CreateIssuer` saga: insert the issuer's
//! first local `status_lists` row and link it from the issuer.

use sqlx::PgPool;

use crate::domain::{IssuerId, StepOutcome, StepResult};
use crate::persistence::{self, PersistenceError};
use crate::worker::create_issuer::CreateIssuerStateData;

/// Uses the registry coordinates recorded by
/// `execute_create_status_list_entry` to populate the row, then
/// re-points `issuers.current_status_list_id` at it so credential
/// issuance can find the entry. On saga resume this step
/// short-circuits when `issuers.current_status_list_id` is already
/// set, returning [`StepOutcome::Done`].
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
