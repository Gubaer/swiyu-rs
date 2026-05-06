//! `persist_issuer` step executor.
//!
//! Inserts the `issuers` row that records the just-published DID,
//! its three `KeyPairId`s, and the BA-supplied description and
//! display name. Idempotent on resume: a second invocation observing
//! a row with the task's pre-allocated `issuer_id` already present
//! returns immediately. The unique-violation race window between the
//! existence check and the insert is also treated as success — the
//! row is the row we were going to write.

use chrono::{DateTime, Utc};

use crate::domain::{
    Issuer, IssuerId, IssuerState, SigningEngine, SigningEngineError, StepOutcome, StepResult,
    TenantId,
};
use crate::persistence::{self, PersistenceError};
use sqlx::PgPool;

use super::log_builder::{BuildError, build_log_entry};
use super::{CreateIssuerInput, CreateIssuerStateData};

pub async fn execute_persist_issuer<S: SigningEngine>(
    pool: &PgPool,
    tenant_id: &TenantId,
    issuer_id: &IssuerId,
    input: &CreateIssuerInput,
    state: &CreateIssuerStateData,
    engine: &S,
    now: DateTime<Utc>,
) -> StepOutcome {
    let mut conn = match pool.acquire().await {
        Ok(c) => c,
        Err(e) => return retry_on_db("acquire connection", e.to_string()),
    };

    match persistence::issuers::find_by_id(&mut conn, issuer_id).await {
        Ok(Some(_)) => return StepOutcome::Done(StepResult::default()),
        Ok(None) => {}
        Err(e) => return outcome_for_persistence_error("find_by_id", e),
    }

    let key_ids = match &state.key_ids {
        Some(k) => k,
        None => {
            return StepOutcome::Terminal {
                error_code: "missing_state".into(),
                error_message: "state_data missing key_ids".into(),
            };
        }
    };

    let entry = match build_log_entry(state, engine, now).await {
        Ok(e) => e,
        Err(BuildError::Engine(SigningEngineError::Backend(_))) => {
            return StepOutcome::Retry {
                error_code: "persist_issuer_failed".into(),
                error_message: "signing-engine backend error".into(),
            };
        }
        Err(e) => {
            return StepOutcome::Terminal {
                error_code: e.error_code("persist_issuer_failed").into(),
                error_message: e.to_string(),
            };
        }
    };

    let did = match entry[3]["value"]["id"].as_str() {
        Some(d) => d.to_string(),
        None => {
            return StepOutcome::Terminal {
                error_code: "missing_did".into(),
                error_message: "constructed entry has no document.id".into(),
            };
        }
    };

    let issuer = Issuer {
        id: issuer_id.clone(),
        tenant_id: tenant_id.clone(),
        did,
        state: Some(IssuerState::Active),
        description: Some(input.description.clone()),
        authorized_key_id: Some(key_ids.authorized),
        authentication_key_id: Some(key_ids.authentication),
        assertion_key_id: Some(key_ids.assertion),
        display_name: Some(input.display_name.clone()),
        logo_uri: None,
        locale: None,
        created_at: now,
    };

    match persistence::issuers::insert(&mut conn, &issuer).await {
        Ok(()) => StepOutcome::Done(StepResult::default()),
        // A concurrent execution wrote the row between our find_by_id and
        // our insert. The state we'd have written is the state that's now
        // there (issuer_id is pre-allocated, so any concurrent inserter
        // wrote semantically the same row). Treat as success.
        Err(PersistenceError::UniqueViolation { .. }) => StepOutcome::Done(StepResult::default()),
        Err(e) => outcome_for_persistence_error("insert", e),
    }
}

fn outcome_for_persistence_error(operation: &'static str, e: PersistenceError) -> StepOutcome {
    match e {
        // Treat all DB issues as transient: the dispatch loop retries with
        // backoff until the 24h cap.
        PersistenceError::Db(err) => retry_on_db(operation, err.to_string()),
        // NotFound from find_by_id should not happen (we just queried) but
        // surface it as Terminal for clarity if it does.
        PersistenceError::NotFound => StepOutcome::Terminal {
            error_code: "persist_issuer_failed".into(),
            error_message: format!("{operation}: not found"),
        },
        PersistenceError::DataIntegrity { details } => StepOutcome::Terminal {
            error_code: "persist_issuer_failed".into(),
            error_message: format!("{operation}: data integrity: {details}"),
        },
        PersistenceError::UniqueViolation { what } => StepOutcome::Terminal {
            error_code: "persist_issuer_failed".into(),
            error_message: format!("{operation}: unique violation: {what}"),
        },
    }
}

fn retry_on_db(operation: &str, message: String) -> StepOutcome {
    StepOutcome::Retry {
        error_code: "persist_issuer_failed".into(),
        error_message: format!("{operation}: {message}"),
    }
}
