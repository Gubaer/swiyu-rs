use crate::domain::DomainError;

use super::PersistenceError;

pub(super) fn integrity_from(err: DomainError) -> PersistenceError {
    PersistenceError::DataIntegrity {
        details: err.to_string(),
    }
}

pub(super) fn map_database_error(err: sqlx::Error) -> PersistenceError {
    if let Some(db_err) = err.as_database_error() {
        // Postgres SQLSTATE 23505: unique_violation.
        if db_err.code().as_deref() == Some("23505") {
            let constraint = db_err.constraint().unwrap_or("unknown").to_string();
            return PersistenceError::UniqueViolation { what: constraint };
        }
    }
    PersistenceError::Db(err)
}
