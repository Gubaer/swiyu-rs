use thiserror::Error;

#[derive(Debug, Error)]
pub enum PersistenceError {
    #[error("not found")]
    NotFound,
    #[error("unique constraint violated: {what}")]
    UniqueViolation { what: String },
    #[error("database error")]
    Db(#[from] sqlx::Error),
}
