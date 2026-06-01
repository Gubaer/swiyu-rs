use thiserror::Error;

use crate::domain::secret_encryption_engine::SecretEncryptionError;

#[derive(Debug, Error)]
pub enum PersistenceError {
    #[error("not found")]
    NotFound,
    #[error("unique constraint violated: {what}")]
    UniqueViolation { what: String },
    #[error("data integrity violation: {details}")]
    DataIntegrity { details: String },
    #[error("database error")]
    Db(#[from] sqlx::Error),
    #[error("encryption error: {0}")]
    Encryption(#[from] SecretEncryptionError),
}
