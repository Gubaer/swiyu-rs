use thiserror::Error;

#[derive(Debug, Error)]
pub enum DomainError {
    #[error("invalid input: {details}")]
    InvalidInput { details: String },
    #[error("state transition not allowed")]
    StateTransitionNotAllowed,
}
