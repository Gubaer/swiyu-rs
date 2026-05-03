use thiserror::Error;

/// Errors returned by registry clients.
///
/// `is_retryable` separates transient failures (transport, 5xx, 429)
/// from permanent ones; callers driving retry/backoff use it directly
/// rather than re-classifying every variant by hand.
#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("transport error: {0}")]
    Transport(#[source] reqwest::Error),

    #[error("registry returned HTTP {status}: {body}")]
    HttpStatus { status: u16, body: String },

    #[error("could not decode registry response: {0}")]
    Decode(String),
}

impl RegistryError {
    pub fn is_retryable(&self) -> bool {
        match self {
            RegistryError::Transport(_) => true,
            RegistryError::HttpStatus { status, .. } => {
                *status == 429 || (500..600).contains(status)
            }
            RegistryError::Decode(_) => false,
        }
    }
}
