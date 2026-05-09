use crate::domain::{StepOutcome, TokenAwareError, TokenProviderError};

/// Translates a [`TokenAwareError`] into a [`StepOutcome`] for the
/// per-step worker functions.
///
/// Every protected registry call in the worker funnels through one of
/// the `*_with_refresh` helpers in [`crate::worker::registry_facades`],
/// so every caller faces the same five-arm `Err` mapping. Centralising
/// it here keeps the per-step bodies focused on their happy paths and
/// ensures the error-code vocabulary stays consistent across sagas.
///
/// The two `registry_*` codes are caller-supplied because the
/// identifier registry uses `registry_unavailable` / `registry_rejected`
/// while the status registry uses `status_registry_unavailable` /
/// `status_registry_rejected`. The token-side codes are fixed.
pub fn token_aware_error_to_outcome(
    error: TokenAwareError,
    registry_retry_code: &str,
    registry_terminal_code: &str,
) -> StepOutcome {
    match error {
        TokenAwareError::Registry(e) if e.is_retryable() => StepOutcome::Retry {
            error_code: registry_retry_code.into(),
            error_message: e.to_string(),
        },
        TokenAwareError::Registry(e) => StepOutcome::Terminal {
            error_code: registry_terminal_code.into(),
            error_message: e.to_string(),
        },
        TokenAwareError::Token(TokenProviderError::MissingCredentials(msg)) => {
            StepOutcome::Terminal {
                error_code: "tenant_missing_oauth_credentials".into(),
                error_message: msg,
            }
        }
        TokenAwareError::Token(e) if e.is_retryable() => StepOutcome::Retry {
            error_code: "token_unavailable".into(),
            error_message: e.to_string(),
        },
        TokenAwareError::Token(e) => StepOutcome::Terminal {
            error_code: "token_rejected".into(),
            error_message: e.to_string(),
        },
    }
}
