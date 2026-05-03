// `AccessToken`'s inner storage and `as_str` are reached only via
// the per-operation modules in `crate::identifier::*`.
#![allow(dead_code)]

use zeroize::Zeroizing;

/// Bearer token used to authenticate with a SWIYU registry.
///
/// The token is wrapped in `zeroize::Zeroizing` so its memory is
/// overwritten on drop, and `Debug` is overridden to mask the value
/// — `AccessToken` instances can appear in logs and span fields
/// without leaking the secret.
pub struct AccessToken(Zeroizing<String>);

impl AccessToken {
    pub fn new(token: String) -> Self {
        Self(Zeroizing::new(token))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccessToken(***)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_does_not_leak_token() {
        let token = AccessToken::new("super-secret-value".to_string());
        let debug = format!("{token:?}");
        assert!(!debug.contains("super-secret-value"));
        assert_eq!(debug, "AccessToken(***)");
    }

    #[test]
    fn as_str_round_trips() {
        let token = AccessToken::new("abc123".to_string());
        assert_eq!(token.as_str(), "abc123");
    }
}
