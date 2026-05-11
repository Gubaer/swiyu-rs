use std::fmt;

const PRE_AUTH_CODE_BYTES: usize = 16;

/// An OID4VCI pre-authorised code — the short-lived secret returned
/// to the business application at credential-offer creation, then
/// delivered to the wallet via the OID4VCI by-reference flow.
///
/// The bare value is stored on the `credential_offers` row for the
/// offer's pending window because the by-reference offer-uri fetch
/// must return it. It is set to `NULL` at the first terminal-state
/// transition. `Display` and `serde::Serialize` are deliberately absent.
#[derive(Clone)]
pub struct PreAuthCode(String);

impl PreAuthCode {
    pub fn generate() -> Self {
        let mut bytes = [0u8; PRE_AUTH_CODE_BYTES];
        getrandom::fill(&mut bytes).expect("OS RNG must be available");
        Self(bs58::encode(&bytes).into_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Reconstructs a `PreAuthCode` from a bare value the persistence
    /// layer just read out of `credential_offers.pre_auth_code`. Only
    /// callers inside `persistence` should invoke this.
    pub fn from_stored(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

impl From<PreAuthCode> for String {
    fn from(code: PreAuthCode) -> Self {
        code.0
    }
}

impl sqlx::Type<sqlx::Postgres> for PreAuthCode {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <String as sqlx::Type<sqlx::Postgres>>::type_info()
    }

    fn compatible(ty: &sqlx::postgres::PgTypeInfo) -> bool {
        <String as sqlx::Type<sqlx::Postgres>>::compatible(ty)
    }
}

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for PreAuthCode {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let s = <String as sqlx::Decode<'r, sqlx::Postgres>>::decode(value)?;
        Ok(Self::from_stored(s))
    }
}

impl<'q> sqlx::Encode<'q, sqlx::Postgres> for PreAuthCode {
    fn encode_by_ref(
        &self,
        buf: &mut sqlx::postgres::PgArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        <&str as sqlx::Encode<'q, sqlx::Postgres>>::encode_by_ref(&self.0.as_str(), buf)
    }
}

impl PartialEq for PreAuthCode {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for PreAuthCode {}

// Custom Debug avoids leaking the secret if a PreAuthCode is logged accidentally.
impl fmt::Debug for PreAuthCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PreAuthCode").field(&"<redacted>").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_codes_are_distinct() {
        let a = PreAuthCode::generate();
        let b = PreAuthCode::generate();
        assert_ne!(a.as_str(), b.as_str());
    }

    #[test]
    fn from_stored_round_trips_with_as_str() {
        let stored = PreAuthCode::from_stored("DevDevDev123");
        assert_eq!(stored.as_str(), "DevDevDev123");
    }

    #[test]
    fn equality_compares_inner_string() {
        let a = PreAuthCode::from_stored("abc");
        let b = PreAuthCode::from_stored("abc");
        let c = PreAuthCode::from_stored("def");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn debug_does_not_reveal_secret() {
        let code = PreAuthCode::generate();
        let rendered = format!("{code:?}");
        assert!(!rendered.contains(code.as_str()));
        assert!(rendered.contains("redacted"));
    }
}
