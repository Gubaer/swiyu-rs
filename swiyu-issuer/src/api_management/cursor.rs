//! Opaque pagination cursors shared by the management-API list
//! endpoints (`issuers`, `credential_offers`, `issued_credentials`).
//!
//! Wire shape: base58(`<rfc3339-timestamp>|<bare-id>`). The format is
//! deliberately not stable across releases — clients must round-trip
//! whatever the server emits and never construct or parse cursors
//! themselves. The decoder also rejects values whose timestamp does
//! not parse or whose bare-id portion fails the caller-supplied
//! validator (typically the id newtype's `from_bare`).

use chrono::{DateTime, Utc};

use super::error::ApiError;

#[derive(Debug)]
pub(super) struct DecodedCursor {
    pub timestamp: DateTime<Utc>,
    pub bare_id: String,
}

pub(super) fn encode(timestamp: DateTime<Utc>, bare_id: &str) -> String {
    let raw = format!("{}|{}", timestamp.to_rfc3339(), bare_id);
    bs58::encode(raw.as_bytes()).into_string()
}

/// Decodes a previously-emitted cursor and validates that its
/// bare-id portion still parses as the expected id newtype.
///
/// `validate_bare` is run against the bare-id portion of the
/// cursor; the typical caller passes a closure that wraps
/// `<IdType>::from_bare(s).map(|_| ())` to enforce the cursor
/// references the id family the endpoint paginates over.
pub(super) fn decode<F, E>(raw: &str, validate_bare: F) -> Result<DecodedCursor, ApiError>
where
    F: FnOnce(&str) -> Result<(), E>,
{
    let bytes = bs58::decode(raw).into_vec().map_err(|_| invalid_cursor())?;
    let text = String::from_utf8(bytes).map_err(|_| invalid_cursor())?;
    let (ts, id) = text.split_once('|').ok_or_else(invalid_cursor)?;
    let timestamp = DateTime::parse_from_rfc3339(ts)
        .map_err(|_| invalid_cursor())?
        .with_timezone(&Utc);
    validate_bare(id).map_err(|_| invalid_cursor())?;
    Ok(DecodedCursor {
        timestamp,
        bare_id: id.to_string(),
    })
}

fn invalid_cursor() -> ApiError {
    ApiError::InvalidInput {
        details: "cursor query parameter: malformed or not issued by this server".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::IssuerId;

    fn validate_issuer(s: &str) -> Result<(), crate::domain::DomainError> {
        IssuerId::from_bare(s).map(|_| ())
    }

    #[test]
    fn round_trips() {
        let ts = DateTime::parse_from_rfc3339("2026-05-01T12:34:56.789Z")
            .unwrap()
            .with_timezone(&Utc);
        let bare = "9hXq2vRtL8pK7f";
        let encoded = encode(ts, bare);
        let decoded = decode(&encoded, validate_issuer).unwrap();
        assert_eq!(decoded.timestamp, ts);
        assert_eq!(decoded.bare_id, bare);
    }

    #[test]
    fn rejects_garbage_base58() {
        let err = decode("0000", validate_issuer).unwrap_err();
        assert!(matches!(err, ApiError::InvalidInput { .. }));
    }

    #[test]
    fn rejects_non_utf8_payload() {
        let encoded = bs58::encode([0xff, 0xfe, 0xfd]).into_string();
        let err = decode(&encoded, validate_issuer).unwrap_err();
        assert!(matches!(err, ApiError::InvalidInput { .. }));
    }

    #[test]
    fn rejects_missing_separator() {
        let encoded = bs58::encode(b"no-separator-here").into_string();
        let err = decode(&encoded, validate_issuer).unwrap_err();
        assert!(matches!(err, ApiError::InvalidInput { .. }));
    }

    #[test]
    fn rejects_bad_timestamp() {
        let encoded = bs58::encode(b"not-a-timestamp|9hXq2vRtL8pK7f").into_string();
        let err = decode(&encoded, validate_issuer).unwrap_err();
        assert!(matches!(err, ApiError::InvalidInput { .. }));
    }

    #[test]
    fn rejects_bad_id() {
        // 'O' is excluded from the base58 alphabet.
        let encoded = bs58::encode(b"2026-05-01T12:34:56+00:00|notValOd").into_string();
        let err = decode(&encoded, validate_issuer).unwrap_err();
        assert!(matches!(err, ApiError::InvalidInput { .. }));
    }
}
