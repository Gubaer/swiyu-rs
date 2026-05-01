//! Identifier newtypes for the issuer's domain aggregates.
//!
//! Three distinct types — [`TenantId`], [`IssuerId`], and
//! [`CredentialOfferId`] — share the same underlying scheme but
//! stay separate at the type level so a [`TenantId`] cannot
//! accidentally be passed where an [`IssuerId`] is expected.
//!
//! # Generation
//!
//! 10 bytes from the operating system's CSPRNG, base58-encoded.
//! The result is a ~14-character string. 80 bits of entropy give a
//! per-insert collision probability of about 10⁻⁹ at 100 million
//! rows ever stored, so retry-on-conflict is a defensive measure
//! that should never fire in practice.
//!
//! # Encoding choice: base58
//!
//! The wallet-facing credential-offer URL is rendered as a QR code;
//! base58 keeps that URL short while staying URL-safe without
//! percent-encoding. The Bitcoin base58 alphabet also excludes the
//! visually similar characters `0`, `O`, `I`, and `l`, which
//! reduces transcription errors when an identifier is read off a
//! screen by a human. UUIDs were rejected for being unnecessarily
//! long; hash-of-UUID for arriving at the same place by a longer
//! route. See `specs/impl_persistence.md`.
//!
//! # Prefix discipline
//!
//! Each ID type carries a textual prefix (`tenant_`, `issuer_`,
//! `offer_`) when serialised but stores only the bare form
//! internally:
//!
//! - `bare()` returns the unprefixed string. Used for DB storage
//!   and the wallet-facing offer URL, where every character
//!   matters for QR density.
//! - `Display` and `Serialize` produce the prefixed form. Used in
//!   management-API JSON bodies and log lines so the type of an
//!   identifier is self-evident in HTTP traffic and traces.
//! - `FromStr` and `Deserialize` accept only the prefixed form,
//!   validating both the prefix and the base58 alphabet.
//!
//! Validation lives in the constructor; the database does not
//! enforce a `CHECK` constraint on the column, which keeps the
//! schema easier to evolve.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::DomainError;

const ID_BYTES: usize = 10;
const MAX_BARE_LEN: usize = 32;

fn generate_bare() -> String {
    let mut bytes = [0u8; ID_BYTES];
    getrandom::fill(&mut bytes).expect("OS RNG must be available");
    bs58::encode(&bytes).into_string()
}

fn validate_bare(s: &str) -> Result<(), DomainError> {
    if s.is_empty() || s.len() > MAX_BARE_LEN {
        return Err(DomainError::InvalidInput {
            details: format!("identifier length out of range: {}", s.len()),
        });
    }
    if s.chars().any(|c| !is_base58_char(c)) {
        return Err(DomainError::InvalidInput {
            details: format!("identifier contains non-base58 character: {s}"),
        });
    }
    Ok(())
}

// Bitcoin base58 alphabet excludes 0 (zero), O (capital o), I (capital i), l (lowercase L).
fn is_base58_char(c: char) -> bool {
    matches!(
        c,
        '1'..='9' | 'A'..='H' | 'J'..='N' | 'P'..='Z' | 'a'..='k' | 'm'..='z'
    )
}

macro_rules! define_id {
    ($name:ident, $prefix:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn generate() -> Self {
                Self(generate_bare())
            }

            pub fn from_bare(s: impl Into<String>) -> Result<Self, DomainError> {
                let s = s.into();
                validate_bare(&s)?;
                Ok(Self(s))
            }

            pub fn bare(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}_{}", $prefix, self.0)
            }
        }

        impl FromStr for $name {
            type Err = DomainError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let bare = s.strip_prefix(concat!($prefix, "_")).ok_or_else(|| {
                    DomainError::InvalidInput {
                        details: format!(
                            "expected identifier with prefix '{}_', got: {s}",
                            $prefix
                        ),
                    }
                })?;
                Self::from_bare(bare)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let s = String::deserialize(deserializer)?;
                Self::from_str(&s).map_err(serde::de::Error::custom)
            }
        }
    };
}

define_id!(TenantId, "tenant");
define_id!(IssuerId, "issuer");
define_id!(CredentialOfferId, "offer");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_id_is_valid_base58() {
        let id = TenantId::generate();
        assert!(validate_bare(id.bare()).is_ok());
    }

    #[test]
    fn display_uses_prefixed_form() {
        let id = TenantId::from_bare("9hXq2vRtL8pK7f").unwrap();
        assert_eq!(id.to_string(), "tenant_9hXq2vRtL8pK7f");
    }

    #[test]
    fn from_str_round_trips_with_display() {
        let id = IssuerId::generate();
        let parsed: IssuerId = id.to_string().parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn from_str_rejects_missing_prefix() {
        assert!("9hXq2vRtL8pK7f".parse::<TenantId>().is_err());
    }

    #[test]
    fn from_str_rejects_wrong_prefix() {
        assert!("issuer_9hXq2vRtL8pK7f".parse::<TenantId>().is_err());
    }

    #[test]
    fn from_bare_rejects_non_base58() {
        // 'O' is excluded from the Bitcoin base58 alphabet.
        assert!(TenantId::from_bare("9hXqOvRtL8pK7f").is_err());
    }

    #[test]
    fn from_bare_rejects_empty_string() {
        assert!(CredentialOfferId::from_bare("").is_err());
    }

    #[test]
    fn serde_round_trip_uses_prefixed_form() {
        let id = CredentialOfferId::from_bare("9hXq2vRtL8pK7f").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"offer_9hXq2vRtL8pK7f\"");

        let parsed: CredentialOfferId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn distinct_id_types_have_distinct_prefixes() {
        let bare = "9hXq2vRtL8pK7f";
        let tenant = TenantId::from_bare(bare).unwrap();
        let issuer = IssuerId::from_bare(bare).unwrap();
        let offer = CredentialOfferId::from_bare(bare).unwrap();
        assert_eq!(tenant.to_string(), "tenant_9hXq2vRtL8pK7f");
        assert_eq!(issuer.to_string(), "issuer_9hXq2vRtL8pK7f");
        assert_eq!(offer.to_string(), "offer_9hXq2vRtL8pK7f");
    }
}
