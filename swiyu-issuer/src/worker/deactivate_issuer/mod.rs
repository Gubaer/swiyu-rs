//! `DeactivateIssuer` task-type executor and supporting types.

use swiyu_core::did::DID;

pub mod build_deactivation_log;
pub mod log_builder;
pub mod mark_deactivated;
pub mod publish_log;
pub mod state;

pub use state::{DeactivateIssuerInput, DeactivateIssuerStateData};

/// Pulls the SWIYU registry's `<uuid>` identifier out of a parsed
/// issuer DID. Both the create_issuer flow and `swiyu-didtool`
/// produce canonical did:tdw of the form
/// `did:tdw:<scid>:<domain>:<path-segments>`, where the last path
/// segment is the registry UUID.
pub(crate) fn registry_identifier(did: &DID) -> Option<String> {
    did.path()?
        .rsplit(':')
        .next()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;

    fn parse(s: &str) -> DID {
        DID::from_str(s).expect("valid did fixture")
    }

    #[test]
    fn registry_identifier_extracts_uuid_from_canonical_shape() {
        let did =
            parse("did:tdw:scid-placeholder:reg.example.com:fce949f2-32c4-4915-8b60-0ee2f705231d");
        assert_eq!(
            registry_identifier(&did),
            Some("fce949f2-32c4-4915-8b60-0ee2f705231d".into()),
        );
    }

    #[test]
    fn registry_identifier_extracts_trailing_uuid_from_multi_segment_path() {
        let did =
            parse("did:tdw:scid:reg.example.com:api:v1:did:fce949f2-32c4-4915-8b60-0ee2f705231d");
        assert_eq!(
            registry_identifier(&did),
            Some("fce949f2-32c4-4915-8b60-0ee2f705231d".into()),
        );
    }

    #[test]
    fn registry_identifier_returns_none_for_did_without_path() {
        // A DID with no path component: `did:tdw:<scid>:<domain>`
        // (no UUID). `path()` is None, so we return None.
        let did = parse("did:tdw:scid:example.com");
        assert!(registry_identifier(&did).is_none());
    }
}
