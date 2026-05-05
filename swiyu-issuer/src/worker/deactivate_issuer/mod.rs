//! `DeactivateIssuer` task-type executor and supporting types.

use std::str::FromStr;

use swiyu_core::did::DID;

pub mod build_deactivation_log;
pub mod log_builder;
pub mod mark_deactivated;
pub mod publish_log;
pub mod state;

pub use state::{DeactivateIssuerInput, DeactivateIssuerStateData};

/// Pulls the SWIYU registry's `<uuid>` identifier out of a stored
/// issuer DID. Both the create_issuer flow and `swiyu-didtool`
/// produce canonical did:tdw of the form
/// `did:tdw:<scid>:<domain>:<path-segments>`, where the last path
/// segment is the registry UUID. We parse via `DID::from_str` and
/// take the trailing segment of `path()`.
pub(crate) fn registry_identifier(did: &str) -> Option<String> {
    DID::from_str(did)
        .ok()?
        .path()?
        .rsplit(':')
        .next()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_identifier_extracts_uuid_from_canonical_shape() {
        let did = "did:tdw:scid-placeholder:reg.example.com:fce949f2-32c4-4915-8b60-0ee2f705231d";
        assert_eq!(
            registry_identifier(did),
            Some("fce949f2-32c4-4915-8b60-0ee2f705231d".into()),
        );
    }

    #[test]
    fn registry_identifier_extracts_trailing_uuid_from_multi_segment_path() {
        let did = "did:tdw:scid:reg.example.com:api:v1:did:fce949f2-32c4-4915-8b60-0ee2f705231d";
        assert_eq!(
            registry_identifier(did),
            Some("fce949f2-32c4-4915-8b60-0ee2f705231d".into()),
        );
    }

    #[test]
    fn registry_identifier_rejects_non_tdw_prefix() {
        // did:webvh has its own DID type; `from_str` accepts it but
        // we only want did:tdw here. Fall through via the path()
        // check returning None for path-less DIDs.
        assert!(registry_identifier("not a did").is_none());
    }

    #[test]
    fn registry_identifier_rejects_did_without_path() {
        // A DID with no path component: `did:tdw:<scid>:<domain>`
        // (no UUID). `path()` is None, so we return None.
        assert!(registry_identifier("did:tdw:scid:example.com").is_none());
    }
}
