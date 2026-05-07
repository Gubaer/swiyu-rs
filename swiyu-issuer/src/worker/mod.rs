//! Task-dispatching worker for swiyu-issuer.
//!
//! A single tokio task that picks operation tasks off the queue and
//! drives them to completion through their per-task-type step sequence.
//! See `specs/impl-issuer.md` (Worker section).

pub mod backoff;
pub mod create_issuer;
pub mod deactivate_issuer;
pub mod dispatch;
pub mod registry;
pub mod rotate_keys;
pub mod runner;
pub mod status_list_publisher;

/// Pulls the SWIYU registry UUID out of a parsed issuer DID.
///
/// Canonical issuer DIDs have the form
/// `did:tdw:<scid>:<domain>:<path-segments>` where the last path
/// segment is the registry-assigned UUID. Returns `None` when the DID
/// carries no path component.
pub(crate) fn registry_identifier(did: &swiyu_core::did::DID) -> Option<String> {
    did.path()?
        .rsplit(':')
        .next()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use swiyu_core::did::DID;

    use super::registry_identifier;

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
        let did = parse("did:tdw:scid:example.com");
        assert!(registry_identifier(&did).is_none());
    }
}

pub use runner::{Worker, WorkerError};
pub use status_list_publisher::{PublisherConfig, StatusListPublisher};

// `test_support` is hand-rolled mocks for `RegistryFacade` and
// `SigningEngine`, used by both inline executor tests and integration
// tests under `tests/`. It is always compiled (rather than gated on
// `cfg(test)`) so integration tests — which see the library without
// `cfg(test)` — can access it. `#[doc(hidden)]` keeps it out of the
// public API surface.
#[doc(hidden)]
pub mod test_support;
