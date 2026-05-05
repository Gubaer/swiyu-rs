//! `DeactivateIssuer` task-type executor and supporting types.

pub mod build_deactivation_log;
pub mod log_builder;
pub mod mark_deactivated;
pub mod publish_log;
pub mod state;

pub use state::{DeactivateIssuerInput, DeactivateIssuerStateData};

/// Pulls the SWIYU registry's `<uuid>` identifier out of a stored
/// issuer DID of the form
/// `did:tdw:<domain>:<path-segments>:<uuid>:<scid>`.
///
/// `swiyu-core::did::DID::parse` expects the spec-canonical
/// `did:tdw:<scid>:<domain>:<path>` order, but the create_issuer
/// flow constructs DIDs with the SCID as the *trailing* segment
/// (see `worker/create_issuer/log_builder.rs`). Resolving that
/// inconsistency in swiyu-core is out of scope for the deactivate
/// slice; here we accept whatever shape create_issuer stores and
/// pull out the segment immediately before the SCID, which is the
/// registry UUID. The registry's allocation URL always carries a
/// UUID path segment, so on issuers created through the task flow
/// the second-to-last segment is the identifier we want.
pub(crate) fn registry_identifier(did: &str) -> Option<String> {
    let rest = did.strip_prefix("did:tdw:")?;
    let segments: Vec<&str> = rest.split(':').filter(|s| !s.is_empty()).collect();
    if segments.len() < 3 {
        return None;
    }
    Some(segments[segments.len() - 2].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_identifier_extracts_uuid_from_canonical_shape() {
        let did = "did:tdw:reg.example.com:fce949f2-32c4-4915-8b60-0ee2f705231d:scid-placeholder";
        assert_eq!(
            registry_identifier(did),
            Some("fce949f2-32c4-4915-8b60-0ee2f705231d".into()),
        );
    }

    #[test]
    fn registry_identifier_rejects_non_tdw_prefix() {
        assert!(registry_identifier("did:webvh:host:uuid:scid").is_none());
        assert!(registry_identifier("not a did").is_none());
    }

    #[test]
    fn registry_identifier_rejects_too_few_segments() {
        // Need at least 3 segments after the prefix (domain, uuid, scid).
        assert!(registry_identifier("did:tdw:host:scid").is_none());
        assert!(registry_identifier("did:tdw:scid").is_none());
    }
}
