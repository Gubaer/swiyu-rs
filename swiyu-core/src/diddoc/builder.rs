//! Builders that construct DID documents from raw key material.
//!
//! Lives next to the DIDDoc value types so callers that want to
//! produce a document — `swiyu-didtool` for CLI flows, `swiyu-issuer`
//! for the issuer-management task flow — share a single source of
//! truth. The function is pure: no I/O, no async, no dependence on
//! any specific keystore type.

use serde_json::{Value, json};

use super::public_keys::{ECKey, P256PublicKey, PublicKey, PublicKeyJWK};
use super::{DIDDoc, VerificationMethod, VerificationMethodOrRef};

/// Constructs the DID document for a freshly created DID, given the
/// `authentication` and `assertion` P-256 public keys.
///
/// The authorized (update) key is **not** embedded as a verification
/// method — it lives only in `parameters.updateKeys` of the DID log
/// entry as a multikey, and the proof references it via `did:key`.
/// Callers therefore pass only the two roles whose public keys appear
/// in the document: `authentication` and `assertion`.
///
/// Returned value is the JSON-LD form of the DID document, suitable
/// for embedding as `state.value` of an initial DID log entry.
pub fn build_initial_did_doc(
    did: &str,
    authentication: &P256PublicKey,
    assertion: &P256PublicKey,
) -> Value {
    let auth_vm_id = format!("{did}#authentication-key-01");
    let assert_vm_id = format!("{did}#assertion-key-01");

    let auth_key = PublicKey::Jwk(Box::new(PublicKeyJWK::EC(
        ECKey::from_p256_coordinates(&authentication.x, &authentication.y)
            .with_kid("authentication-key-01".into()),
    )));
    let assert_key = PublicKey::Jwk(Box::new(PublicKeyJWK::EC(
        ECKey::from_p256_coordinates(&assertion.x, &assertion.y)
            .with_kid("assertion-key-01".into()),
    )));

    DIDDoc::new(did.to_string())
        .with_context(json!([
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/jwk/v1"
        ]))
        .add_verification_method(VerificationMethod::new(
            auth_vm_id.clone(),
            "JsonWebKey2020".into(),
            did.to_string(),
            auth_key,
        ))
        .add_verification_method(VerificationMethod::new(
            assert_vm_id.clone(),
            "JsonWebKey2020".into(),
            did.to_string(),
            assert_key,
        ))
        .add_authentication(VerificationMethodOrRef::Reference(auth_vm_id))
        .add_assertion_method(VerificationMethodOrRef::Reference(assert_vm_id))
        .to_jsonld()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_p256() -> P256PublicKey {
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        for i in 0..32 {
            x[i] = i as u8;
            y[i] = (i + 100) as u8;
        }
        P256PublicKey { x, y }
    }

    #[test]
    fn build_initial_did_doc_embeds_did_and_two_verification_methods() {
        let did = "did:tdw:example.com:abc";
        let auth = fixture_p256();
        let assertion = fixture_p256();

        let doc = build_initial_did_doc(did, &auth, &assertion);

        assert_eq!(doc["id"], did);
        let vms = doc["verificationMethod"].as_array().unwrap();
        assert_eq!(vms.len(), 2);
        assert!(
            vms.iter()
                .any(|vm| vm["id"] == format!("{did}#authentication-key-01"))
        );
        assert!(
            vms.iter()
                .any(|vm| vm["id"] == format!("{did}#assertion-key-01"))
        );
    }

    #[test]
    fn build_initial_did_doc_does_not_embed_authorized_key() {
        let did = "did:tdw:example.com:abc";
        let auth = fixture_p256();
        let assertion = fixture_p256();

        let doc = build_initial_did_doc(did, &auth, &assertion);

        let vms = doc["verificationMethod"].as_array().unwrap();
        assert!(
            !vms.iter()
                .any(|vm| vm["id"] == format!("{did}#authorized-key-01"))
        );
    }

    #[test]
    fn build_initial_did_doc_uses_p256_jwk_for_both_keys() {
        let did = "did:tdw:example.com:abc";
        let auth = fixture_p256();
        let assertion = fixture_p256();

        let doc = build_initial_did_doc(did, &auth, &assertion);

        for vm in doc["verificationMethod"].as_array().unwrap() {
            assert_eq!(vm["type"], "JsonWebKey2020");
            assert_eq!(vm["publicKeyJwk"]["kty"], "EC");
            assert_eq!(vm["publicKeyJwk"]["crv"], "P-256");
        }
    }
}
