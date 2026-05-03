use serde_json::{Value, json};

use swiyu_core::diddoc::public_keys::{ECKey, PublicKey, PublicKeyJWK};
use swiyu_core::diddoc::{DIDDoc, VerificationMethod, VerificationMethodOrRef};

use crate::keystore::StagedKeys;

// The authorized (update) key signs DID log entries but is not embedded as a
// verification method in the DID document — it lives only in `parameters.updateKeys`
// as a multikey, and the proof references it via did:key.
pub(crate) fn build_did_doc(did: &str, staged: &StagedKeys) -> Value {
    let auth_vm_id = format!("{did}#authentication-key-01");
    let assert_vm_id = format!("{did}#assertion-key-01");

    let (auth_x, auth_y) = staged.authentication_key_coords();
    let (assert_x, assert_y) = staged.assertion_key_coords();

    let auth_key = PublicKey::Jwk(Box::new(PublicKeyJWK::EC(
        ECKey::from_p256_coordinates(&auth_x, &auth_y).with_kid("authentication-key-01".into()),
    )));
    let assert_key = PublicKey::Jwk(Box::new(PublicKeyJWK::EC(
        ECKey::from_p256_coordinates(&assert_x, &assert_y).with_kid("assertion-key-01".into()),
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
