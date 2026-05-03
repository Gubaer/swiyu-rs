use serde_json::Value;

use swiyu_core::diddoc::builder::build_initial_did_doc;

use crate::keystore::StagedKeys;

// The authorized (update) key signs DID log entries but is not embedded as a
// verification method in the DID document — it lives only in `parameters.updateKeys`
// as a multikey, and the proof references it via did:key.
//
// Thin wrapper around `swiyu_core::diddoc::builder::build_initial_did_doc` that
// extracts the P-256 coordinates from `StagedKeys` and forwards.
pub(crate) fn build_did_doc(did: &str, staged: &StagedKeys) -> Value {
    let authentication_xy = staged.authentication_key_coords();
    let assertion_xy = staged.assertion_key_coords();
    build_initial_did_doc(did, &authentication_xy, &assertion_xy)
}
