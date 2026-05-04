use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use serde_json::Value;
use tracing::debug;

use swiyu_core::proof::{Cryptosuite, DataIntegrityProof, ProofConfig, ProofPurpose};

/// Builds a Data Integrity Proof (`eddsa-jcs-2022`) over `document`, signed by
/// the authorized EdDSA key. The verification method is encoded as
/// `did:key:<multikey>#<multikey>` so verifiers can fetch it without a registry
/// round-trip.
///
/// Includes a local self-verification step: any failure here points to a
/// key/signature mismatch rather than a JCS canonicalization issue, which has
/// historically been the harder kind of bug to diagnose.
pub(crate) fn build_proof(
    signer: &SigningKey,
    document: &Value,
    authorized_multikey: &str,
    version_id: &str,
    proof_purpose: ProofPurpose,
    now: &str,
) -> Value {
    let vm_id = format!("did:key:{authorized_multikey}#{authorized_multikey}");
    let proof_config = ProofConfig {
        cryptosuite: Cryptosuite::EddsaJcs2022,
        verification_method: vm_id,
        proof_purpose,
        challenge: version_id.into(),
        created: now.into(),
    };

    let hash_data = proof_config.signing_input(document);
    debug!("hash_data (64 bytes): {}", hex_encode(&hash_data));

    let sig_bytes = signer.sign(&hash_data).to_bytes();
    debug!("signature (64 bytes): {}", hex_encode(&sig_bytes));
    debug!("authorized multikey: {}", authorized_multikey);

    let verifying = signer.verifying_key();
    match verifying.verify(&hash_data, &Signature::from_bytes(&sig_bytes)) {
        Ok(_) => debug!("local self-verification: OK"),
        Err(e) => debug!("local self-verification FAILED: {}", e),
    }

    DataIntegrityProof::from_signature(proof_config, &sig_bytes).to_value()
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
