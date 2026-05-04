use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use serde_json::{Value, json};
use tracing::debug;

use swiyu_core::didlog::eddsa_jcs_2022_hash;

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
    proof_purpose: &str,
    now: &str,
) -> Value {
    let vm_id = format!("did:key:{authorized_multikey}#{authorized_multikey}");
    let proof_config = json!({
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": vm_id,
        "proofPurpose": proof_purpose,
        "challenge": version_id,
        "created": now,
    });

    let proof_jcs = serde_jcs::to_vec(&proof_config).expect("proof config is serialisable");
    let document_jcs = serde_jcs::to_vec(document).expect("document is serialisable");
    debug!(
        "JCS proof_config ({} bytes): {}",
        proof_jcs.len(),
        String::from_utf8_lossy(&proof_jcs)
    );
    debug!(
        "JCS document ({} bytes): {}",
        document_jcs.len(),
        String::from_utf8_lossy(&document_jcs)
    );

    let hash_data = eddsa_jcs_2022_hash(document, &proof_config);
    debug!("hash_data (64 bytes): {}", hex_encode(&hash_data));

    let sig_bytes = signer.sign(&hash_data).to_bytes();
    debug!("signature (64 bytes): {}", hex_encode(&sig_bytes));
    debug!("authorized multikey: {}", authorized_multikey);

    let verifying = signer.verifying_key();
    match verifying.verify(&hash_data, &Signature::from_bytes(&sig_bytes)) {
        Ok(_) => debug!("local self-verification: OK"),
        Err(e) => debug!("local self-verification FAILED: {}", e),
    }

    let proof_value = format!("z{}", bs58::encode(sig_bytes).into_string());

    let mut proof = proof_config.as_object().unwrap().clone();
    proof.insert("proofValue".into(), json!(proof_value));
    Value::Object(proof)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
