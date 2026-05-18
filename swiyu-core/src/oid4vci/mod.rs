//! SWIYU OID4VCI profile constants.
//!
//! The four protocol values the SWIYU profile fixes regardless of
//! credential type — credential format, credential signing
//! algorithm, holder-key binding methods, and proof types —
//! centralised so every SWIYU producer (issuer binaries) and
//! consumer (verifiers, test crates) reads from one source of
//! truth instead of duplicating string literals.
//!
//! OID4VCI permits per-credential-type variation on these fields
//! in general; the SWIYU profile collapses that variation to
//! constants, which is why they live here as profile-level facts
//! rather than per-row columns in any issuer's database.

use serde_json::{Value, json};

/// OID4VCI credential format identifier for SD-JWT Verifiable
/// Credentials.
pub const FORMAT: &str = "vc+sd-jwt";

/// JOSE algorithm SWIYU uses to sign credentials' assertions and
/// to verify the holder's proof JWTs. ES256 over the P-256 curve.
pub const CREDENTIAL_SIGNING_ALG: &str = "ES256";

/// Cryptographic-binding method SWIYU advertises in the OID4VCI
/// metadata: the holder key embedded as a JWK in the credential's
/// `cnf.jwk` claim. DID-based bindings are not in the profile.
pub const CRYPTOGRAPHIC_BINDING_METHOD_JWK: &str = "jwk";

/// OID4VCI proof type SWIYU wallets use to prove possession of the
/// holder key at credential issuance — a self-signed JWT.
pub const PROOF_TYPE_JWT: &str = "jwt";

/// `credential_signing_alg_values_supported` array for the SWIYU
/// profile. Always `["ES256"]`.
pub fn credential_signing_alg_values_supported() -> Value {
    json!([CREDENTIAL_SIGNING_ALG])
}

/// `cryptographic_binding_methods_supported` array for the SWIYU
/// profile. Always `["jwk"]`.
pub fn cryptographic_binding_methods_supported() -> Value {
    json!([CRYPTOGRAPHIC_BINDING_METHOD_JWK])
}

/// `proof_types_supported` object for the SWIYU profile. One entry
/// keyed by [`PROOF_TYPE_JWT`] whose
/// `proof_signing_alg_values_supported` advertises
/// [`CREDENTIAL_SIGNING_ALG`] as the only acceptable holder-proof
/// signing algorithm.
pub fn proof_types_supported() -> Value {
    json!({
        PROOF_TYPE_JWT: {
            "proof_signing_alg_values_supported": [CREDENTIAL_SIGNING_ALG]
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_signing_alg_values_round_trips() {
        assert_eq!(
            credential_signing_alg_values_supported(),
            json!(["ES256"])
        );
    }

    #[test]
    fn cryptographic_binding_methods_round_trips() {
        assert_eq!(cryptographic_binding_methods_supported(), json!(["jwk"]));
    }

    #[test]
    fn proof_types_advertises_jwt_with_es256() {
        let v = proof_types_supported();
        assert_eq!(
            v["jwt"]["proof_signing_alg_values_supported"],
            json!(["ES256"])
        );
    }
}
