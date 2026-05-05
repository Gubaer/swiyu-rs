pub mod lookup;
pub mod verify;

use swiyu_core::did::{DID, DIDError};
use swiyu_core::diddoc::DIDDocError;
use swiyu_core::statuslist::StatusListError;
use swiyu_core::truststatement::TrustStatementError;

use crate::cmd::ResolveError;
use crate::cmd::http::FetchError;
use crate::keystore::KeyStoreError;

#[cfg(test)]
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
#[cfg(test)]
use serde_json::Value;
#[cfg(test)]
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    #[error("--trust-registry-url or SWIYU_TRUST_REGISTRY_URL is required")]
    TrustRegistryUrlMissing,
    #[error("--trust-issuer or SWIYU_TRUST_ISSUER_DID is required")]
    TrustIssuerMissing,
    #[error("trust registry response is not a JSON array of JWT strings")]
    ResponseShape,
    #[error("trust statement #{n} is malformed: {source}")]
    Statement {
        n: usize,
        #[source]
        source: TrustStatementError,
    },
    #[error("cannot resolve issuer DID log for '{iss}': {reason}")]
    IssuerResolution { iss: String, reason: String },
    #[error("status list at '{url}' is malformed: {reason}")]
    StatusListMalformed { url: String, reason: String },
    #[error("status list signature verification failed")]
    StatusListSignatureInvalid,
    #[error(transparent)]
    StatusList(#[from] StatusListError),
    #[error(transparent)]
    Fetch(#[from] FetchError),
    #[error(transparent)]
    Resolve(#[from] ResolveError),
    #[error(transparent)]
    Did(#[from] DIDError),
    #[error(transparent)]
    DidDoc(#[from] DIDDocError),
    #[error(transparent)]
    KeyStore(#[from] KeyStoreError),
}

pub(crate) fn build_endpoint(base_url: &str, did: &DID) -> String {
    let trimmed = base_url.trim_end_matches('/');
    format!(
        "{trimmed}/api/v1/truststatements/identity/{}",
        did.url_path_segment()
    )
}

// ── Test fixtures (cfg(test) only, shared across submodules) ─────────────────

/// Builds a single SD-JWT VC string with the given disclosed claims.
/// The signature segment is junk — callers that need a valid signature must
/// build their own JWT.
#[cfg(test)]
pub(crate) fn build_jwt(payload_extra: Value, disclosures: Vec<serde_json::Value>) -> String {
    use serde_json::json;
    let mut sd_hashes: Vec<String> = Vec::new();
    let mut encoded_disclosures: Vec<String> = Vec::new();
    for d in &disclosures {
        let json = serde_json::to_string(d).unwrap();
        let enc = URL_SAFE_NO_PAD.encode(json.as_bytes());
        let hash = URL_SAFE_NO_PAD.encode(Sha256::digest(enc.as_bytes()));
        sd_hashes.push(hash);
        encoded_disclosures.push(enc);
    }

    let mut payload = json!({
        "_sd": sd_hashes,
        "_sd_alg": "sha-256",
        "vct": "TrustStatementIdentityV1",
        "iss": "did:tdw:Q123:trust-reg.example.com:api:v1:did:abc",
        "iat": 1776683538u64,
        "exp": 1798761600u64,
        "nbf": 1767225600u64,
        "status": {
            "status_list": {
                "type": "SwissTokenStatusList-1.0",
                "idx": 643,
                "uri": "https://status-reg.example.com/api/v1/statuslist/abc.jwt",
            }
        }
    });
    let payload_obj = payload.as_object_mut().unwrap();
    if let Some(extra_obj) = payload_extra.as_object() {
        for (k, v) in extra_obj {
            payload_obj.insert(k.clone(), v.clone());
        }
    }

    let header =
        json!({ "alg": "ES256", "kid": "did:tdw:Q123:...:abc#assert-key-02", "typ": "vc+sd-jwt" });
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
    let sig_b64 = URL_SAFE_NO_PAD.encode(b"junk-signature-not-verified");
    let mut out = format!("{header_b64}.{payload_b64}.{sig_b64}");
    for d in encoded_disclosures {
        out.push('~');
        out.push_str(&d);
    }
    out.push('~');
    out
}

#[cfg(test)]
pub(crate) fn is_state_actor_disclosure(b: bool) -> serde_json::Value {
    serde_json::json!(["rIPBffSxmopF09SQ2-gjaQ", "isStateActor", b])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_endpoint_percent_encodes_did() {
        let did: DID = "did:tdw:Q123:host.example.com:api:v1:did:abc"
            .parse()
            .unwrap();
        let url = build_endpoint("https://trust-reg.example.com/", &did);
        assert_eq!(
            url,
            "https://trust-reg.example.com/api/v1/truststatements/identity/did%3Atdw%3AQ123%3Ahost.example.com%3Aapi%3Av1%3Adid%3Aabc"
        );
    }

    #[test]
    fn build_endpoint_handles_trailing_slash() {
        let did: DID = "did:tdw:abc:example.com".parse().unwrap();
        let with_slash = build_endpoint("https://x/", &did);
        let without = build_endpoint("https://x", &did);
        assert_eq!(with_slash, without);
    }
}
