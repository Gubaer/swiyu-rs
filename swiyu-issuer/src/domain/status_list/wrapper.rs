//! Status-list JWT (`application/statuslist+jwt`) wrapper construction.
//!
//! Orchestration only: the JSON shape, zlib+base64 encoding of the
//! bitstring, and the typed envelope all come from
//! `swiyu_core::statuslist`. This module assembles the JWS compact
//! form (`header_b64.payload_b64.signature_b64`) and signs it with the
//! issuer's assertion key via the [`SigningEngine`].

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use swiyu_core::statuslist::{
    STATUSLIST_JWT_TYP, SWIYU_STATUS_LIST_BITS, StatusList as CoreStatusList, StatusListError,
    StatusListJwtHeader, StatusListJwtPayload,
};
use thiserror::Error;

use super::StatusList;
use crate::domain::{Issuer, SigningEngine, SigningEngineError};

#[derive(Debug, Error)]
pub enum BuildError {
    #[error("status_list {0} has no registry_url; create_status_list_entry must run first")]
    MissingRegistryUrl(String),
    #[error("issuer {0} has no assertion_key_id")]
    MissingAssertionKey(String),
    #[error("status list decode: {0}")]
    StatusList(#[from] StatusListError),
    #[error("signing engine: {0}")]
    Engine(#[from] SigningEngineError),
    #[error("JSON serialisation: {0}")]
    Json(#[from] serde_json::Error),
}

/// Builds the signed `statuslist+jwt` for a status list.
///
/// `now` is the value embedded in the payload's `iat` claim and the
/// moment over which the signature is computed; callers pass the same
/// value they would log so test fixtures can pin it deterministically.
pub async fn build_signed<S: SigningEngine>(
    list: &StatusList,
    issuer: &Issuer,
    engine: &S,
    now: DateTime<Utc>,
) -> Result<String, BuildError> {
    let registry_url = list
        .registry_url
        .as_deref()
        .ok_or_else(|| BuildError::MissingRegistryUrl(list.id.bare().to_string()))?;
    let assertion_key_id = issuer
        .assertion_key_id
        .as_ref()
        .ok_or_else(|| BuildError::MissingAssertionKey(issuer.id.bare().to_string()))?;

    let core_list = CoreStatusList::from_raw(SWIYU_STATUS_LIST_BITS, list.bitstring.clone())?;

    let payload = StatusListJwtPayload::new(
        issuer.did.clone(),
        registry_url.to_string(),
        now.timestamp() as u64,
        None,
        core_list,
    );
    let header = StatusListJwtHeader::new(
        "ES256".to_string(),
        STATUSLIST_JWT_TYP.to_string(),
        format!("{}#assertion-key-01", issuer.did),
    );

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&serde_json::Value::from(&header))?);
    let payload_b64 =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&serde_json::Value::from(&payload))?);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let digest = Sha256::digest(signing_input.as_bytes());
    let signature = engine.sign(assertion_key_id, &digest).await?;
    let signature_b64 = URL_SAFE_NO_PAD.encode(&signature.bytes);

    Ok(format!("{header_b64}.{payload_b64}.{signature_b64}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    use p256::ecdsa::SigningKey as P256SigningKey;
    use p256::ecdsa::VerifyingKey as P256VerifyingKey;
    use p256::ecdsa::signature::Verifier as _;
    use p256::ecdsa::signature::hazmat::PrehashSigner as _;
    use serde_json::Value;
    use uuid::Uuid;

    use crate::domain::{
        IssuerId, IssuerState, KeyAlgorithm, KeyPairId, Signature, SigningEngineError,
        StatusListId, TenantId,
    };
    use crate::worker::test_support::{MockSigningEngine, SignCall};

    const FIXTURE_ENTRY_ID: &str = "11111111-2222-3333-4444-555555555555";
    const FIXTURE_REGISTRY_URL: &str = "https://status-reg.test/lists/abc.jwt";
    const FIXTURE_DID: &str = "did:tdw:dev.example.com:test";

    fn fixture_kid(byte: u8) -> KeyPairId {
        let mut bytes = [byte; 16];
        bytes[6] = (bytes[6] & 0x0F) | 0x40;
        bytes[8] = (bytes[8] & 0x3F) | 0x80;
        KeyPairId::from(Uuid::from_bytes(bytes))
    }

    fn fixture_now() -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_768_982_400, 0).unwrap()
    }

    fn fixture_issuer() -> Issuer {
        Issuer {
            id: IssuerId::generate(),
            tenant_id: TenantId::generate(),
            did: FIXTURE_DID.into(),
            state: Some(IssuerState::Active),
            description: None,
            authorized_key_id: Some(fixture_kid(0x11)),
            authentication_key_id: Some(fixture_kid(0x22)),
            assertion_key_id: Some(fixture_kid(0x33)),
            display_name: Some("Test issuer".into()),
            logo_uri: None,
            locale: None,
            created_at: fixture_now(),
        }
    }

    fn fixture_list() -> StatusList {
        StatusList {
            id: StatusListId::generate(),
            issuer_id: IssuerId::generate(),
            bitstring: vec![0u8; super::super::BITSTRING_BYTES],
            allocated_count: 0,
            committed_version: 0,
            published_version: 0,
            last_publish_attempt_at: None,
            last_publish_error: None,
            next_publish_attempt_at: None,
            publish_attempts: 0,
            created_at: fixture_now(),
            registry_entry_id: Some(FIXTURE_ENTRY_ID.into()),
            registry_url: Some(FIXTURE_REGISTRY_URL.into()),
        }
    }

    fn split_compact(jwt: &str) -> (String, String, Vec<u8>) {
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "expected three segments in {jwt}");
        let signature = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        (parts[0].to_string(), parts[1].to_string(), signature)
    }

    fn decode_segment(b64: &str) -> Value {
        let bytes = URL_SAFE_NO_PAD.decode(b64).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn missing_registry_url_is_terminal() {
        let mut list = fixture_list();
        list.registry_url = None;
        let issuer = fixture_issuer();
        let engine = MockSigningEngine::new();

        let err = build_signed(&list, &issuer, &engine, fixture_now())
            .await
            .unwrap_err();
        assert!(matches!(err, BuildError::MissingRegistryUrl(_)));
    }

    #[tokio::test]
    async fn missing_assertion_key_is_terminal() {
        let list = fixture_list();
        let mut issuer = fixture_issuer();
        issuer.assertion_key_id = None;
        let engine = MockSigningEngine::new();

        let err = build_signed(&list, &issuer, &engine, fixture_now())
            .await
            .unwrap_err();
        assert!(matches!(err, BuildError::MissingAssertionKey(_)));
    }

    #[tokio::test]
    async fn iat_matches_signing_moment() {
        let list = fixture_list();
        let issuer = fixture_issuer();
        let engine = MockSigningEngine::new();
        engine.enqueue_sign(SignCall::Ok(Signature {
            algorithm: KeyAlgorithm::EcdsaP256,
            bytes: vec![0u8; 64],
        }));

        let now = fixture_now();
        let jwt = build_signed(&list, &issuer, &engine, now).await.unwrap();
        let (_h, payload_b64, _sig) = split_compact(&jwt);
        let payload = decode_segment(&payload_b64);
        assert_eq!(payload["iat"].as_i64().unwrap(), now.timestamp());
    }

    #[tokio::test]
    async fn header_carries_alg_typ_and_kid() {
        let list = fixture_list();
        let issuer = fixture_issuer();
        let engine = MockSigningEngine::new();
        engine.enqueue_sign(SignCall::Ok(Signature {
            algorithm: KeyAlgorithm::EcdsaP256,
            bytes: vec![0u8; 64],
        }));

        let jwt = build_signed(&list, &issuer, &engine, fixture_now())
            .await
            .unwrap();
        let (header_b64, _p, _sig) = split_compact(&jwt);
        let header = decode_segment(&header_b64);
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["typ"], "statuslist+jwt");
        assert_eq!(header["kid"], format!("{FIXTURE_DID}#assertion-key-01"));
    }

    #[tokio::test]
    async fn signature_verifies_under_assertion_public_key() {
        // Generate a real P-256 keypair, configure the mock engine to
        // produce signatures with that key, then verify build_signed's
        // output round-trips through the public side.
        let signing_key = P256SigningKey::random(&mut rand_core::OsRng);
        let verifying_key: P256VerifyingKey = (&signing_key).into();

        let issuer = fixture_issuer();
        let assertion_key_id = issuer.assertion_key_id.unwrap();

        let engine = MockSigningEngine::new();

        // Mock returns the same key for any get_public_key (not used
        // here) and computes a real ES256 signature for sign().
        // We can't intercept input via the mock's queue, so we
        // pre-queue a signature computed over the canonical signing
        // input. Reconstruct that input here.
        let list = fixture_list();
        let core_list =
            CoreStatusList::from_raw(SWIYU_STATUS_LIST_BITS, list.bitstring.clone()).unwrap();
        let now = fixture_now();
        let payload = StatusListJwtPayload::new(
            issuer.did.clone(),
            FIXTURE_REGISTRY_URL.to_string(),
            now.timestamp() as u64,
            None,
            core_list,
        );
        let header = StatusListJwtHeader::new(
            "ES256".to_string(),
            STATUSLIST_JWT_TYP.to_string(),
            format!("{}#assertion-key-01", issuer.did),
        );
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&Value::from(&header)).unwrap());
        let payload_b64 =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&Value::from(&payload)).unwrap());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let digest = Sha256::digest(signing_input.as_bytes());
        // Match the engine: sign over the prehash, not the raw bytes.
        let real_sig: p256::ecdsa::Signature = signing_key.sign_prehash(&digest).unwrap();

        engine.enqueue_sign(SignCall::Ok(Signature {
            algorithm: KeyAlgorithm::EcdsaP256,
            bytes: real_sig.to_bytes().to_vec(),
        }));

        let jwt = build_signed(&list, &issuer, &engine, now).await.unwrap();
        let (h, p, sig_bytes) = split_compact(&jwt);
        let recovered_input = format!("{h}.{p}");
        let signature = p256::ecdsa::Signature::from_slice(&sig_bytes).unwrap();
        // Verifier::verify hashes raw input internally; equivalent to
        // verify_prehash(SHA-256(input)).
        verifying_key
            .verify(recovered_input.as_bytes(), &signature)
            .unwrap();

        // Sanity: the assertion_key_id was the one passed to sign().
        let invocations = engine.sign_invocations.lock().unwrap();
        assert_eq!(invocations.len(), 1);
        assert_eq!(invocations[0].0, assertion_key_id);
    }

    #[tokio::test]
    async fn signing_engine_backend_error_propagates() {
        let list = fixture_list();
        let issuer = fixture_issuer();
        let engine = MockSigningEngine::new();
        engine.enqueue_sign(SignCall::Backend("hsm offline".into()));

        let err = build_signed(&list, &issuer, &engine, fixture_now())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            BuildError::Engine(SigningEngineError::Backend(_))
        ));
    }
}
