//! In-memory test double for [`SigningEngine`].
//!
//! Records each call in order and replays a pre-configured queue of
//! outcomes; tests fail loudly on under- or over-call. Used by
//! per-step worker tests, status-list wrapper tests, and OIDC
//! credential-issuance tests — anywhere a real signing engine is too
//! heavyweight.

use std::future::Future;
use std::sync::Mutex;

use crate::domain::signing_engine::{
    GeneratedKeyPair, KeyAlgorithm, KeyPairId, KeyRole, RawPublicKey, Signature, SigningEngine,
    SigningEngineError,
};

pub fn fixture_ed25519_pk() -> RawPublicKey {
    RawPublicKey {
        algorithm: KeyAlgorithm::Ed25519,
        bytes: vec![0xab; 32],
    }
}

pub fn fixture_p256_pk() -> RawPublicKey {
    let mut bytes = vec![0x04];
    bytes.extend_from_slice(&[0xcd; 32]);
    bytes.extend_from_slice(&[0xef; 32]);
    RawPublicKey {
        algorithm: KeyAlgorithm::EcdsaP256,
        bytes,
    }
}

pub fn fixture_signature() -> Signature {
    Signature {
        algorithm: KeyAlgorithm::Ed25519,
        bytes: vec![0x42; 64],
    }
}

pub enum GenerateKeypairCall {
    Ok(GeneratedKeyPair),
    Backend(String),
    Unsupported,
}

pub enum GetPublicKeyCall {
    Ok(RawPublicKey),
    NotFound(KeyPairId),
    Backend(String),
}

pub enum SignCall {
    Ok(Signature),
    NotFound(KeyPairId),
    Backend(String),
}

#[derive(Default)]
pub struct MockSigningEngine {
    generate_queue: Mutex<Vec<GenerateKeypairCall>>,
    public_key_queue: Mutex<Vec<GetPublicKeyCall>>,
    sign_queue: Mutex<Vec<SignCall>>,
    pub generate_invocations: Mutex<Vec<KeyRole>>,
    pub public_key_invocations: Mutex<Vec<KeyPairId>>,
    pub sign_invocations: Mutex<Vec<(KeyPairId, Vec<u8>)>>,
}

impl MockSigningEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enqueue_generate(&self, call: GenerateKeypairCall) {
        self.generate_queue.lock().unwrap().push(call);
    }

    pub fn enqueue_public_key(&self, call: GetPublicKeyCall) {
        self.public_key_queue.lock().unwrap().push(call);
    }

    pub fn enqueue_sign(&self, call: SignCall) {
        self.sign_queue.lock().unwrap().push(call);
    }
}

impl SigningEngine for MockSigningEngine {
    fn generate_keypair(
        &self,
        role: KeyRole,
    ) -> impl Future<Output = Result<GeneratedKeyPair, SigningEngineError>> + Send {
        self.generate_invocations.lock().unwrap().push(role);
        let next = self.generate_queue.lock().unwrap().remove(0);
        async move {
            match next {
                GenerateKeypairCall::Ok(kp) => Ok(kp),
                GenerateKeypairCall::Backend(message) => {
                    Err(SigningEngineError::Backend(message.into()))
                }
                GenerateKeypairCall::Unsupported => Err(SigningEngineError::UnsupportedAlgorithm),
            }
        }
    }

    fn get_public_key(
        &self,
        id: &KeyPairId,
    ) -> impl Future<Output = Result<RawPublicKey, SigningEngineError>> + Send {
        self.public_key_invocations.lock().unwrap().push(*id);
        let next = self.public_key_queue.lock().unwrap().remove(0);
        async move {
            match next {
                GetPublicKeyCall::Ok(pk) => Ok(pk),
                GetPublicKeyCall::NotFound(id) => Err(SigningEngineError::KeyNotFound(id)),
                GetPublicKeyCall::Backend(message) => {
                    Err(SigningEngineError::Backend(message.into()))
                }
            }
        }
    }

    fn sign(
        &self,
        id: &KeyPairId,
        input: &[u8],
    ) -> impl Future<Output = Result<Signature, SigningEngineError>> + Send {
        self.sign_invocations
            .lock()
            .unwrap()
            .push((*id, input.to_vec()));
        let next = self.sign_queue.lock().unwrap().remove(0);
        async move {
            match next {
                SignCall::Ok(sig) => Ok(sig),
                SignCall::NotFound(id) => Err(SigningEngineError::KeyNotFound(id)),
                SignCall::Backend(message) => Err(SigningEngineError::Backend(message.into())),
            }
        }
    }

    async fn delete_keypair(&self, _id: &KeyPairId) -> Result<(), SigningEngineError> {
        Ok(())
    }
}
