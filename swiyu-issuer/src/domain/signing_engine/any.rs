use super::{
    DevSigningEngine, GeneratedKeyPair, KeyPairId, KeyRole, RawPublicKey, Signature, SigningEngine,
    SigningEngineError, VaultSigningEngine,
};

/// Runtime-selected `SigningEngine` backend, picked once at startup.
///
/// The set of backends is closed (dev / vault / future hsm) and the choice
/// is fixed for the process lifetime, so an enum gives clean dispatch and
/// exhaustiveness checks when a new variant lands. Held behind
/// `Arc<AnySigningEngine>` and shared across handlers.
///
/// `Box<dyn SigningEngine>` is not an option: the trait's methods return
/// `impl Future<Output = …> + Send` (RPITIT), which makes it not
/// dyn-compatible. Restoring dyn-compatibility would require pulling in
/// `async-trait` (and the `Pin<Box<dyn Future>>` heap allocation per call
/// it forces) — an unnecessary dependency for a closed set of backends.
pub enum AnySigningEngine {
    Dev(DevSigningEngine),
    Vault(VaultSigningEngine),
}

impl SigningEngine for AnySigningEngine {
    async fn generate_keypair(
        &self,
        role: KeyRole,
    ) -> Result<GeneratedKeyPair, SigningEngineError> {
        match self {
            AnySigningEngine::Dev(engine) => engine.generate_keypair(role).await,
            AnySigningEngine::Vault(engine) => engine.generate_keypair(role).await,
        }
    }

    async fn get_public_key(&self, id: &KeyPairId) -> Result<RawPublicKey, SigningEngineError> {
        match self {
            AnySigningEngine::Dev(engine) => engine.get_public_key(id).await,
            AnySigningEngine::Vault(engine) => engine.get_public_key(id).await,
        }
    }

    async fn sign(&self, id: &KeyPairId, input: &[u8]) -> Result<Signature, SigningEngineError> {
        match self {
            AnySigningEngine::Dev(engine) => engine.sign(id, input).await,
            AnySigningEngine::Vault(engine) => engine.sign(id, input).await,
        }
    }

    async fn delete_keypair(&self, id: &KeyPairId) -> Result<(), SigningEngineError> {
        match self {
            AnySigningEngine::Dev(engine) => engine.delete_keypair(id).await,
            AnySigningEngine::Vault(engine) => engine.delete_keypair(id).await,
        }
    }
}
