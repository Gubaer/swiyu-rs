use super::{
    Ciphertext, DevSecretEncryptionEngine, SecretEncryptionEngine, SecretEncryptionError,
    VaultSecretEncryptionEngine,
};

// Enum (same shape as `AnySigningEngine`) rather than `Box<dyn ...>`: the
// trait's methods return `impl Future<Output = ...> + Send` (RPITIT), which
// makes it not dyn-compatible. Match-dispatch also gives exhaustiveness
// checks when a new backend is added.
pub enum AnySecretEncryptionEngine {
    Dev(DevSecretEncryptionEngine),
    Vault(VaultSecretEncryptionEngine),
}

impl SecretEncryptionEngine for AnySecretEncryptionEngine {
    async fn encrypt(
        &self,
        key_name: &str,
        plaintext: &[u8],
    ) -> Result<Ciphertext, SecretEncryptionError> {
        match self {
            AnySecretEncryptionEngine::Dev(engine) => engine.encrypt(key_name, plaintext).await,
            AnySecretEncryptionEngine::Vault(engine) => engine.encrypt(key_name, plaintext).await,
        }
    }

    async fn decrypt(
        &self,
        key_name: &str,
        ciphertext: &Ciphertext,
    ) -> Result<Vec<u8>, SecretEncryptionError> {
        match self {
            AnySecretEncryptionEngine::Dev(engine) => engine.decrypt(key_name, ciphertext).await,
            AnySecretEncryptionEngine::Vault(engine) => engine.decrypt(key_name, ciphertext).await,
        }
    }
}
