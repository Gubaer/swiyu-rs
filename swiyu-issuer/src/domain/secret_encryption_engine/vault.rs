use super::{Ciphertext, SecretEncryptionEngine, SecretEncryptionError};

// Stub backed by HashiCorp Vault's Transit secrets engine. The empty type
// exists so `AnySecretEncryptionEngine` has a valid `Vault` arm and the
// dispatch impl compiles; the builder refuses to construct one.
pub struct VaultSecretEncryptionEngine;

impl SecretEncryptionEngine for VaultSecretEncryptionEngine {
    async fn encrypt(
        &self,
        _key_name: &str,
        _plaintext: &[u8],
    ) -> Result<Ciphertext, SecretEncryptionError> {
        unimplemented!("VaultSecretEncryptionEngine is not yet implemented")
    }

    async fn decrypt(
        &self,
        _key_name: &str,
        _ciphertext: &Ciphertext,
    ) -> Result<Vec<u8>, SecretEncryptionError> {
        unimplemented!("VaultSecretEncryptionEngine is not yet implemented")
    }
}
