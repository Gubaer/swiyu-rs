use std::future::Future;

use thiserror::Error;
use uuid::Uuid;

pub use swiyu_core::KeyRole;

pub mod any;
pub mod dev;
pub mod vault;
pub use any::AnySigningEngine;
pub use dev::DevSigningEngine;
pub use vault::{VaultSigningEngine, VaultSigningEngineConfig};

/// The signing algorithm of a key pair.
///
/// Limited to the two algorithms required by SWIYU. The mapping from
/// `KeyRole` to algorithm is fixed by `KeyAlgorithm::for_role`:
///
/// - `Ed25519` — used for the `Authorized` role (signs DID log entries).
/// - `EcdsaP256` — ECDSA over the NIST P-256 curve. Used for the
///   `Assertion` and `Authentication` roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyAlgorithm {
    Ed25519,
    EcdsaP256,
}

impl KeyAlgorithm {
    pub fn for_role(role: KeyRole) -> Self {
        match role {
            KeyRole::Authorized => KeyAlgorithm::Ed25519,
            KeyRole::Assertion | KeyRole::Authentication => KeyAlgorithm::EcdsaP256,
        }
    }
}

/// Opaque identifier for a key pair stored inside a `SigningEngine`.
///
/// Backed by UUID v4, not the project-wide bs58/prefix scheme used by
/// `IssuerId` and friends. `KeyPairId` is never embedded in a URL or
/// QR code, so the density constraints that motivated bs58 do not
/// apply here. Serialises as the standard hyphenated UUID string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct KeyPairId(Uuid);

impl KeyPairId {
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl std::fmt::Display for KeyPairId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

/// Raw public-key material returned by a `SigningEngine`.
///
/// Distinct from `swiyu_core::diddoc::public_keys::PublicKey`, which is
/// the JWK-/multibase-encoded form embedded in DID documents. Conversion
/// between the two happens at the DIDLog construction layer, not inside
/// the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawPublicKey {
    pub algorithm: KeyAlgorithm,
    pub bytes: Vec<u8>,
}

/// Result of `SigningEngine::generate_keypair`.
///
/// The private-key counterpart never appears in this type — it stays
/// inside the engine. Callers use `id` to reference the key for
/// subsequent `sign` and `delete_keypair` calls, and embed `public_key`
/// in the issuer's DID log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedKeyPair {
    pub id: KeyPairId,
    pub public_key: RawPublicKey,
}

/// Signature with its algorithm tag, in the encoding swiyu-issuer expects:
/// 64 raw bytes for Ed25519, raw `r || s` (64 bytes) for ECDSA P-256.
/// The engine normalises to this form regardless of what the backend produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub algorithm: KeyAlgorithm,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum SigningEngineError {
    #[error("key pair not found: {0}")]
    KeyNotFound(KeyPairId),

    #[error("unsupported role/algorithm combination")]
    UnsupportedAlgorithm,

    #[error("invalid input length: expected {expected} bytes, got {actual}")]
    InvalidInputLength { expected: usize, actual: usize },

    #[error("backend error: {0}")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// Performs all private-key operations for swiyu-issuer.
///
/// The fundamental rule: a private key never leaves the engine. All
/// signing happens inside the engine's process space; callers receive
/// only public keys, signatures, and opaque identifiers. Backends
/// range across maturity levels — `DevSigningEngine` (database-backed,
/// development), a possible `VaultSigningEngine`, and `HsmSigningEngine`
/// (PKCS#11, required in production). See `aspect-key-management.md`
/// and `impl-key-management.md`.
pub trait SigningEngine: Send + Sync {
    /// Generates a new key pair for the given role.
    ///
    /// The role pins the algorithm via `KeyAlgorithm::for_role`. The
    /// engine persists the private key internally and returns the public
    /// key together with an opaque `KeyPairId` for subsequent calls.
    fn generate_keypair(
        &self,
        role: KeyRole,
    ) -> impl Future<Output = Result<GeneratedKeyPair, SigningEngineError>> + Send;

    /// Returns the public key for `id`.
    ///
    /// Used by callers that hold a `KeyPairId` (typically read from
    /// persistence after a worker crash) and need to embed the public
    /// key in a DID document or verify a signature locally. Returns
    /// `KeyNotFound` if `id` is unknown to the engine.
    fn get_public_key(
        &self,
        id: &KeyPairId,
    ) -> impl Future<Output = Result<RawPublicKey, SigningEngineError>> + Send;

    /// Signs `input` with the private key identified by `id`.
    ///
    /// The interpretation of `input` depends on the key's algorithm:
    ///
    /// - **Ed25519** — `input` is the message. Any length is valid; the
    ///   engine feeds the bytes directly into plain Ed25519 (not
    ///   Ed25519ph). The `eddsa-jcs-2022` cryptosuite, for example,
    ///   passes a 64-byte concatenation of two SHA-256 hashes here.
    /// - **ECDSA P-256** — `input` is a pre-computed digest. It must be
    ///   exactly 32 bytes; otherwise `InvalidInputLength` is returned.
    ///
    /// Returns `KeyNotFound` if `id` is unknown to the engine.
    fn sign(
        &self,
        id: &KeyPairId,
        input: &[u8],
    ) -> impl Future<Output = Result<Signature, SigningEngineError>> + Send;

    /// Deletes the key pair identified by `id`.
    ///
    /// Idempotent: deleting an id that does not exist returns `Ok(())`.
    /// The trait postcondition is "the key is gone", which is met either
    /// way. `KeyNotFound` is therefore reserved for `sign`.
    fn delete_keypair(
        &self,
        id: &KeyPairId,
    ) -> impl Future<Output = Result<(), SigningEngineError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_for_authorized_role_is_ed25519() {
        assert_eq!(
            KeyAlgorithm::for_role(KeyRole::Authorized),
            KeyAlgorithm::Ed25519
        );
    }

    #[test]
    fn algorithm_for_assertion_and_authentication_roles_is_ecdsa_p256() {
        assert_eq!(
            KeyAlgorithm::for_role(KeyRole::Assertion),
            KeyAlgorithm::EcdsaP256
        );
        assert_eq!(
            KeyAlgorithm::for_role(KeyRole::Authentication),
            KeyAlgorithm::EcdsaP256
        );
    }

    #[test]
    fn generated_ids_are_distinct() {
        let a = KeyPairId::generate();
        let b = KeyPairId::generate();
        assert_ne!(a, b);
    }

    #[test]
    fn key_pair_id_display_uses_hyphenated_uuid() {
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let id = KeyPairId::from_uuid(uuid);
        assert_eq!(id.to_string(), "550e8400-e29b-41d4-a716-446655440000");
    }
}
