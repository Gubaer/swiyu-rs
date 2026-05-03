//! Development-tier `SigningEngine` backed by a Postgres table that
//! stores private keys unencrypted. See
//! `specs/impl-key-management.md` (DevSigningEngine subsection).

use std::future::Future;

use ed25519_dalek::Signer as Ed25519Signer;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use p256::ecdsa::Signature as EcdsaSignature;
use p256::ecdsa::SigningKey as EcdsaSigningKey;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use rand_core::OsRng;
use sqlx::PgPool;

use super::{
    GeneratedKeyPair, KeyAlgorithm, KeyPairId, KeyRole, RawPublicKey, Signature, SigningEngine,
    SigningEngineError,
};

const ALGORITHM_ED25519: &str = "ed25519";
const ALGORITHM_ECDSA_P256: &str = "ecdsa-p256";

/// Low-maturity `SigningEngine` for development and integration tests.
///
/// Persists private keys unencrypted in `signing_engine_dev_keypairs`.
/// Not suitable for production — production uses `HsmSigningEngine`.
pub struct DevSigningEngine {
    pool: PgPool,
}

impl DevSigningEngine {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl SigningEngine for DevSigningEngine {
    fn generate_keypair(
        &self,
        role: KeyRole,
    ) -> impl Future<Output = Result<GeneratedKeyPair, SigningEngineError>> + Send {
        let pool = self.pool.clone();
        async move {
            let algorithm = KeyAlgorithm::for_role(role);
            let (private_bytes, public_bytes) = match algorithm {
                KeyAlgorithm::Ed25519 => generate_ed25519(),
                KeyAlgorithm::EcdsaP256 => generate_ecdsa_p256(),
            };
            let id = KeyPairId::generate();

            sqlx::query(
                "INSERT INTO signing_engine_dev_keypairs \
                 (id, algorithm, private_key, public_key) \
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(id.as_uuid())
            .bind(algorithm_label(algorithm))
            .bind(&private_bytes)
            .bind(&public_bytes)
            .execute(&pool)
            .await
            .map_err(backend_error)?;

            Ok(GeneratedKeyPair {
                id,
                public_key: RawPublicKey {
                    algorithm,
                    bytes: public_bytes,
                },
            })
        }
    }

    fn sign(
        &self,
        id: &KeyPairId,
        input: &[u8; 32],
    ) -> impl Future<Output = Result<Signature, SigningEngineError>> + Send {
        let pool = self.pool.clone();
        let id = *id;
        let input = *input;
        async move {
            let row: Option<(String, Vec<u8>)> = sqlx::query_as(
                "SELECT algorithm, private_key \
                 FROM signing_engine_dev_keypairs \
                 WHERE id = $1",
            )
            .bind(id.as_uuid())
            .fetch_optional(&pool)
            .await
            .map_err(backend_error)?;

            let (algorithm_str, private_bytes) = row.ok_or(SigningEngineError::KeyNotFound(id))?;
            let algorithm = parse_algorithm_label(&algorithm_str)?;

            let signature_bytes = match algorithm {
                KeyAlgorithm::Ed25519 => sign_ed25519(&private_bytes, &input)?,
                KeyAlgorithm::EcdsaP256 => sign_ecdsa_p256(&private_bytes, &input)?,
            };

            Ok(Signature {
                algorithm,
                bytes: signature_bytes,
            })
        }
    }

    fn delete_keypair(
        &self,
        id: &KeyPairId,
    ) -> impl Future<Output = Result<(), SigningEngineError>> + Send {
        let pool = self.pool.clone();
        let id = *id;
        async move {
            sqlx::query("DELETE FROM signing_engine_dev_keypairs WHERE id = $1")
                .bind(id.as_uuid())
                .execute(&pool)
                .await
                .map_err(backend_error)?;
            Ok(())
        }
    }
}

fn algorithm_label(algorithm: KeyAlgorithm) -> &'static str {
    match algorithm {
        KeyAlgorithm::Ed25519 => ALGORITHM_ED25519,
        KeyAlgorithm::EcdsaP256 => ALGORITHM_ECDSA_P256,
    }
}

fn parse_algorithm_label(label: &str) -> Result<KeyAlgorithm, SigningEngineError> {
    match label {
        ALGORITHM_ED25519 => Ok(KeyAlgorithm::Ed25519),
        ALGORITHM_ECDSA_P256 => Ok(KeyAlgorithm::EcdsaP256),
        other => Err(SigningEngineError::Backend(
            format!("unknown algorithm label in DB: {other}").into(),
        )),
    }
}

fn generate_ed25519() -> (Vec<u8>, Vec<u8>) {
    let signing_key = Ed25519SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (
        signing_key.to_bytes().to_vec(),
        verifying_key.to_bytes().to_vec(),
    )
}

// SEC1 uncompressed encoding (0x04 || x || y, 65 bytes total).
fn generate_ecdsa_p256() -> (Vec<u8>, Vec<u8>) {
    let signing_key = EcdsaSigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let public_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();
    (signing_key.to_bytes().to_vec(), public_bytes)
}

fn sign_ed25519(private_bytes: &[u8], input: &[u8; 32]) -> Result<Vec<u8>, SigningEngineError> {
    let bytes: &[u8; 32] = private_bytes.try_into().map_err(|_| {
        SigningEngineError::Backend(
            format!(
                "ed25519 private key has unexpected length: {}",
                private_bytes.len()
            )
            .into(),
        )
    })?;
    let signing_key = Ed25519SigningKey::from_bytes(bytes);
    let signature = signing_key.sign(input);
    Ok(signature.to_bytes().to_vec())
}

fn sign_ecdsa_p256(private_bytes: &[u8], input: &[u8; 32]) -> Result<Vec<u8>, SigningEngineError> {
    let signing_key = EcdsaSigningKey::from_slice(private_bytes)
        .map_err(|e| SigningEngineError::Backend(e.to_string().into()))?;
    let signature: EcdsaSignature = signing_key
        .sign_prehash(input)
        .map_err(|e| SigningEngineError::Backend(e.to_string().into()))?;
    Ok(signature.to_bytes().to_vec())
}

fn backend_error(e: sqlx::Error) -> SigningEngineError {
    SigningEngineError::Backend(Box::new(e))
}

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::Verifier;
    use ed25519_dalek::VerifyingKey as Ed25519VerifyingKey;
    use p256::ecdsa::VerifyingKey as EcdsaVerifyingKey;
    use p256::ecdsa::signature::hazmat::PrehashVerifier;

    #[test]
    fn ed25519_sign_verify_roundtrip() {
        let (private_bytes, public_bytes) = generate_ed25519();
        let input = [0xa5_u8; 32];

        let signature_bytes = sign_ed25519(&private_bytes, &input).unwrap();
        assert_eq!(signature_bytes.len(), 64);

        let public_array: [u8; 32] = public_bytes.as_slice().try_into().unwrap();
        let verifying_key = Ed25519VerifyingKey::from_bytes(&public_array).unwrap();
        let signature_array: [u8; 64] = signature_bytes.as_slice().try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&signature_array);
        verifying_key.verify(&input, &signature).unwrap();
    }

    #[test]
    fn ecdsa_p256_sign_verify_roundtrip() {
        let (private_bytes, public_bytes) = generate_ecdsa_p256();
        let input = [0x5a_u8; 32];

        let signature_bytes = sign_ecdsa_p256(&private_bytes, &input).unwrap();
        assert_eq!(signature_bytes.len(), 64);

        let verifying_key = EcdsaVerifyingKey::from_sec1_bytes(&public_bytes).unwrap();
        let signature = EcdsaSignature::from_slice(&signature_bytes).unwrap();
        verifying_key.verify_prehash(&input, &signature).unwrap();
    }

    #[test]
    fn algorithm_label_round_trips() {
        assert_eq!(
            parse_algorithm_label(algorithm_label(KeyAlgorithm::Ed25519)).unwrap(),
            KeyAlgorithm::Ed25519
        );
        assert_eq!(
            parse_algorithm_label(algorithm_label(KeyAlgorithm::EcdsaP256)).unwrap(),
            KeyAlgorithm::EcdsaP256
        );
    }

    #[test]
    fn parse_algorithm_label_rejects_unknown() {
        assert!(parse_algorithm_label("rsa-2048").is_err());
    }
}
