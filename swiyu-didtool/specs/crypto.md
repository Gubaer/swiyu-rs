didtool must be able to create, read, and write the following key pairs
1. key pairs for ECDSA
2. key pairs for EdDSA 

# Requirements

## Key generation
* add a function to generate an ECDSA key pair
* add a function to generate an EdDSA key pair

## Key serialisation
Keys are stored on disk in PEM format:
* private keys in PKCS#8 PEM format
* public keys in SubjectPublicKeyInfo (SPKI) PEM format

Private and public keys are stored in separate files, because they serve
different purposes and have different sensitivity.

## API

```rust
pub enum CryptoError {
    Io(std::io::Error),
    InvalidKey(String),
}

pub type CryptoResult<T> = Result<T, CryptoError>;

pub fn generate_ecdsa_key_pair() -> (EcdsaSigningKey, EcdsaVerifyingKey)
pub fn generate_eddsa_key_pair() -> (Ed25519SigningKey, Ed25519VerifyingKey)

pub fn write_private_key_ecdsa(key: &EcdsaSigningKey, path: &Path) -> CryptoResult<()>
pub fn read_private_key_ecdsa(path: &Path) -> CryptoResult<EcdsaSigningKey>

pub fn write_public_key_ecdsa(key: &EcdsaVerifyingKey, path: &Path) -> CryptoResult<()>
pub fn read_public_key_ecdsa(path: &Path) -> CryptoResult<EcdsaVerifyingKey>

pub fn write_private_key_eddsa(key: &Ed25519SigningKey, path: &Path) -> CryptoResult<()>
pub fn read_private_key_eddsa(path: &Path) -> CryptoResult<Ed25519SigningKey>

pub fn write_public_key_eddsa(key: &Ed25519VerifyingKey, path: &Path) -> CryptoResult<()>
pub fn read_public_key_eddsa(path: &Path) -> CryptoResult<Ed25519VerifyingKey>
```

The algorithm appears in the function name because the return types differ —
there is no single key type that covers both ECDSA and EdDSA.
