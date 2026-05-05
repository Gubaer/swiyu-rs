# Implementation: Key Management

This document describes how the key-management aspect (see `aspect-key-management.md`) is realised inside the `swiyu-issuer` crate. It is incremental — sections will be added as we work through the design.

## SigningEngine

The SigningEngine is the runtime component that performs all private-key operations. swiyu-issuer reaches it through a Rust trait so that different backends (database-backed for development, HSM-backed for production, possibly HashiCorp Vault) can be swapped without changing call sites.

The fundamental rule from the aspect spec applies: a private key never leaves the SigningEngine. Calls into the trait return public keys, signatures, and opaque identifiers — never private-key material.

### Module location

Trait, supporting types, and backend implementations live together under one module in the domain layer of the `swiyu-issuer` crate:

```
swiyu-issuer/src/domain/signing_engine/
    mod.rs       — trait, KeyRole, KeyPairId, errors, re-exports
    any.rs       — AnySigningEngine (runtime dispatch enum)
    dev.rs       — DevSigningEngine
    vault.rs     — VaultSigningEngine
    hsm.rs       — HsmSigningEngine
```

Backend selection is made at startup based on the `SIGNING_ENGINE` environment variable (`dev` or `vault`; `hsm` lands when that backend ships) and exposed to the rest of the binary as `AnySigningEngine`. See *Dispatch* below.

### Supporting types

```rust
/// The role a key pair plays for an issuer.
/// See `aspect-key-management.md` for the meaning of each role.
pub enum KeyRole {
    Authorized,
    Authentication,
    Assertion,
}

/// Algorithm a key pair uses. Determined by the role at generation time:
/// `Authorized` → `Ed25519`, the other two roles → `EcdsaP256`.
pub enum KeyAlgorithm {
    Ed25519,
    EcdsaP256,
}

/// Opaque identifier for a key pair stored inside a SigningEngine.
/// Backed by a randomly generated UUID v4. The same value is used as
/// the persistent key across all backends (DB primary key, PKCS#11
/// `CKA_ID`, Vault key name) — no per-backend translation needed.
pub struct KeyPairId(uuid::Uuid);

/// Raw public-key material returned by a `SigningEngine`. Distinct from
/// `swiyu_core::diddoc::public_keys::PublicKey`, which is the JWK-/multibase-
/// encoded form embedded in DID documents. Conversion between the two happens
/// at the DIDLog construction layer, not inside the engine.
pub struct RawPublicKey {
    pub algorithm: KeyAlgorithm,
    pub bytes: Vec<u8>,
}

/// Result of `generate_keypair`.
pub struct GeneratedKeyPair {
    pub id: KeyPairId,
    pub public_key: RawPublicKey,
}

/// Signature returned by `sign`. Encoding matches the algorithm:
/// - `Ed25519` → standard 64-byte signature
/// - `EcdsaP256` → raw `r || s`, 64 bytes (engine normalises if the backend
///   produces a different encoding)
pub struct Signature {
    pub algorithm: KeyAlgorithm,
    pub bytes: Vec<u8>,
}
```

`KeyPairId` lives in `domain/signing_engine/mod.rs`, **not** in `domain/ids.rs`. The latter file's id scheme (10-byte CSPRNG → bs58 → prefix) is justified by QR-code density on wallet-facing URLs; that constraint does not apply to key-pair identifiers, so the simpler and more standard UUID is used here.

Crate additions for the supporting types: `uuid = { version = "1", features = ["v4", "serde"] }`. The existing `sqlx` dependency line gains the `uuid` feature so the `Uuid` ↔ Postgres `uuid` mapping works out of the box.

### Trait

```rust
pub trait SigningEngine: Send + Sync {
    async fn generate_keypair(
        &self,
        role: KeyRole,
    ) -> Result<GeneratedKeyPair, SigningEngineError>;

    async fn get_public_key(
        &self,
        id: &KeyPairId,
    ) -> Result<RawPublicKey, SigningEngineError>;

    async fn sign(
        &self,
        id: &KeyPairId,
        input: &[u8],
    ) -> Result<Signature, SigningEngineError>;

    async fn delete_keypair(
        &self,
        id: &KeyPairId,
    ) -> Result<(), SigningEngineError>;
}
```

Notes on the trait shape:

- **Async.** Vault is reached over HTTP and the dev engine touches a database, so trait methods are `async`. PKCS#11 calls are synchronous; the HSM-backed implementation will wrap them with `tokio::task::spawn_blocking`. The crate is on Rust 2024 edition, so `async fn` in trait works natively without the `async-trait` macro.
- **`&self` (not `&mut self`).** Backends manage their own internal synchronisation (HSM session pools, Vault HTTP client, DB pool). The trait stays cheaply shareable.
- **`Send + Sync`.** swiyu-issuer holds the SigningEngine inside an `Arc` and shares it across request handlers.
- **Variable-length input.** `input: &[u8]` keeps the trait honest about the per-algorithm contract spelled out in `aspect-key-management.md`: ECDSA P-256 expects exactly 32 bytes (a SHA-256 digest); Ed25519 accepts any length and treats the bytes as the message. The earlier `&[u8; 32]` shape was wrong for `eddsa-jcs-2022`, which signs a 64-byte concatenation of two SHA-256 hashes; pre-hashing to fit a 32-byte slot would change the cryptosuite and break verifiers. ECDSA length mismatches surface as `InvalidInputLength`.
- **`delete_keypair` is idempotent.** Deleting an id that does not exist returns `Ok(())`. The trait postcondition is "the key is gone", which is met either way. `KeyNotFound` is therefore reserved for `sign` and never returned from `delete_keypair`.
- **Public-key byte shape is single per algorithm** so DIDLog construction (and any cross-engine equivalence test) can rely on a stable representation regardless of backend:
  - **Ed25519** — raw 32-byte point (the `ed25519-dalek` `to_bytes()` form).
  - **ECDSA P-256** — SEC1 uncompressed (`0x04 ‖ x ‖ y`, 65 bytes), the form `p256::EncodedPoint::to_encoded_point(false).as_bytes()` produces.

  Backends normalise to this shape internally — `VaultSigningEngine` decodes Vault's PEM-encoded SubjectPublicKeyInfo; `DevSigningEngine` produces it natively.

### Errors

```rust
#[derive(Debug, thiserror::Error)]
pub enum SigningEngineError {
    #[error("key pair not found: {0:?}")]
    KeyNotFound(KeyPairId),

    #[error("unsupported role/algorithm combination")]
    UnsupportedAlgorithm,

    #[error("invalid input length: expected {expected} bytes, got {actual}")]
    InvalidInputLength { expected: usize, actual: usize },

    #[error("backend error: {0}")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync>),
}
```

The variant set is intentionally minimal for the first cut. As concrete backends surface specific failure modes, we will add typed variants rather than letting everything fall through `Backend`.

### Dispatch

Backend selection happens once at startup. The set of backends is closed (dev / vault / future hsm) and never changes mid-process, so swiyu-issuer wraps the chosen backend in a single enum:

```rust
pub enum AnySigningEngine {
    Dev(DevSigningEngine),
    Vault(VaultSigningEngine),
}
```

`AnySigningEngine` itself impls `SigningEngine` and dispatches each method via `match`. The `Hsm(HsmSigningEngine)` variant slots in later under the same enum.

`Box<dyn SigningEngine>` is not an option: the trait's methods return `impl Future<Output = …> + Send` (RPITIT), which makes it not dyn-compatible. Restoring dyn-compatibility would require pulling in `async-trait` (and the heap allocation per call it forces). Enum dispatch avoids that dependency, gives exhaustiveness checks when a backend is added, and reads more directly than a macro-generated trait object.

## Backend implementations

Three SigningEngine flavours, one per maturity level from the aspect spec. They share the trait above; each lives in its own sibling file.

### `DevSigningEngine` — Low maturity (development)

**Status.** Ships in the initial version. Used in development and integration tests.

**Storage.** A dedicated Postgres table accessed through the existing `sqlx` pool. Private keys are stored unencrypted — this is the defining property of the Low maturity level.

```sql
CREATE TABLE signing_engine_dev_keypairs (
    id UUID PRIMARY KEY,
    algorithm TEXT NOT NULL,        -- 'ed25519' or 'ecdsa-p256'
    private_key BYTEA NOT NULL,
    public_key BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

The migration file follows the existing `YYYYMMDD_NNNNNN_<name>.sql` pattern (next free sequence number).

**No `role` column.** Role is consumed at generation time (it picks the algorithm) and is never used during signing. Storing it would be cargo-cult.

**No `tenant_id` / `issuer_id` columns.** Per the aspect spec, the `(issuer, role) → current_id` mapping lives one layer up, in swiyu-issuer's domain state. The engine stores keys by id only and is ignorant of issuer ownership.

**Crypto crates.** Ed25519 via `ed25519-dalek` (already a dep). ECDSA P-256 via the `p256` crate (new dep).

**Signing.**
- ECDSA: input is treated as the digest, no further hashing. Output is raw `r || s` from `p256::ecdsa::Signature::to_bytes()`.
- Ed25519: input is the message, signed with plain Ed25519 (`ed25519_dalek::SigningKey::sign`). Output is the standard 64-byte signature.

**Deletion.** Removes the row by primary key; idempotent per the trait contract.

### `VaultSigningEngine` — Middle maturity

**Status.** Shipped. Selected at startup with `SIGNING_ENGINE=vault`; configured via `VAULT_ADDR`, `VAULT_TOKEN`, optional `VAULT_TRANSIT_PATH` (default `transit`), and optional `VAULT_REQUEST_TIMEOUT_SECS` (default 5). Used for staging and small-scale production where a dedicated HSM is not yet available.

**Backend.** HashiCorp Vault, Transit Secrets Engine. Both `ed25519` and `ecdsa-p256` are first-class native key types — no extra wrapping or external crypto needed.

**Identifier mapping.** The UUID v4 string (e.g. `550e8400-e29b-41d4-a716-446655440000`) is used directly as the Vault key name. UUIDs are valid Vault key names. No mapping table.

**API operations.**
- Generate: `POST /v1/{transit_path}/keys/{uuid}` with `type=ed25519` or `type=ecdsa-p256`, then `GET /v1/{transit_path}/keys/{uuid}` to read the public key.
- Sign (ECDSA): `POST /v1/{transit_path}/sign/{uuid}` with `prehashed=true`, `hash_algorithm=sha2-256`, `marshaling_algorithm=jws`. This combination forces "treat input as digest, return raw `r || s`".
- Sign (Ed25519): `POST /v1/{transit_path}/sign/{uuid}` with default parameters; Vault signs the input as a message with plain Ed25519.
- Delete: `POST /v1/{transit_path}/keys/{uuid}/config` with `deletion_allowed=true`, then `DELETE /v1/{transit_path}/keys/{uuid}`. Both calls are issued unconditionally on every `delete_keypair` so the engine works for keys it just created (Vault marks new keys as non-deletable by default).

**Vault's built-in key versioning is not used.** Each `generate_keypair` creates a fresh Vault key. Every Vault key in our usage stays at version 1. Rotation creates new keys with new UUIDs; old keys remain (or are deleted). This keeps the structural model identical to the HSM backend, and lets the engine read `data.keys["1"].public_key` directly without chasing `latest_version`.

**Algorithm cache.** `sign` needs to know each key's algorithm to craft the correct request body shape. The engine keeps an in-memory `RwLock<HashMap<KeyPairId, KeyAlgorithm>>` populated as a side effect of every successful key read (`generate_keypair` and `get_public_key` both write to it). On a cache miss `sign` falls through to a `GET` and populates the cache before signing. `delete_keypair` evicts.

**Signature envelope decoding.** Vault returns signatures as `data.signature` strings prefixed `vault:v1:`; the body encoding differs by algorithm and is non-obvious:

| Algorithm | Body encoding | Decoded length |
|---|---|---|
| Ed25519 (default) | standard base64 (`+`, `/`, `=` padding) | 64 raw bytes |
| ECDSA P-256 (`marshaling_algorithm=jws`) | base64url-no-padding (`-`, `_`, no `=`) | 64 raw bytes (`r ‖ s`) |

The `r ‖ s` ordering is implicit in the JWS marshalling — the layout matches what the rest of swiyu-issuer expects from `DevSigningEngine`, so no further normalisation is needed.

**"Key missing" mapping.** Vault is inconsistent about how it reports a missing key, so the engine discriminates per-operation:

- `GET /v1/{transit_path}/keys/{id}` returns a clean **404** → `KeyNotFound`.
- `POST /v1/{transit_path}/sign/{id}` returns **400** with body containing `signing key not found` → `KeyNotFound`. Other 400s → `Backend`.
- `POST /v1/{transit_path}/keys/{id}/config` returns **400** with body containing `no existing key named` → swallow (`delete_keypair` proceeds; the trait's idempotency contract is met by either of the two delete-path calls succeeding).
- `DELETE /v1/{transit_path}/keys/{id}` returns **400** with body containing `could not delete key; not found` → swallow.

The body-substring match is fragile by nature; the integration tests (`#[ignore]` by default, run against the dev container) guard against silent wording changes.

**Authentication.** The engine carries a Vault client configured with a token (typically obtained via AppRole or a Kubernetes service-account auth method). Token lifecycle, renewal, and Vault policy are internal concerns of the engine and do not surface in the trait.

**Network failures.** Vault is reached over the network. v1 behaviour: a single attempt per operation with the configured `request_timeout` (default 5 seconds), no retry, no backoff. Transport errors, JSON parse failures, and 5xx responses all map to `SigningEngineError::Backend`. A retry/backoff layer can be added later as an interceptor at the `reqwest::Client` layer or a wrapper inside the engine without changing the trait surface.

### `HsmSigningEngine` — High maturity (production)

**Status.** Required for production deployment. The aspect spec mandates that the deployed engine be HSM-backed.

**Backend.** PKCS#11 (Cryptoki) — the most widely supported HSM API. Works for Thales Luna, Utimaco SecurityServer, AWS CloudHSM, YubiHSM, Azure Managed HSM (via PKCS#11), and SoftHSM (for testing).

**Required mechanisms.** The HSM **must** support both:
- `CKM_EDDSA` (plain mode, `phFlag=false`, no context) — for the `Authorized` role.
- `CKM_ECDSA` with curve `secp256r1` (P-256) — for the `Assertion` and `Authentication` roles.

These are non-negotiable; they are dictated by SWIYU.

**Identifier mapping.** The UUID v4 is set as `CKA_ID` in the key template at creation time:

```
C_GenerateKeyPair(session, mechanism, template = [
    (CKA_ID,      uuid_bytes),    // application-chosen persistent id
    (CKA_TOKEN,   true),          // persistent, not session-scoped
    (CKA_PRIVATE, true),
    ... mechanism-specific params ...
]);
```

For `sign` and `delete_keypair`, the engine looks up the current session handle via `C_FindObjects` filtered by `CKA_ID`. Session handles (`CK_OBJECT_HANDLE`) are ephemeral; only `CKA_ID` is persistent. **No mapping table is needed:** the UUID *is* the persistent key in the HSM.

**Async wrapping.** PKCS#11 is a synchronous C API. The engine wraps each PKCS#11 call (or each high-level operation) in `tokio::task::spawn_blocking` so the trait's `async fn` contract is honoured without blocking the runtime.

**Signature normalisation.** PKCS#11 returns ECDSA as raw `r || s` (each integer padded to the curve's field size) — already our target format. Ed25519 is returned as the standard 64-byte signature — also our target. If a particular HSM driver deviates (e.g. produces DER), the engine normalises before returning.

**Login / session management.** PKCS#11 requires `C_Login` before private-key operations. Slot/PIN configuration, session pooling, and re-login on session loss are internal concerns of the engine and do not surface in the trait.

**Rust client side.** The Rust binding to PKCS#11 is the [`cryptoki`](https://crates.io/crates/cryptoki) crate (maintained under the Parsec project). It loads any PKCS#11 module at runtime, so switching between SoftHSM (in tests) and a real production HSM is a configuration change, not a code change. Recent versions support `CKM_EDDSA` and `CKM_ECDSA` over `secp256r1`.

**Testing with SoftHSMv2.** Implementation and integration tests run against [SoftHSMv2](https://github.com/opendnssec/SoftHSMv2), the standard open-source PKCS#11 software implementation:

- Available as a package on common platforms (`apt install softhsm2`, `brew install softhsm`, etc.). Build from source if the packaged version is older than 2.6.0 — Ed25519 support (`CKM_EDDSA`) was added in 2.6.0.
- Loaded as a PKCS#11 module (`libsofthsm2.so` or platform equivalent) by `cryptoki`. From the engine's point of view it is just another PKCS#11 driver.
- Test fixtures initialise an isolated token at a temp directory, set the user PIN, and point `cryptoki` at the module path. CI runners need `softhsm2` installed.

**SoftHSM is not a security boundary.** It is a *functional* PKCS#11 implementation: token files on disk store the keys and crypto runs in software. Anyone with filesystem access to the token store can extract private keys. This is by design — SoftHSM substitutes for an HSM at the API surface only, not at the security boundary. Implementation and integration tests use it freely; production deployments must use a real HSM.

**Behavioural differences from real HSMs.** SoftHSM is faithful to the PKCS#11 spec but does not reproduce vendor-specific edge cases, error codes, performance characteristics, or session/object-handle limits. Smoke-test `HsmSigningEngine` against the production HSM before release.

## Open implementation questions

1. **`RawPublicKey` representation.**
   The current sketch (`KeyAlgorithm` + `Vec<u8>`) is the simplest. The DIDLog code may want a typed enum (`Ed25519PublicKey` / `EcdsaP256PublicKey`) or a JWK-/multibase-friendly form. To be decided when we wire DIDLog construction to this trait.
