# Implementation: key management

This document captures the concrete shape of `swiyu-issuer`'s key-handling code: the trait surface, the keystore schema, and the per-backend mappings. For the architectural decisions and reasoning see [`aspect-key-management.md`](aspect-key-management.md).

Status: preliminary. The trait shape and DB-backed schema are stable enough to start implementation; HSM and cloud-KMS impls are sketched but unwritten.

## Scope

Covers:

- The `Signer` and `KeyManager` traits and their supporting types.
- The `swiyu_issuer_keystore` schema tables.
- How each backend (DB-backed, PKCS#11, cloud KMS) maps the trait operations onto its native vocabulary.
- Implementation wrinkles that don't surface in the trait but matter for correctness.

Does *not* cover:

- The `KekProvider` trait that the DB-backed impl depends on (separate concern).
- DID log entry construction (lives in the management API layer).
- Status-list signing (separate slice).

## Module layout

`swiyu-issuer/src/signer/`:

- `mod.rs` — trait definitions and re-exports.
- `types.rs` — `KeyRole`, `Generation`, `Algorithm`, `PublicKey`, `Signature`, `KeyTriplePublic`.
- `error.rs` — `SignerError` enum.
- `db.rs` — DB-backed `Signer` + `KeyManager` impl.
- `hsm.rs` — PKCS#11-backed `Signer` + `KeyManager` impl. Stub at v0.1.x; lit up for production.
- `kms.rs` — cloud-KMS-backed impl. Stub; lit up if cloud is selected.

`swiyu-issuer/src/persistence/keystore/`:

- `mod.rs` — module declarations and re-exports.
- `signing_key_generations.rs` — read/write functions for the keystore table. Free functions, taking `&mut PgConnection`, scoped by `(tenant, issuer)` in every signature.

## Public surface

```rust
// types.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRole {
    Authorized,
    Authentication,
    Assertion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Generation(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Ed25519,
    Es256,
}

#[derive(Debug, Clone)]
pub struct PublicKey {
    pub algorithm: Algorithm,
    pub raw: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Signature {
    pub algorithm: Algorithm,
    pub raw: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct KeyTriplePublic {
    pub authorized: PublicKey,
    pub authentication: PublicKey,
    pub assertion: PublicKey,
}

// error.rs
#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    #[error("no key for issuer {issuer:?} role {role:?} generation {generation:?}")]
    KeyNotFound {
        issuer: IssuerId,
        role: KeyRole,
        generation: Generation,
    },
    #[error("generation {generation:?} for issuer {issuer:?} already exists")]
    GenerationAlreadyExists {
        issuer: IssuerId,
        generation: Generation,
    },
    #[error("key encryption key for tenant {0:?} unavailable")]
    KekUnavailable(TenantId),
    #[error("backend not healthy")]
    Unhealthy,
    #[error("backend error: {0}")]
    Backend(Box<dyn std::error::Error + Send + Sync>),
}

// mod.rs
#[async_trait::async_trait]
pub trait Signer: Send + Sync {
    async fn sign(
        &self,
        tenant: &TenantId,
        issuer: &IssuerId,
        role: KeyRole,
        generation: Generation,
        payload: &[u8],
    ) -> Result<Signature, SignerError>;

    async fn public_key(
        &self,
        tenant: &TenantId,
        issuer: &IssuerId,
        role: KeyRole,
        generation: Generation,
    ) -> Result<PublicKey, SignerError>;

    fn non_exportable_keys(&self) -> bool;

    async fn health_check(&self) -> Result<(), SignerError>;
}

#[async_trait::async_trait]
pub trait KeyManager: Signer {
    async fn generate_key_triple(
        &self,
        tenant: &TenantId,
        issuer: &IssuerId,
        generation: Generation,
    ) -> Result<KeyTriplePublic, SignerError>;
}
```

## Schema

`swiyu_issuer_keystore.signing_key_generations`:

| Column | Type | Notes |
|--------|------|-------|
| `tenant_id` | TEXT NOT NULL | Reference into `swiyu_issuer_mgmt.tenants`; logical-only when keystore is on a separate database. |
| `issuer_id` | TEXT NOT NULL | Reference into `swiyu_issuer_mgmt.issuers`; same caveat. |
| `generation` | INTEGER NOT NULL | 1-based. |
| `created_at` | TIMESTAMPTZ NOT NULL DEFAULT NOW() | |
| `retired_at` | TIMESTAMPTZ NULL | NULL while active. |
| `backend_kind` | TEXT NOT NULL | `'db'` \| `'pkcs11'` \| `'kms'`. |
| `authorized_public_pem` | TEXT NOT NULL | |
| `authentication_public_pem` | TEXT NOT NULL | |
| `assertion_public_pem` | TEXT NOT NULL | |
| `authorized_private_ciphertext` | BYTEA NULL | DB-backed only. |
| `authentication_private_ciphertext` | BYTEA NULL | DB-backed only. |
| `assertion_private_ciphertext` | BYTEA NULL | DB-backed only. |
| `aead_nonce` | BYTEA NULL | DB-backed only. 12-byte AES-GCM nonce, fresh per row. |
| `authorized_handle` | TEXT NULL | HSM/KMS only. PKCS#11 `CKA_ID` (hex), KMS key ID, etc. |
| `authentication_handle` | TEXT NULL | HSM/KMS only. |
| `assertion_handle` | TEXT NULL | HSM/KMS only. |

Primary key: `(tenant_id, issuer_id, generation)`.

CHECK constraint: ciphertext-and-handle exclusivity per row. `backend_kind = 'db'` requires the three `*_ciphertext` columns and `aead_nonce` to be non-NULL and the three `*_handle` columns to be NULL; `backend_kind IN ('pkcs11', 'kms')` reverses this.

Three roles per row keeps generation atomicity natural — a key triple's three public PEMs land in a single INSERT.

`retired_at` lets historical generations stay queryable for verifying past signatures; "active generation for this issuer" filters by `retired_at IS NULL`.

The PEM columns are populated in every backend (DB cache for HSM/KMS impls, primary store for the DB-backed impl). This avoids HSM round-trips for `public_key` calls at request time.

## Backend implementations

### DB-backed (`signer/db.rs`)

Implements `Signer` + `KeyManager` directly against `swiyu_issuer_keystore.signing_key_generations`.

`sign`:

1. `SELECT {role}_private_ciphertext, aead_nonce FROM signing_key_generations WHERE tenant_id=$1 AND issuer_id=$2 AND generation=$3`.
2. Fetch tenant KEK via `kek_provider.fetch(tenant_id)`.
3. AES-256-GCM decrypt the ciphertext with AAD `(tenant_id, issuer_id, key_role, generation)`.
4. Sign via `swiyu-didtool::crypto::{sign_eddsa, sign_es256}` depending on role.
5. Wrap in `Signature { algorithm, raw }`.

`public_key`:

1. `SELECT {role}_public_pem FROM signing_key_generations WHERE …`.
2. Parse PEM into algorithm-tagged `PublicKey`.

`generate_key_triple`:

1. `swiyu-didtool::crypto::generate_*` for each of the three roles.
2. AES-256-GCM encrypt each private key with the tenant KEK and the AAD tuple.
3. INSERT one row with the three ciphertexts, the fresh nonce, the three public PEMs, and `backend_kind = 'db'`.
4. Return `KeyTriplePublic` from the in-memory publics; the privates are dropped after encryption.

`non_exportable_keys()`: `false`.

`health_check()`: `SELECT 1` against the pool, plus a no-op KEK fetch for a sentinel tenant.

### PKCS#11 (`signer/hsm.rs`)

Implements the same traits against an HSM via PKCS#11. Construction takes the path to the vendor's `.so`, the slot ID, and a credential source for the user PIN (the orchestrator secret store). The impl maintains a pool of pre-authenticated sessions; each operation acquires one, runs its calls inside `tokio::task::spawn_blocking`, and returns it to the pool.

`sign`:

1. Read `{role}_handle` from the keystore row. The handle is the `CKA_ID` value, hex-encoded.
2. Acquire a session from the pool.
3. `C_FindObjectsInit(session, [{CKA_ID, decoded_id}, {CKA_CLASS, CKO_PRIVATE_KEY}])` → `C_FindObjects` → `C_FindObjectsFinal`.
4. `C_SignInit(session, mechanism, handle)` where `mechanism = CKM_EDDSA` (Authorized) or `CKM_ECDSA` (Authentication, Assertion). For ECDSA the impl hashes with SHA-256 first and feeds the digest.
5. `C_Sign(session, payload_or_digest, …)`.
6. Canonicalise the signature (raw `r || s` for ECDSA, raw 64 bytes for Ed25519) and wrap in `Signature`.

`public_key`: cached PEM in the keystore row, no HSM round-trip.

`generate_key_triple`:

1. Compute the deterministic `CKA_ID` for each role: `BLAKE3(tenant_id || issuer_id || role || generation)[..16]`.
2. For each role, `C_GenerateKeyPair` with the appropriate mechanism, public template (`CKA_EC_PARAMS` set to the curve OID, `CKA_VERIFY=true`, `CKA_TOKEN=true`, `CKA_LABEL`, `CKA_ID`), and private template (`CKA_PRIVATE=true`, `CKA_SENSITIVE=true`, `CKA_EXTRACTABLE=false`, `CKA_TOKEN=true`, `CKA_LABEL`, `CKA_ID`, `CKA_SIGN=true`).
3. `C_GetAttributeValue(public_handle, [CKA_EC_POINT])` to read the public-key bytes.
4. INSERT the keystore row with the three handles (hex-encoded `CKA_ID`s), the three cached PEMs, and `backend_kind = 'pkcs11'`.

The deterministic `CKA_ID` makes the generate-then-DB-insert pair idempotent under retry. If the DB write fails after HSM-side generation succeeded, retrying the operation finds the prior HSM object via `C_FindObjects([CKA_ID=…])` and reuses it instead of double-creating. Plays directly with the cross-database-portable rotation discipline.

`non_exportable_keys()`: `true`, asserted at construction time by checking that `CKA_EXTRACTABLE=false` is enforceable on the configured slot.

`health_check()`: open a session, log in, run a no-op `C_FindObjectsInit`/`C_FindObjectsFinal` for a sentinel tag.

### Cloud KMS (`signer/kms.rs`, sketch)

Same traits against AWS KMS, Azure Managed HSM, or GCP Cloud KMS. The keystore row's `*_handle` columns store the cloud key identifier (e.g., AWS KMS Key ID, GCP `CryptoKeyVersion` resource name, Azure key name).

| Trait method | AWS KMS | GCP KMS | Azure Managed HSM |
|--------------|---------|---------|-------------------|
| `sign` | `Sign { KeyId, Message, MessageType: DIGEST, SigningAlgorithm: ECDSA_SHA_256 \| ED25519 }` | `AsymmetricSign` | `Sign` |
| `public_key` | Cached PEM (preferred), or `GetPublicKey { KeyId }` | `GetPublicKey` | `GetKey` |
| `generate_key_triple` | `CreateKey { KeyUsage: SIGN_VERIFY, KeySpec: ECC_NIST_P256 \| ECC_ED25519 } × 3` | `CreateCryptoKey × 3` | `CreateKey × 3` |

`non_exportable_keys()`: `true` for all three providers' asymmetric keys (non-extractable by service contract).

## Implementation wrinkles

- **PKCS#11 session pooling.** Sessions are stateful and login is per-session. The HSM impl maintains a pool of N pre-authenticated sessions (typically 4–16, configurable). Acquire-borrow-return on each operation.
- **Hash-then-sign vs sign-with-digest.** PKCS#11 has both `CKM_ECDSA` (caller hashes) and `CKM_ECDSA_SHA256` (HSM hashes); cloud KMS has the equivalent `RAW` vs `DIGEST` split. Older HSM firmware sometimes only supports one. The impl picks one at construction time based on slot capabilities, defaulting to caller-side hashing via `swiyu-didtool::crypto::sha256`.
- **ECDSA signature canonicalisation.** PKCS#11 returns ECDSA signatures as fixed-length raw `r || s`; AWS KMS returns DER `SEQUENCE { r INTEGER, s INTEGER }`. The trait's `Signature.raw` carries the **fixed-length raw** form. Each impl normalises to it.
- **Ed25519 algorithm support drift.** Some older HSM firmware does not implement `CKM_EDDSA`. If procurement lands on such a vendor, the `Authorized` role can't be HSM-backed without a rotation to a different DID method. This is an HSM-selection criterion to surface during procurement; the trait doesn't help.
- **Multi-slot deployments.** If tenants are partitioned across slots, the impl resolves the slot via a `slot_label` column on the keystore row (or a per-tenant config map). Doesn't surface in the trait.
- **PIN/password sourcing.** The PKCS#11 PIN comes from the same orchestrator secret store as the per-tenant KEKs. Fetched once at construction, never logged.
- **Atomic generate-then-insert.** Always paired with the cross-database-portable rotation discipline: backend (HSM object or DB ciphertext) first, mgmt (DID log entry) second. Deterministic `CKA_ID` (PKCS#11) or deterministic key alias (cloud KMS) makes the backend-side step idempotent under retry.

## Open

- **`SignerError` granularity.** Current variants: `KeyNotFound`, `GenerationAlreadyExists`, `KekUnavailable`, `Unhealthy`, `Backend`. Expect a few more variants for specific recoverable conditions as impls are written.
- **`KekProvider` trait.** Shape and orchestrator backends to be specified in a separate spec; the DB-backed `Signer` impl depends on it.
- **Rotation orchestration.** The cross-DB-portable discipline (write keystore first, mgmt second, idempotent retry) lives above the trait — orchestrated by the management API. Where exactly it lives in the management layer is open.
- **Verification helpers.** Wallet-side and verifier-side signature verification doesn't need the trait; a `swiyu-didtool::crypto::verify_*` helper covers it. Coordination point only.
- **Schema constraint check shape.** The ciphertext-vs-handle exclusivity could be a single multi-column CHECK or three separate ones. Implementation choice when the migration lands.
