# Implementation: Secret Management

This document describes how the secret-management aspect (see `aspect-secret-management.md`) is realised inside the `swiyu-issuer` crate. It is incremental — sections will be added as we work through the design.

## SecretEncryptionEngine

The SecretEncryptionEngine is the runtime component that performs all symmetric encryption and decryption of small application secrets. swiyu-issuer reaches it through a Rust trait so that different backends (master-key-and-KDF for development, HashiCorp Vault for production) can be swapped without changing call sites.

The fundamental rule from the aspect spec applies: a symmetric key never leaves the engine. Calls into the trait take and return plaintext and self-describing ciphertext blobs — never key material.

### Module location

Trait, supporting types, and backend implementations live together under one module in the domain layer of the `swiyu-issuer` crate:

```
swiyu-issuer/src/domain/secret_encryption_engine/
    mod.rs       — trait, Ciphertext, errors, re-exports
    envelope.rs  — encode/decode of the self-describing ciphertext envelope
    any.rs       — AnySecretEncryptionEngine (runtime dispatch enum)
    dev.rs       — DevSecretEncryptionEngine
    vault.rs     — VaultSecretEncryptionEngine
```

Backend selection is made at startup based on the `SECRET_ENCRYPTION_ENGINE` environment variable (`dev` or `vault`; default `dev`) and exposed to the rest of the binary as `AnySecretEncryptionEngine`. See *Dispatch* below.

### Supporting types

```rust
/// Self-describing ciphertext blob, persisted as a single `BYTEA` column.
/// Carries (format_version, key_name, key_version, nonce_or_payload).
/// Construction goes through `encrypt`; reconstruction from the database
/// uses `Ciphertext::from_bytes`.
pub struct Ciphertext(Vec<u8>);

impl Ciphertext {
    pub fn as_bytes(&self) -> &[u8] { &self.0 }
    pub fn into_bytes(self) -> Vec<u8> { self.0 }
}

impl From<Vec<u8>> for Ciphertext { ... }   // accepts the raw column bytes
```

`Ciphertext` is intentionally not parsed at construction time. The format is validated when the engine attempts to decrypt; that keeps the persistence-layer round-trip cheap and makes "malformed envelope" a `decrypt`-time error in the same place as "tag verification failed".

`KeyName` and `KeyVersion` are not introduced as newtypes. `key_name` is `&str` everywhere in the trait surface; `key_version` is `u32` and lives only inside the envelope. Newtypes would buy little — there is no risk of confusing them with anything else in the codebase — and would clutter call sites.

### Trait

```rust
pub trait SecretEncryptionEngine: Send + Sync {
    async fn encrypt(
        &self,
        key_name: &str,
        plaintext: &[u8],
    ) -> Result<Ciphertext, SecretEncryptionError>;

    async fn decrypt(
        &self,
        key_name: &str,
        ciphertext: &Ciphertext,
    ) -> Result<Vec<u8>, SecretEncryptionError>;
}
```

Notes on the trait shape:

- **Async.** The Vault backend is reached over HTTP; the Dev backend is CPU-only but still async to keep the trait uniform. The crate is on Rust 2024 edition, so `async fn` in trait works natively without the `async-trait` macro.
- **`&self` (not `&mut self`).** Backends manage their own internal synchronisation (Vault HTTP client, Dev master-key storage). The trait stays cheaply shareable.
- **`Send + Sync`.** swiyu-issuer holds the engine inside an `Arc` and shares it across request handlers.
- **Plaintext as `&[u8]`, not `&str`.** Some secrets are not UTF-8 (random bytes, opaque tokens). Callers that have a string can pass `s.as_bytes()`.
- **Returned plaintext as `Vec<u8>`.** Callers that need a `String` validate UTF-8 themselves; the engine does not assume one shape.

### Errors

```rust
#[derive(Debug, thiserror::Error)]
pub enum SecretEncryptionError {
    #[error("key not configured: {0}")]
    KeyNotFound(String),

    #[error("ciphertext envelope is malformed")]
    MalformedCiphertext,

    #[error("ciphertext key_name does not match argument: envelope={envelope}, argument={argument}")]
    KeyNameMismatch { envelope: String, argument: String },

    #[error("ciphertext key_version is not configured: {key_name} v{version}")]
    KeyVersionNotFound { key_name: String, version: u32 },

    #[error("authentication tag verification failed")]
    Tampered,

    #[error("backend error: {0}")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync>),
}
```

The variant set is intentionally minimal for the first cut. As concrete backends surface specific failure modes, we will add typed variants rather than letting everything fall through `Backend`.

### Dispatch

Backend selection happens once at startup. The set of backends is closed (dev / vault) and never changes mid-process, so swiyu-issuer wraps the chosen backend in a single enum:

```rust
pub enum AnySecretEncryptionEngine {
    Dev(DevSecretEncryptionEngine),
    Vault(VaultSecretEncryptionEngine),
}
```

`AnySecretEncryptionEngine` itself impls `SecretEncryptionEngine` and dispatches each method via `match`. The same reasoning as for `AnySigningEngine` applies: `Box<dyn …>` is not an option because the trait's async methods return `impl Future + Send` (RPITIT), making the trait not dyn-compatible. Enum dispatch avoids `async-trait`, gives exhaustiveness checks, and reads more directly than a macro-generated trait object.

## Ciphertext envelope

Encoded as a single byte slice, persisted as one `BYTEA` column. The first byte selects the layout for the rest of the envelope, so each backend defines its own — they are not interchangeable across backends.

### Format `0x01` — Dev backend (AES-256-GCM with HKDF-derived key)

| Field | Size | Notes |
|---|---|---|
| `format_version` | 1 byte | `0x01` |
| `key_name_len` | 1 byte | Length in bytes of `key_name`. Max 255. |
| `key_name` | `key_name_len` bytes | UTF-8, no terminator. |
| `key_version` | 4 bytes (u32 big-endian) | Selects the version of `key_name`. |
| `nonce` | 12 bytes | Random per encryption call. |
| `ct_and_tag` | rest | AES-GCM ciphertext concatenated with the 16-byte authentication tag. |

### Format `0x02` — Vault backend (Vault Transit ciphertext)

| Field | Size | Notes |
|---|---|---|
| `format_version` | 1 byte | `0x02` |
| `key_name_len` | 1 byte | Length in bytes of `key_name`. Max 255. |
| `key_name` | `key_name_len` bytes | UTF-8, no terminator. |
| `key_version` | 4 bytes (u32 big-endian) | Mirrors the version Vault embedded in its own ciphertext (parsed from the `vault:v<N>:` prefix). |
| `vault_payload` | rest | Base64-decoded body of `vault:v<N>:<base64>`. The nonce is internal to this payload. |

The `key_name` and `key_version` fields are duplicated between our envelope and Vault's own ciphertext. They are kept in our envelope so that decrypt can reject a wrong-`key_name` argument before calling Vault, and so that the persisted form is uniform across backends in everything except the final payload.

### Cross-backend incompatibility

Format `0x01` and Format `0x02` are not interchangeable. A row written by the Dev backend cannot be decrypted by the Vault backend and vice versa. Switching backends in production therefore requires an explicit re-encryption migration: read each ciphertext, decrypt with the old backend's engine, encrypt with the new backend's engine. The decrypt method rejects any ciphertext whose `format_version` does not match the backend in use, returning `MalformedCiphertext`.

## Tenant-scoped key naming

The aspect spec establishes that tenant-scoped secrets are encrypted under keys named `tenant/<tenant_id>/<family>` (see *Tenant-scoped secrets* in `aspect-secret-management.md`). The engine itself stays tenant-agnostic — it accepts any string as `key_name` — so the convention is enforced by the calling code rather than by the trait surface.

### Naming helper

A small helper module lives alongside the tenant repository, not inside the engine. It exposes one function per known secret family. The initial families are OAuth2 refresh tokens and OAuth2 client secrets, both tenant-scoped:

```rust
pub fn oauth2_refresh_token_key_name(tenant_id: &TenantId) -> String {
    format!("tenant-{tenant_id}-oauth2_refresh_token")
}

pub fn oauth2_client_secret_key_name(tenant_id: &TenantId) -> String {
    format!("tenant-{tenant_id}-oauth2_client_secret")
}
```

Hyphens, not slashes: Vault Transit's `keys/<name>` route uses a name regex that rejects `/`, so a slash-delimited convention is unroutable in Transit. `TenantId` is bare base58 (no `-`) and family names use `_` internally (no `-`), so `tenant-<tenant_id>-<family>` parses unambiguously. When a new family is introduced it gets a new function in the same module. Centralising the format here means the literal template appears in exactly one place per family; call sites refer to the family by function name. The engine never sees the family separately from the rest of the key name.

### Bounds

The envelope's `key_name_len` field is one byte (max 255). A typical name — `tenant-<tenant_id>-oauth2_refresh_token` — is around 45 bytes, comfortably within budget. Future families with longer names would need to stay under the same bound.

### Set of secret families

The set of secret families is fixed in code (one helper function per family), not in environment configuration. Adding a new family is a code change. There is no runtime mechanism to register or remove families; this matches the aspect spec's framing — *secret families* are fixed at engine startup, while the concrete `key_name`s for tenant-scoped families are open-ended.

## Backend implementations

Two SecretEncryptionEngine flavours, one per maturity level from the aspect spec. They share the trait above; each lives in its own sibling file.

### `DevSecretEncryptionEngine` — Low maturity (development)

**Status.** Ships in the initial version. Used in development and integration tests. Must not be used in production.

**Configuration.** One environment variable:

- `SECRET_ENCRYPTION_DEV_MASTER_KEY` — base64-encoded 32 random bytes (the master key). Standard or URL-safe base64; the engine accepts both.

Required at startup. A missing or malformed value is a fatal startup error. Blank values are treated as absent (consistent with the SigningEngine builder convention).

The Dev backend does not pre-declare a list of valid `key_name`s. Any name passed to `encrypt` or `decrypt` is accepted; the corresponding AES-256 key is derived on demand. Misconfigured names therefore surface only when the deployment runs against the Vault backend, where Vault enforces the registered key set. This is an intentional development convenience: dev configuration stays minimal at the cost of a typo not failing at startup.

**Master key handling.** The master key is loaded once at startup, base64-decoded, validated to be exactly 32 bytes, and held in a `secrecy::SecretBox<[u8; 32]>` (or equivalent zeroizing wrapper) so it never appears in `Debug` output, panic messages, or logs.

**No versioning.** The Dev backend does not support key rotation. Every ciphertext is written with `key_version = 1`. Decrypt rejects any other version with `KeyVersionNotFound`. Rotation is exercised against the Vault backend, not simulated here.

**Key derivation.** A separate AES-256 encryption key is derived for each `key_name` via HKDF-SHA256:

- `salt`: empty (`&[]`)
- `ikm`: master key (32 bytes)
- `info`: ASCII bytes `"swiyu-issuer/v1/secret-management/" ‖ key_name`
- `okm`: 32 bytes — the AES-256 key

The `info` string includes a domain-separator prefix and the key_name. This guarantees that different `key_name`s never collide on the same derived key, and that a future engine reusing the same master key for some other purpose will not collide as long as it picks a different domain-separator prefix. Tenant-scoped names of the form `tenant/<tenant_id>/<family>` are baked into `info` verbatim, so per-tenant separation is automatic — the Dev backend itself remains tenant-agnostic.

Derivation is performed on every encrypt and decrypt call. A small in-memory `HashMap<KeyName, [u8; 32]>` cache may be added later if profiling shows it is worth the complexity; v1 derives unconditionally.

**Encryption.** AES-256-GCM via the `aes-gcm` crate. A fresh 12-byte random nonce is drawn from `rand::rngs::OsRng` per call. The output is the AES-GCM ciphertext concatenated with the 16-byte authentication tag, placed in the `ct_and_tag` field of the format-`0x01` envelope. The envelope's `key_version` field is always `1`.

**Decryption.** Parses the envelope, checks `format_version == 0x01`, reads `key_name` from the envelope and compares against the argument (`KeyNameMismatch` on mismatch), checks `key_version == 1` (`KeyVersionNotFound` otherwise), derives the key for `key_name`, and runs AES-GCM decrypt. Tag failure surfaces as `Tampered`.

**Crate additions.**

- `aes-gcm` — AES-256-GCM encryption.
- `hkdf` and `sha2` — HKDF-SHA256 key derivation.
- `secrecy` — wrapping the master key so it is not leaked to logs.
- `base64` (already a transitive dep; pin if needed) — decoding the master key env var.

### `VaultSecretEncryptionEngine` — Middle maturity (production)

**Status.** Ships in the initial version. Required for production deployments.

**Backend.** HashiCorp Vault, Transit Secrets Engine. Symmetric type: `aes256-gcm96` (the Transit default). Native key versioning is used directly — Vault's notion of *version* is what we surface in our envelope's `key_version` field.

**Configuration.** Three environment variables:

- `VAULT_ADDR`, `VAULT_TOKEN` — reused from `VaultSigningEngine`. Same client identity, single Vault server per deployment.
- `SECRET_ENCRYPTION_VAULT_TRANSIT_PATH` — defaults to `transit`. Engine-scoped: `VaultSigningEngine` reads its own `SIGNING_VAULT_TRANSIT_PATH`. Operators who want to isolate signing keys from secret-encryption keys give each engine a different mount with a different ACL policy; that is an out-of-band Vault configuration step and not something this engine enforces.

The engine does **not** enumerate `key_name`s at startup. With tenant-scoped families (see *Tenant-scoped key naming*) the set of concrete `key_name`s grows as tenants are created, so a static list is not the right model. Misconfiguration — a missing tenant key in Vault — surfaces at first encrypt or decrypt as `KeyNotFound`, logged loudly. The set of families that the application uses is captured in the naming helper (code), not in environment configuration.

**Local Vault provisioning (docker-compose).** The `vault-init` sidecar in `swiyu-issuer/docker-compose.yml` runs once after the dev Vault container becomes healthy. It enables the Transit secrets engine and applies the policy attached to the runtime token. It does **not** pre-create per-tenant keys (see *Tenant-key provisioning* below); test fixtures and the dev tenant bootstrap issue the corresponding `vault write -f {transit}/keys/<name> type=aes256-gcm96` calls themselves.

**Tenant-key provisioning.** Operators provision a tenant's Vault Transit keys out of band — Terraform (`vault_transit_secret_backend_key`), an Ansible playbook, or a runbook `vault write -f {transit}/keys/<name> type=aes256-gcm96` — before the tenant is admitted. swiyu-issuer never calls `POST /v1/{transit}/keys/*` itself, neither in the tenant-create transaction nor lazily on first encrypt. This is the same onboarding shape used for OAuth2 tenant credentials in `aspect-oauth2.md` / `impl-oauth2.md`: tenant-row state required by the runtime is seeded by an operator (direct SQL or a CLI subcommand) before the first call, and "missing onboarding state" surfaces as a Terminal failure at first use — here, `KeyNotFound`. The Dev backend has no equivalent step (HKDF derives on demand).

The Vault policy attached to the runtime token therefore grants `update` on `{transit}/encrypt/*` and `{transit}/decrypt/*` only; it does **not** grant `create` or `update` on `{transit}/keys/*`. Key provisioning, rotation, and destruction stay operator responsibilities, typically expressed as infrastructure-as-code.

**Identifier mapping.** None. The configured `key_name` is used directly as the Vault Transit key name.

**API operations.**

- Encrypt: `POST /v1/{transit}/encrypt/{key_name}` with body `{ "plaintext": "<base64(plaintext)>" }`. Response body has `data.ciphertext` of the form `vault:v<N>:<base64-no-pad>`. The engine parses the `<N>` for the envelope's `key_version` field, base64-decodes the body, and writes the format-`0x02` envelope.
- Decrypt: `POST /v1/{transit}/decrypt/{key_name}` with body `{ "ciphertext": "vault:v<N>:<base64-no-pad>" }`. The engine reconstructs the `vault:v<N>:…` string from the envelope's `key_version` and `vault_payload` fields. Response body has `data.plaintext` as base64; the engine decodes and returns it.

**"Key missing" mapping.**

- `POST /v1/{transit}/encrypt/{name}` returns **400** with body containing `encryption key not found` → `KeyNotFound` at request time. Other 400s → `Backend`.
- `POST /v1/{transit}/decrypt/{name}` returns **400** with body containing `encryption key not found` → `KeyNotFound`. Body containing `cipher: message authentication failed` → `Tampered`. Other 400s → `Backend`.

There is no startup probe (see *Configuration*); a missing tenant key surfaces only when a request actually targets it. The body-substring match is fragile by nature; integration tests (`#[ignore]` by default, run against a Vault dev container) guard against silent wording changes.

**Authentication.** Reuses the Vault token configured for `VaultSigningEngine`. Token lifecycle, renewal, and policy are concerns of the operator and the Vault client setup, not of this engine.

**Network failures.** Vault is reached over the network. v1 behaviour: a single attempt per operation with the configured `request_timeout` (default 5 seconds), no retry, no backoff. Transport errors, JSON parse failures, and 5xx responses all map to `SecretEncryptionError::Backend`. Same shape and reasoning as the Vault signing backend.

## Open implementation questions

1. **Within-family swap mitigation (deferred).** The aspect spec lists, as part of its open issue *Broader implications of the database-write threat model*, binding the owning entity's identifier into AES-GCM AAD so that swapping ciphertexts between rows of the same `(tenant, family)` pair is rejected at decrypt time. If accepted, the impl will need a new envelope format (`0x03`) carrying an `aad_context` field and the trait will grow either an extra parameter or a paired set of methods. Deferred until the aspect-level open issue is resolved.
