# Implementation: key management

This document captures the concrete shape of `swiyu-issuer`'s key-handling code: the trait surface, the keystore schema, and the per-backend mappings. For the architectural decisions and reasoning see [`aspect-key-management.md`](aspect-key-management.md).

Status: preliminary. The trait shape and DB-backed schema are stable enough to start implementation; HSM and cloud-KMS impls are sketched but unwritten.

## Scope

Covers:

- The `Signer` and `KeyManager` traits, their supporting types, and the single DB-backed implementation.
- The `swiyu_issuer_keystore` schema.
- The `KekProvider` and `KEKManager` traits, their supporting types, and an overview of each backend (filesystem dev, Vault Transit, PKCS#11) — enough to name the contract; full per-backend wire details belong in a separate orchestrator-specific spec.
- The re-encryption sweep, which lives above both trait pairs.
- Implementation wrinkles that don't surface in the traits but matter for correctness.

Does *not* cover:

- Detailed per-backend wire specs (Vault Transit policy and auth, PKCS#11 vendor quirks).
- DID log entry construction (lives in the management API layer).
- Rotation orchestration (the call-graph that ties `stage_rotation`, registry submission, and `commit_rotation` together — lives in the management API layer).
- Status-list signing (separate slice).

## Module layout

`swiyu-issuer/src/signer/`:

- `mod.rs` — `Signer` and `KeyManager` (concrete structs, no trait polymorphism since the keystore is DB-only).
- `types.rs` — `KeyRole`, `Algorithm`, `PublicKey`, `Signature`, `KeyTriplePublic`.
- `error.rs` — `SignerError` enum.

`swiyu-issuer/src/kek/`:

- `mod.rs` — `KekProvider` and `KEKManager` trait definitions and re-exports.
- `types.rs` — `KekVersion`, `Ciphertext`.
- `error.rs` — `KekError` enum.
- `fs.rs` — dev-only filesystem impl, behind cargo feature `dev-kek-fs`.
- `vault_transit.rs` — Hashicorp Vault Transit impl.
- `pkcs11.rs` — PKCS#11 / HSM impl.

`swiyu-issuer/src/persistence/keystore/`:

- `mod.rs` — module declarations and re-exports.
- `signing_keys.rs` — read/write functions for the keystore table. Free functions, taking `&mut PgConnection`, scoped by `(tenant, issuer)` in every signature.

## Public surface

```rust
// types.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRole {
    Authorized,
    Authentication,
    Assertion,
}

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
    #[error("no active key for issuer {issuer:?} role {role:?}")]
    KeyNotFound { issuer: IssuerId, role: KeyRole },
    #[error("active key triple already exists for issuer {0:?}")]
    AlreadyInitialised(IssuerId),
    #[error("a pending rotation already exists for issuer {0:?}")]
    PendingRotationExists(IssuerId),
    #[error("no pending rotation to commit for issuer {0:?}")]
    NoPendingRotation(IssuerId),
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
    /// Sign with the *active* triple's key for the given role.
    async fn sign(
        &self,
        tenant: &TenantId,
        issuer: &IssuerId,
        role: KeyRole,
        payload: &[u8],
    ) -> Result<Signature, SignerError>;

    async fn health_check(&self) -> Result<(), SignerError>;
}

#[async_trait::async_trait]
pub trait KeyManager: Signer {
    /// Bootstrap: generate the issuer's first triple and store it as active.
    /// Fails with `AlreadyInitialised` if a triple already exists.
    async fn create_initial_triple(
        &self,
        tenant: &TenantId,
        issuer: &IssuerId,
    ) -> Result<KeyTriplePublic, SignerError>;

    /// Generate a new triple and store it as `pending_next`.
    /// Fails with `PendingRotationExists` if one is already pending.
    async fn stage_rotation(
        &self,
        tenant: &TenantId,
        issuer: &IssuerId,
    ) -> Result<KeyTriplePublic, SignerError>;

    /// Promote `pending_next` to `active`, destroying the previous active
    /// triple's material. Idempotent: a second call after success is a no-op.
    /// Fails with `NoPendingRotation` only if called with no pending row
    /// *and* no expectation that one was committed previously — see
    /// reconciliation note below.
    async fn commit_rotation(
        &self,
        tenant: &TenantId,
        issuer: &IssuerId,
    ) -> Result<(), SignerError>;

    /// Discard a staged `pending_next` without committing.
    /// Idempotent: a no-op if no pending rotation exists.
    async fn discard_pending(
        &self,
        tenant: &TenantId,
        issuer: &IssuerId,
    ) -> Result<(), SignerError>;

    /// Destroy all key material for the issuer (deactivation).
    /// Idempotent.
    async fn delete_keys(
        &self,
        tenant: &TenantId,
        issuer: &IssuerId,
    ) -> Result<(), SignerError>;
}
```

`Signer::sign` always targets the `active` row. During a rotation the management layer signs the new log entry by calling `sign(.., role: Authorized, ..)` *before* `commit_rotation` is invoked — so the signature is produced by the outgoing key, which is still the active one at that moment. Once `commit_rotation` succeeds, the new triple is active and subsequent signs use it.

There is no `public_key` method on the trait. The application has no operational reason to query the keystore for a public key; see [`aspect-key-management.md`](aspect-key-management.md). The `KeyTriplePublic` returned from `create_initial_triple` and `stage_rotation` is consumed once — by the management layer composing the next DID log entry — and then dropped.

### KEK traits

```rust
// kek/types.rs
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KekVersion(pub String);

/// Opaque wrapped-plaintext blob. Owns whatever the impl needs to unwrap —
/// AES-GCM nonce + ciphertext for the file impl, the bytes Vault Transit
/// returned, the bytes the HSM returned, etc. Treated as an opaque BYTEA in
/// the keystore.
#[derive(Debug, Clone)]
pub struct Ciphertext(pub Vec<u8>);

// kek/error.rs
#[derive(Debug, thiserror::Error)]
pub enum KekError {
    #[error("tenant {0:?} not registered with the KEK provider")]
    UnknownTenant(TenantId),
    #[error("version {version:?} not found for tenant {tenant:?}")]
    UnknownVersion { tenant: TenantId, version: KekVersion },
    #[error("tenant {0:?} already has a KEK; create_initial_kek refused")]
    AlreadyInitialised(TenantId),
    #[error("AAD mismatch on unwrap (tenant {tenant:?}, version {version:?})")]
    AadMismatch { tenant: TenantId, version: KekVersion },
    #[error("KEK provider not healthy")]
    Unhealthy,
    #[error("backend error: {0}")]
    Backend(Box<dyn std::error::Error + Send + Sync>),
}

// kek/mod.rs
#[async_trait::async_trait]
pub trait KekProvider: Send + Sync {
    /// Wrap `plaintext` under the tenant's *current* KEK, binding `aad` to
    /// the resulting ciphertext (via AES-GCM AAD, Vault Transit `context`,
    /// PKCS#11 GCM AAD, etc.). Returns the ciphertext and the version label
    /// that was used — the caller stores both alongside the wrapped data.
    async fn wrap(
        &self,
        tenant: &TenantId,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<(Ciphertext, KekVersion), KekError>;

    /// Unwrap `ciphertext` under the tenant's KEK at `version`, verifying
    /// the AAD binding. Fails with `AadMismatch` if the binding is wrong,
    /// `UnknownVersion` if the version has been retired or never existed.
    async fn unwrap(
        &self,
        tenant: &TenantId,
        version: &KekVersion,
        ciphertext: &Ciphertext,
        aad: &[u8],
    ) -> Result<Vec<u8>, KekError>;

    /// True when the impl guarantees that the KEK material never leaves the
    /// trust boundary — HSM hardware, Vault Transit with `exportable=false`.
    /// The dev filesystem impl returns false. The production binary refuses
    /// to start unless this returns true.
    fn non_exportable_kek(&self) -> bool;

    async fn health_check(&self) -> Result<(), KekError>;
}

#[async_trait::async_trait]
pub trait KEKManager: KekProvider {
    /// Tenant provisioning: create the tenant's first KEK as version 1
    /// (or whatever the impl chooses as a starting label).
    /// Fails with `AlreadyInitialised` if the tenant is already registered.
    async fn create_initial_kek(
        &self,
        tenant: &TenantId,
    ) -> Result<KekVersion, KekError>;

    /// Add a new KEK version that becomes the new "current". Existing
    /// versions remain usable for `unwrap`. Returns the new version label.
    async fn introduce_version(
        &self,
        tenant: &TenantId,
    ) -> Result<KekVersion, KekError>;

    /// Permanently remove an old version. The caller must verify, via the
    /// keystore, that no row still references the version before calling
    /// this — keeping `KEKManager` decoupled from keystore wire format.
    async fn retire_version(
        &self,
        tenant: &TenantId,
        version: &KekVersion,
    ) -> Result<(), KekError>;

    /// List every version currently held for the tenant. Used by the
    /// re-encryption sweep to find rows still on a retired-but-not-yet-
    /// removed version.
    async fn list_versions(
        &self,
        tenant: &TenantId,
    ) -> Result<Vec<KekVersion>, KekError>;

    /// The version that the next `wrap` call will use. Used by the sweep to
    /// decide which rows are stale.
    async fn current_version(
        &self,
        tenant: &TenantId,
    ) -> Result<KekVersion, KekError>;

    /// Tenant deprovisioning: remove every KEK version for the tenant.
    /// The caller must ensure no keystore rows remain.
    async fn delete_tenant(&self, tenant: &TenantId) -> Result<(), KekError>;
}
```

The OIDC binary's wiring takes `Arc<dyn KekProvider>`; the management binary takes `Arc<dyn KEKManager>`. A given concrete impl (e.g., `VaultTransitKekManager`) implements both traits and can be handed to either binary at the privilege level it needs.

## Schema

`swiyu_issuer_keystore.signing_keys`:

| Column | Type | Notes |
|--------|------|-------|
| `tenant_id` | TEXT NOT NULL | Reference into `swiyu_issuer_mgmt.tenants`; logical-only when keystore is on a separate database. |
| `issuer_id` | TEXT NOT NULL | Reference into `swiyu_issuer_mgmt.issuers`; same caveat. |
| `status` | TEXT NOT NULL | `'active'` \| `'pending_next'`. CHECK constraint. |
| `created_at` | TIMESTAMPTZ NOT NULL DEFAULT NOW() | |
| `authorized_ciphertext` | BYTEA NOT NULL | Output of `KekProvider::wrap` for the `Authorized` private key. Opaque to the keystore — the impl knows how to unwrap. |
| `authentication_ciphertext` | BYTEA NOT NULL | Same, for `Authentication`. |
| `assertion_ciphertext` | BYTEA NOT NULL | Same, for `Assertion`. |
| `kek_version` | TEXT NOT NULL | The `KekVersion` returned by `wrap` when these three ciphertexts were produced. The `unwrap` path passes it back. The re-encryption sweep uses it to find rows still wrapped under retired versions. Not part of AAD. |

Primary key: `(tenant_id, issuer_id, status)`. Per `(tenant_id, issuer_id)` the table holds at most one `active` row and at most one `pending_next` row — zero, one, or two rows total.

No `backend_kind` column — there is only one signing-side backend (DB) and the per-row variation lives entirely inside the `Ciphertext` blob's interpretation by the held `KekProvider`. No `*_handle` columns. No separate `aead_nonce` column (the nonce, if any, is part of the wrapped blob).

Three roles per row keeps triple atomicity natural — a key triple's three pieces of material land in a single INSERT.

No public-key columns. Public keys are returned in-memory from the trait calls that produce them and are not persisted. The DID log in the registry is the canonical source.

No `retired_at`, no historical-generation rows. A retired triple is destroyed.

## Signer / KeyManager implementation

The keystore is DB-only; there is no per-backend polymorphism on the signing side. The struct holds a `PgPool` and an `Arc<dyn KekProvider>`. Tenant-lifecycle KEK calls (`create_initial_kek`, `delete_tenant`) are *not* this struct's job — the management binary calls them on a separate `Arc<dyn KEKManager>` at tenant provisioning time, before any issuer is created.

`sign`:

1. `SELECT {role}_ciphertext, kek_version FROM signing_keys WHERE tenant_id=$1 AND issuer_id=$2 AND status='active'`.
2. `plaintext = kek_provider.unwrap(tenant, &row.kek_version, &row.ciphertext, aad((tenant, issuer, role, "active"))).await`.
3. Sign via `swiyu-didtool::crypto::{sign_eddsa, sign_es256}` depending on role.
4. Wrap in `Signature { algorithm, raw }`.

The OIDC binary's `sign` path is read-only on the keystore — it does not migrate stale `kek_version` rows. Re-encryption is the management binary's job (see [Re-encryption sweep](#re-encryption-sweep)).

`create_initial_triple`:

1. `swiyu-didtool::crypto::generate_*` for each of the three roles.
2. For each role: `(ciphertext, version) = kek_provider.wrap(tenant, &private_bytes, aad((tenant, issuer, role, "active"))).await`. All three calls return the same `version` (the current KEK).
3. INSERT one row with status `'active'`, the three ciphertexts, and `kek_version = version`. Fails with `AlreadyInitialised` if the row already exists.
4. Return `KeyTriplePublic` from the in-memory publics; the private bytes are dropped after `wrap`.

`stage_rotation`:

1. Generate the three private keys.
2. For each role: `(ciphertext, version) = kek_provider.wrap(tenant, &private_bytes, aad((tenant, issuer, role, "pending_next"))).await`.
3. INSERT row with status `'pending_next'`, the three ciphertexts, `kek_version = version`. Fails with `PendingRotationExists` if one already exists.
4. Return `KeyTriplePublic`.

`commit_rotation`:

1. Open a transaction.
2. `DELETE FROM signing_keys WHERE tenant_id=$1 AND issuer_id=$2 AND status='active'`.
3. For each role on the `pending_next` row: `unwrap` with the row's own `kek_version` and AAD `(…, "pending_next")`, then `wrap` (no version argument — uses the current) with AAD `(…, "active")`. The `wrap` call returns `(new_ciphertext, new_version)`.
4. `UPDATE` the row to status `'active'` with the three new ciphertexts and `kek_version = new_version`.
5. Commit.

The AAD rebind in step 3 is unavoidable — the AAD includes the row's status, so changing the status requires re-wrapping. Using the current KEK at the same time means a rotation also opportunistically migrates the row to the freshest KEK version. The work happens once per rotation and only on the management binary's host, not in the OIDC binary's hot path.

If the `pending_next` row doesn't exist when `commit_rotation` is called, the function logs and returns `Ok(())` (idempotent re-call after success). The `NoPendingRotation` error is reserved for callers that want to assert a pending row should exist; the management layer's reconciliation logic uses it.

`discard_pending`:

`DELETE FROM signing_keys WHERE tenant_id=$1 AND issuer_id=$2 AND status='pending_next'`. No-op if absent.

`delete_keys`:

`DELETE FROM signing_keys WHERE tenant_id=$1 AND issuer_id=$2`. No-op if absent.

`health_check()`: `SELECT 1` against the pool. The KEK provider's health is checked separately at boot.

### Re-encryption sweep

A management-binary-only background job that walks rows wrapped under retired KEK versions and re-`wrap`s them under the current version. Runs per tenant; can be invoked on demand (right after `KEKManager::introduce_version` returns, to drain rapidly) or on a schedule.

Lives outside both traits as a free function in the management layer. Takes:

- `&KeyManager` — for the per-row read/UPDATE inside short transactions.
- `&dyn KEKManager` — for `current_version`, `list_versions`, `unwrap`/`wrap` (inherited from `KekProvider`), and ultimately `retire_version`.

Per-tenant flow:

1. Call `kek_manager.current_version(tenant)` and `kek_manager.list_versions(tenant)` to determine the set of retired-but-still-needed versions.
2. For each retired version `v`, walk rows where `kek_version = v` (paged query against the keystore). For each row, in its own short transaction:
   a. `SELECT … FOR UPDATE` ciphertexts, `kek_version`, `status`. Row lock prevents a concurrent `commit_rotation` from racing.
   b. If `kek_version` is already current (re-check inside the transaction), skip.
   c. For each role: `unwrap` with `(tenant, &row.kek_version, &row.ciphertext, aad((tenant, issuer, role, status)))`, then `wrap` with `(tenant, &plaintext, aad((tenant, issuer, role, status)))`. The `wrap` calls return the current version label.
   d. `UPDATE` the row's three ciphertexts and `kek_version`.
   e. Commit.
3. After the sweep walks the retired version to exhaustion, verify the gate by counting rows still on `v` (within a single read-only transaction). If zero, call `kek_manager.retire_version(tenant, &v)`.

Properties:

- **Idempotent and restartable.** A crash between transactions leaves the partial-progress visible (`kek_version` reflects whichever rows have been migrated); the sweep can resume from the same point and only the still-stale rows are re-touched.
- **No global lock.** Each row is its own transaction.
- **No correctness coupling to the OIDC binary.** A signing call concurrent with a sweep on the same row either takes the row's lock first (sweep waits one short transaction) or sees the row in its old or new state, but never an inconsistent in-between.
- **Retirement gate is enforced by the sweep, not by `KEKManager`.** `KEKManager::retire_version` does not query the DB itself — it just removes the version from the secret store. The sweep's keystore count is the precondition; this keeps `KEKManager` impls decoupled from the keystore's wire format.

The OIDC binary does not run the sweep and does not need write privileges on the keystore for this purpose.

## KEK backend impls (per-backend overview)

Concrete `KekProvider` / `KEKManager` impls live in `swiyu-issuer/src/kek/<backend>.rs`. Detailed mappings (request/response shapes, auth, retry/backoff) are deferred to a separate spec; this section names the three backends in scope and the contract each one satisfies.

### `FilesystemKekManager` (`kek/fs.rs`, dev-only)

Behind cargo feature `dev-kek-fs`. Construction takes a `&Path`. The path is resolved from the env var `SWIYU_DEV_KEK_FS_PATH` at the binary's wiring layer; the constructor itself takes the resolved `&Path` so unit tests don't depend on env state. If the env var is unset while the feature is compiled in and the tier is `Alpha`, the wiring layer returns an error naming the var.

The YAML file at that path:

```yaml
tenants:
  tenant_9hXq2vRtL8pK7f:
    # display_name: "Gemeinde Buchs"   # reserved; not yet on the tenant domain model
    current_kek: v2
    keks:
      v1: "<32 hex bytes>"
      v2: "<32 hex bytes>"
  tenant_AbC3xY9mZ2qR4t:
    current_kek: v1
    keks:
      v1: "<32 hex bytes>"
```

Tenants are keyed by the **prefixed** id form (`tenant_<bare>`) — matching the `Display`/`Serialize` convention in `swiyu-issuer/src/domain/ids.rs`. The deserializer parses each key via `TenantId::from_str` so the same validation rules apply as in management-API bodies: prefix required, bare segment must be valid base58.

The optional `display_name` field is reserved for when the tenant domain model gains one (e.g., `"Gemeinde Buchs"`). Until then, the deserializer accepts the field and ignores it (keeps the YAML forward-compatible) but has no domain-side use for it. When the domain model adds the field, the loader can start propagating it.

Refuses to construct unless `MaturityTier == Alpha`. Refuses to load if the file is group- or world-readable. Emits a `WARN` log line on construction naming the path and tier.

`wrap` / `unwrap` perform AES-256-GCM in process, with a fresh 12-byte nonce per `wrap` (the nonce is prepended to the ciphertext bytes inside `Ciphertext`). AAD passes through to the AES-GCM AAD parameter unchanged.

`introduce_version` writes a new `vN+1` entry into the `keks` map and updates `current_kek`. `retire_version` deletes the entry. `delete_tenant` removes the tenant's whole map entry. The file is rewritten atomically (temp file + rename).

`non_exportable_kek()` returns `false`.

### `VaultTransitKekManager` (`kek/vault_transit.rs`)

Talks to Vault's Transit secrets engine. Each tenant maps to a Transit key (`transit/keys/<tenant_id>`), with versions managed by Transit itself (`min_decryption_version`, `latest_version`).

| Trait method | Vault Transit call |
|---|---|
| `wrap` | `POST /v1/transit/encrypt/<tenant>` with `plaintext` (base64) and `context` (base64 of AAD). Returns `ciphertext` like `vault:v3:…`; the `:vN:` segment is the version label. |
| `unwrap` | `POST /v1/transit/decrypt/<tenant>` with `ciphertext` and `context`. Vault picks the version from the ciphertext prefix; the `version` argument from the trait must match it (we verify after parse). |
| `create_initial_kek` | `POST /v1/transit/keys/<tenant>` with `type=aes256-gcm96`, `exportable=false`, `allow_plaintext_backup=false`. |
| `introduce_version` | `POST /v1/transit/keys/<tenant>/rotate`. |
| `retire_version` | `POST /v1/transit/keys/<tenant>/config` with raised `min_decryption_version`. (Vault doesn't physically delete the version; raising the floor makes it unreachable, which is the equivalent.) |
| `list_versions` | `GET /v1/transit/keys/<tenant>` reads the keys list and returns the version range that's still decryptable (`min_decryption_version` upward). |
| `current_version` | Same call; returns `latest_version`. |
| `delete_tenant` | `DELETE /v1/transit/keys/<tenant>` (requires `deletion_allowed=true`, set at create time only when policy permits). |

`non_exportable_kek()` returns `true` if `exportable=false` is reflected on the key (verified at `health_check` time and cached).

`health_check` reads the key's metadata and verifies it exists, is `aes256-gcm96`, and is non-exportable.

### `Pkcs11KekManager` (`kek/pkcs11.rs`)

Talks to an HSM via PKCS#11. Each tenant's KEK is one or more `CKO_SECRET_KEY` objects on the slot, attribute `CKA_LABEL = tenant_id`, `CKA_ID` encoding the version (e.g., `tenant_id || ":v" || N`). All KEK objects have `CKA_EXTRACTABLE = false`, `CKA_SENSITIVE = true`, `CKA_TOKEN = true`.

| Trait method | PKCS#11 mechanism |
|---|---|
| `wrap` | `C_EncryptInit` + `C_Encrypt` with `CKM_AES_GCM`, AAD parameter set to the trait's `aad`, fresh 12-byte IV. The `Ciphertext` blob carries IV \|\| ciphertext \|\| tag. |
| `unwrap` | `C_DecryptInit` + `C_Decrypt` with `CKM_AES_GCM`, same AAD. |
| `create_initial_kek` | `C_GenerateKey` with `CKM_AES_KEY_GEN`, `CKA_VALUE_LEN = 32`, the `CKA_LABEL`/`CKA_ID` for `(tenant, "v1")`, attributes above. |
| `introduce_version` | `C_GenerateKey` with `(tenant, "vN+1")` derived from the current max version on the slot. |
| `retire_version` | `C_DestroyObject` for the matching `CKA_ID`. |
| `list_versions` | `C_FindObjects` with `CKA_LABEL = tenant_id`, parse versions out of the `CKA_ID`s. |
| `current_version` | Highest `vN` from `list_versions`. |
| `delete_tenant` | `C_DestroyObject` for every key with `CKA_LABEL = tenant_id`. |

The impl maintains a pool of pre-authenticated sessions (4–16, configurable), runs each call inside `tokio::task::spawn_blocking`. PIN/password is sourced from the deployment's secret-injection mechanism (e.g., a Kubernetes projected file), fetched once at construction, never logged.

`non_exportable_kek()` returns `true`, asserted at construction time by sampling a key's `CKA_EXTRACTABLE` attribute.

`health_check` opens a session, logs in, lists objects with `CKA_LABEL = "<sentinel-tenant>"`, and returns success only on a clean round-trip.

## Implementation wrinkles

- **AAD rebind on `commit_rotation`.** The AAD includes `status`, so promoting `pending_next` to `active` requires re-`wrap` (which is two trait calls per role: `unwrap` + `wrap`). Cost is small and only on the management binary.
- **`Ciphertext` is opaque to the keystore.** Whatever the impl needs (nonce, version prefix, GCM tag) lives inside the blob. The DB stores it as a `BYTEA`; the only structured data the keystore exposes is the `kek_version` column.
- **Backend mismatch on unwrap is a real failure mode.** A keystore row written by one `KekProvider` impl cannot be unwrapped by another. The deployment configuration must keep the impl stable across the data's lifetime; switching impls requires a re-encryption sweep that re-`wrap`s every row.
- **Vault Transit version arithmetic.** Vault embeds the version number in the ciphertext prefix (`vault:v3:…`). The impl parses this and verifies it matches the `version` argument passed to `unwrap` — guards against silent provider drift.
- **PKCS#11 session pooling.** Same shape as the Vault Transit HTTP client pool. Pool size is a deployment knob; default 8.

## Open

- **`SignerError` granularity.** Current variants cover the major failure modes; expect a few more (e.g., a distinct variant for "registry/keystore disagreement on the active key") as the reconciliation logic is written.
- **Vault Transit details.** Auth method (token vs AppRole vs Kubernetes auth), retry/backoff for transient `503`s, and the policy required by the issuer's role are TBD in the orchestrator-specific spec.
- **PKCS#11 details.** Vendor-specific quirks (label/ID length limits, `CKM_AES_GCM` parameter shape across libraries) are TBD when an HSM is procured.
- **Re-encryption sweep packaging.** Whether the sweep runs as a tokio task inside the management binary's process, as a separate one-shot binary scheduled by the operator, or both. Throttle/batch knobs to surface.
- **Reconciliation entry point.** The startup-time check that compares the registry's latest authorized key against the keystore's active row — likely a free function in the management layer that takes a `KeyManager` and a registry client. Where exactly it sits, and whether it's invoked from `main` or from a dedicated reconciliation step, is open.
- **Verification helpers.** Wallet-side and verifier-side signature verification doesn't need the trait; a `swiyu-didtool::crypto::verify_*` helper covers it. Coordination point only.
