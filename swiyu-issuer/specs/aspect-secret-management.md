# Aspect: Secret Management

## What we encrypt

swiyu-issuer stores small application secrets in its RDBMS that must round-trip through the database in reversible form. These secrets are sensitive and must be encrypted at rest so that a database dump (backup, replica, snapshot) does not reveal them in plain form.

Examples of secrets in scope:

- OAuth2 refresh tokens — tenant-scoped (one per tenant of swiyu-issuer)
- OAuth2 client secrets — tenant-scoped (one per tenant of swiyu-issuer); persisted alongside the matching client id on the `tenants` row and used to obtain access tokens against SWIYU registries
- Other small, reversible secrets the application later needs to read back as plaintext

Most secrets handled by this surface are tenant-scoped: each tenant of swiyu-issuer has its own. Tenant-scoped secrets are encrypted under tenant-specific keys so that a compromise of one tenant's key cannot expose the others. The mechanism is described in *Tenant-scoped secrets* below.

Out of scope:

- **Signing keys.** Asymmetric private keys used for Verifiable Credential and DIDLog signatures are managed by `SigningEngine` (see `aspect-key-management.md`). They are never handled as plaintext by the secret-management surface.
- **Hashes and one-way derivatives.** Anything we never need to recover (token hashes, fingerprints) uses a hash type, not encryption.
- **Large blobs.** The engine targets short payloads (up to a few kilobytes). Streaming or chunked encryption is not supported.

## What we do not manage

- **Key material.** Symmetric keys live inside the engine; they are never exposed to swiyu-issuer's domain or persistence layers. Callers refer to keys by `key_name` only.
- **Plaintext retention.** Callers always store ciphertext in the database. Plaintext is held in process memory only for the duration of a request.

## SecretEncryptionEngine

All symmetric-encryption operations are performed by a **SecretEncryptionEngine**. The fundamental rule is:

> A symmetric key never leaves the SecretEncryptionEngine. Encrypt and decrypt always happen in the engine's process space — never in the process space of the calling layer.

### Capabilities

The engine exposes two operations:

- `encrypt(key_name, plaintext) -> ciphertext`
  - Looks up the key registered under `key_name` and uses its **latest** version.
  - Generates a fresh nonce per call.
  - Returns a self-describing ciphertext blob (see *Ciphertext envelope* below) suitable for storing in a single column.
  - Returns `KeyNotFound` if `key_name` is not configured.

- `decrypt(key_name, ciphertext) -> plaintext`
  - Reads the embedded `key_name` and version from the ciphertext envelope and verifies that the embedded `key_name` matches the `key_name` argument.
  - Looks up the corresponding key version and verifies the authentication tag.
  - Returns the plaintext on success.
  - Returns `KeyNotFound` if the `key_name` or embedded version is not configured. Returns `Tampered` if the authentication tag does not verify.

The engine has **no** `rotate` or `rewrap` operation. Rotation is a backend-side configuration change (see *Rotation choreography*). When a re-encryption migration is needed, the caller decrypts with the old ciphertext and re-encrypts; `encrypt` always picks the latest version.

### Algorithm

AES-256-GCM. 256-bit key, 96-bit random nonce per call, 128-bit authentication tag. Hardware-accelerated on every production-relevant CPU; the default symmetric type in Vault Transit (`aes256-gcm96`).

### Key naming and versioning

A `key_name` is an opaque string identifying one symmetric key at the backend. The engine has no operation to register or remove names; backends that pre-register keys (Vault) require the name to exist before `encrypt` or `decrypt` is called.

What is fixed for a deployment is the set of *secret families* — coarse categories such as `oauth2_refresh_token`. For tenant-scoped families the concrete `key_name`s are open-ended and grow as tenants are created (see *Tenant-scoped secrets*). For a non-tenant-scoped secret the family name is the `key_name` directly.

Each `key_name` carries one or more **versions**, numbered `1..N`. Versions are append-only: new versions are created by rotation; older versions remain available so existing ciphertexts continue to decrypt. `encrypt` always uses the latest version of the named key. `decrypt` reads the version tag from the ciphertext envelope and uses that specific version.

### Ciphertext envelope

Ciphertext is a single self-describing byte blob, persisted as one `BYTEA` column. Callers do not track the key name or version separately — both travel with the ciphertext.

Layout:

| Field | Size | Notes |
|---|---|---|
| `format_version` | 1 byte | Currently `0x01`. Bumped only if the layout changes. |
| `key_name_len` | 1 byte | Length in bytes of `key_name`. Max 255. |
| `key_name` | `key_name_len` bytes | UTF-8, no terminator. |
| `key_version` | 4 bytes (u32 big-endian) | Selects the version of `key_name`. |
| `nonce` | 12 bytes | Random per encryption call. |
| `ct_and_tag` | rest | AES-GCM ciphertext concatenated with the 16-byte authentication tag. |

The first byte versions the format itself. Future changes — different algorithm, longer nonce, addition of associated data — can coexist with v1 ciphertexts during a migration window by recognising both prefixes.

## Tenant-scoped secrets

Most secrets handled by this surface belong to one specific tenant of swiyu-issuer. Two tenants' secrets must remain protected from each other even in the event of a single-tenant key compromise. The engine achieves this by giving each tenant its own symmetric key per secret family.

### Compartmentalisation rule

A tenant-scoped secret of family `<family>` belonging to tenant `<tenant_id>` is encrypted under the `key_name`

```
tenant/<tenant_id>/<family>
```

The `<family>` segment names one of the application's known secret families (e.g. `oauth2_refresh_token`); the `<tenant_id>` segment is the tenant's stable identifier. The combination uniquely identifies one symmetric key — there is exactly one such key per (tenant, family) pair, never shared across tenants and never overloaded across families.

### Engine remains tenant-agnostic

The engine itself does not know what a tenant is. It accepts `key_name` as an opaque string; the `tenant/<tenant_id>/<family>` convention is enforced by the calling code (a small naming helper alongside the tenant repository), not by the engine. This keeps the engine narrow — it does symmetric crypto and nothing else — and lets future non-tenant-scoped secrets coexist under different `key_name` shapes without changing the trait.

### Threats addressed

Compartmentalisation along both axes — per tenant *and* per family — is **defense in depth** against two distinct threats:

- **Single-key compromise.** If one tenant's key material is exposed (through a misconfigured backend ACL, operator error, or any other single-key compromise), the blast radius is confined to that tenant; other tenants' ciphertexts remain protected. This motivates the *tenant* axis.
- **Database integrity compromise.** An attacker with database write access but no key access must not be able to swap ciphertexts between secret families — for example, swapping a stored OAuth2 client secret into the refresh-token column so the application then transmits the client secret to an OAuth2 server as if it were a refresh token, with the value potentially surfacing in error responses or logs. Encrypting each family under a different key makes such cross-family swaps fail to decrypt rather than silently deliver wrong-purpose plaintext, and the protection is automatic at call sites because it is carried by the `key_name` rather than by per-call discipline (e.g. associated-data conventions). This motivates the *family* axis.

What compartmentalisation does *not* address are requirements the project does not currently have — there is no regulator-mandated cryptographic erasure deadline, no per-tenant rotation cadence, and no contractual data-segregation guarantee to a tenant. If those arise later they layer on top of this design rather than replacing it.

### Lifecycle expectations

- **Provisioning.** A tenant-scoped key is provisioned when the tenant is created. The mechanism (who calls the backend, with what permissions) is a backend-specific implementation concern; see `impl-secret-management.md`.
- **Use.** All encrypts and decrypts of that tenant's secrets target the corresponding `tenant/<tenant_id>/<family>` key. The engine's *latest version* and rotation rules apply per (tenant, family) pair, independently of other tenants.
- **Offboarding.** Because the requirement is defense-in-depth and not cryptographic erasure, key destruction on tenant offboarding is best-effort and not required for correctness. Operators who want stronger erasure guarantees can destroy the key material at the backend after offboarding; this is an out-of-band operator decision and not enforced by swiyu-issuer.

## Maturity levels

Two backends ship. The HSM (High) maturity tier from `aspect-key-management.md` does not apply to this surface — symmetric protection of small application secrets does not need an HSM the way credential signing does — and is not in scope here.

### Low — Dev backend

For development and integration tests. Must not be used in production.

The Dev backend is configured with a single 32-byte **master key**, supplied through an environment variable. No key file on disk is required. From the master key, the backend derives a separate AES-256 key for each `key_name` using a key derivation function whose context includes the full name. Tenant-scoped names of the form `tenant/<tenant_id>/<family>` therefore yield naturally distinct derived keys, with no tenant awareness in the backend itself. The derived key is computed on demand inside the engine and used immediately for AES-GCM; it is never persisted.

The Dev backend does not support key rotation. Every ciphertext is written with `key_version = 1`, and only `key_version = 1` is accepted on decrypt. Rotation is a production concern; production uses the Vault backend, which versions keys natively. Developers who need to exercise rotation paths do so against Vault, not against a simulated rotation in the Dev backend.

The master key itself is the only long-term secret. If the master key is replaced, all existing ciphertexts become unreadable; in development this is acceptable because development databases are routinely wiped and reseeded.

This backend is Low maturity because the master key sits in plain form in the deployment environment (an environment variable). It is fit for development; it is not fit for production.

### Middle — Vault backend

For staging and production. Backed by HashiCorp Vault's Transit Secrets Engine.

Each `key_name` corresponds to one Transit key. Vault holds the key material; encrypt and decrypt are performed inside Vault. Versioning is Vault's native key-versioning: rotating a Transit key creates a new version, `encrypt` automatically uses the latest, older versions remain available for `decrypt`.

This backend is Middle maturity because the keys never appear outside Vault and Vault's own access controls protect them, but the protection is software (process isolation + ACLs), not hardware.

### Requirements

- **Production:** the deployed SecretEncryptionEngine must be at least Middle maturity (Vault-backed).
- **Development:** swiyu-issuer ships with the Dev backend for local work and integration tests.
- **High:** not in scope. The trait is shaped so an HSM-backed backend could be added later without breaking callers.

## Rotation choreography

Because the engine has no `rotate` operation, rotation is performed at the backend layer and observed by swiyu-issuer through the change in *latest version*:

1. **Add a new version to `key_name`** at the backend. The two backends do this differently (operator action; not a swiyu-issuer responsibility).
2. **`encrypt(key_name, …)` now produces ciphertexts tagged with the new version.** No coordination with swiyu-issuer is required — the engine reads the latest version on each call.
3. **`decrypt` of older ciphertexts continues to work** as long as the previous versions remain available at the backend.
4. **Optional re-encryption migration.** swiyu-issuer may walk existing rows and re-encrypt them with the new version. v1 has no built-in `rewrap` helper; the caller decrypts the old ciphertext and re-encrypts (which writes the new version because `encrypt` always picks the latest). This is an offline operation, scheduled by the operator.
5. **Removal of old versions** is a backend operation and is out of scope here. Removing a version that still has live ciphertexts will cause subsequent `decrypt` calls to return `KeyNotFound`. Operators should complete the re-encryption migration first.

### Properties of this design

- Symmetric keys never leave the engine.
- Ciphertexts are self-describing: callers store one column and never track key name or version separately.
- Rotation requires no coordinated cutover: old and new versions coexist for as long as the operator needs.
- The backend (not swiyu-issuer) is the source of truth for *which versions of `key_name` exist*.

## Open issues

### Broader implications of the database-write threat model

The *Threats addressed* subsection brings an attacker with write access to the swiyu-issuer database (but no access to the encryption keys) into scope. This assumption is internally consistent for the secret-encryption surface specified here, but it has implications for other defence mechanisms in swiyu-issuer that have **not yet been analysed** as part of this aspect or anywhere else. Areas worth examining in a follow-up — non-exhaustive — include: within-family ciphertext swap (different rows sharing the same `key_name`); re-verification of signed data (DIDLogs, issued credentials, status lists) on every read rather than trusting a stored "verified" marker; integrity of unsigned `tenant_id` columns used by the application for authorisation or routing; tamper resistance of audit logs that share the database; replay safety of short-lived state such as OIDC `state`/`nonce` values, preauth codes, and idempotency keys; and the use of AES-GCM AAD as a defence-in-depth layer on top of the envelope's `key_name` check.

Some of these (within-family swap, AAD as defence in depth) refine the encryption surface itself and may eventually fold back into this aspect. Others (signature re-verification on read, audit-log integrity, replay protection of ephemeral state, hardening of database roles and backups) belong in a broader "database as untrusted input" analysis that does not yet exist. This open issue tracks the gap; it is not a commitment to address every item here.
