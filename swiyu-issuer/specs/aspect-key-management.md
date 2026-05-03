# Key management

This document records decisions and open questions about how `swiyu-issuer` generates, persists, and uses the cryptographic key material that backs its issuers' DIDs.

Status: preliminary. Direction agreed; several implementation details still open.

## Scope

Covers:

- What key material the issuer holds locally and what it doesn't.
- Where private keys live across the project's maturity levels.
- How private keys are protected at rest.
- Reuse of and divergence from `swiyu-didtool`'s key handling.
- Code-level expectations on the signing path.

Does *not* cover:

- The wire-format details of `did:tdw` and `did:webvh` log entries.
- The internals of HSM provider selection — see [`aspect-persistence.md`](aspect-persistence.md) for the open question.
- Status-list signing (separate slice).

## Local key state

From [`aspect-multi-tenancy.md`](aspect-multi-tenancy.md):

```
tenant 1:{0..n} issuer 1:1 did 1:{1..m} key-triple-generation
```

The DID accumulates multiple key-triple generations across its lifetime — but the full history lives in the DID log, which `swiyu-issuer` publishes to the SWIYU Issuer Registry. The registry is the canonical source for every public key the issuer has ever used.

`swiyu-issuer` does **not** mirror that history locally. The keystore holds at most one current key triple per active issuer, plus optionally a second triple in a transient `pending_next` state during rotation. A deactivated issuer holds no key material at all.

This is the most important simplification of the local data model. Three properties fall out of it:

- The issuer never re-signs with a retired private key. Past credentials remain verifiable because verifiers resolve the DID through the registry and find each historical public key in the log.
- The issuer never serves its own DID document over HTTP. The registry resolves DIDs.
- The issuer doesn't need its own public keys at runtime. The application has no operational reason to ask the keystore "what's my current assertion public key?" — the registry holds that, and any place a `kid` is needed in a JWS header it can be constructed from the issuer's DID and the role-stable verification-method ID.

The triple's shape is fixed:

| Role             | Algorithm | Purpose                          |
|------------------|-----------|----------------------------------|
| `authorized`     | EdDSA     | Signs DID log entries            |
| `authentication` | ECDSA     | DID authentication               |
| `assertion`      | ECDSA     | Signs verifiable credentials     |

Public-key bytes flow through the issuer in-memory: key generation produces them, the new DID log entry embeds them, the registry receives them, and the local process drops them. They are not persisted in the keystore.

### Rotation: the one place the previous private key matters

In `did:tdw` 0.3 and `did:webvh` 1.0, a rotation log entry is signed by the **outgoing** `authorized` key (its public counterpart having been pre-committed in the previous entry's `nextKeyHashes`). So during the rotation operation the keystore briefly holds two triples — the active one (about to be retired) and `pending_next` (about to take its place) — and the active `authorized` private key signs the rotation entry one last time. After the registry acknowledges the entry, the active triple is destroyed and `pending_next` is promoted to active.

This is the only situation in which the issuer touches material that's about to be retired. There is no steady-state need to keep retired private keys around.

## Storage taxonomy

The keystore architecture is a clean two-layer split:

- **Issuer private keys** — always live in the RDBMS (`swiyu_issuer_keystore.signing_keys`) as AEAD ciphertext. One backend, no polymorphism. The DB is the right home because the issuer is a fleet behind a load balancer (see [`aspect-multi-tenancy.md`](aspect-multi-tenancy.md)): atomic rotation, transactional reads, and `pg_dump` backups are all one mechanism away. A filesystem keystore — the design `swiyu-didtool` uses — would force a network filesystem with its own locking and latency pain, and is rejected for `swiyu-issuer`.
- **KEKs (key-encryption keys)** — live wherever the deployment's `KekProvider` impl points. The KEK material is what the security boundary actually protects: an attacker with the DB but not the KEK has only ciphertext.

Three KEK backends are in scope, ranked by trust strength:

1. **Filesystem (dev only).** The KEK lives in a TOML file on the developer's machine; the application reads the bytes and does AES-256-GCM in-process. Compiled in only with the `dev-kek-fs` cargo feature; a non-alpha binary cannot construct it. See [Dev-only filesystem KEK provider](#dev-only-filesystem-kek-provider).
2. **Software service with server-side crypto** — Hashicorp Vault Transit. The KEK is created inside Vault (`exportable=false`) and never leaves; wrap/unwrap delegates to Transit's `encrypt`/`decrypt` endpoints. Security boundary: the Vault process and its auto-unseal mechanism.
3. **Hardware-rooted** — PKCS#11 / HSM. The KEK is a `CKO_SECRET_KEY` with `CKA_EXTRACTABLE=false`; wrap/unwrap is performed inside the HSM via `CKM_AES_GCM`. Security boundary: the HSM hardware.

The cantonal e-government threat model requires (3) for production. (2) is the intermediate target — same trait surface, much simpler ops than running an HSM. Vault Enterprise auto-unsealed by an HSM is a realistic stepping stone: same code path as (2), with the KEK protected by hardware behind the scenes.

What's deliberately *not* in this list:

- **Backends that fetch raw KEK material to do AES locally** (Vault KV v2, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, Kubernetes Secrets). The dev filesystem case is the one place we accept this shape — gated, not a deployment option.
- **Deliver-at-start mechanisms** (systemd-creds, Vault KV v1). Cannot serve multiple coexisting KEK versions, breaks lock-free rotation.
- **Cloud KMS as a separate backend.** Vault Transit is sufficient for the "encrypt-as-a-service" niche; if a deployment specifically requires AWS KMS / GCP KMS / Azure Managed HSM, it can be added as a fourth `KekProvider` impl using the same trait surface.

## Maturity-tier mapping

Issuer private keys are *always* stored in the RDBMS as AEAD ciphertext. What varies across maturity tiers is only where the **KEK** lives — and therefore where the AEAD operations actually happen:

| Tier               | Issuer-key storage   | KEK location                    | Wrap/unwrap happens on  | `non_exportable_kek` |
|--------------------|----------------------|---------------------------------|-------------------------|-----------------------|
| Alpha (dev)        | RDBMS ciphertext     | Filesystem (TOML, dev gating)   | Application host        | false                  |
| Beta / Intermediate | RDBMS ciphertext     | Vault Transit                   | Vault server            | true (with `exportable=false` config)   |
| Production         | RDBMS ciphertext     | HSM via PKCS#11                 | HSM                     | true                   |

Three consequences of this table:

**The encryption code path is on from alpha onward.** Ciphertext is the only shape ever written to the keystore. There are no `if maturity == prod { encrypt() }` branches; what varies is the KEK provider, not whether wrapping happens.

**The issuer's private keys always touch process memory.** When the application signs, it asks the KEK provider to unwrap a ciphertext, then signs in-process with the unwrapped bytes. The security boundary is the KEK, not the issuer key — that's why hardening focuses on KEK exportability, not issuer-key exportability.

**Production refuses to start unless `KekProvider::non_exportable_kek()` returns true.** The dev filesystem provider is gated separately to make this constraint a soft contract at construction time and a hard refusal in any non-alpha binary.

## Encryption scheme

Where we encrypt at rest (alpha through intermediate), private keys are wrapped by a symmetric **key-encryption key (KEK)** held in the deployment's orchestrator secret store. The scheme is:

- **Algorithm**: AES-256-GCM.
- **Granularity**: one symmetric KEK **per tenant**.
- **KEK location**: indexed by `tenant_id`, supplied by a `KekProvider` impl. The KEK material is never in the DB and (outside the dev tier) never on the application filesystem. The provider must support multiple KEK versions for the same tenant coexisting (see [KEK rotation](#kek-rotation) for why) and must offer `wrap`/`unwrap` operations that bind AAD. Three backends are in scope:
  - `FilesystemKekManager` — *dev only*. TOML file holding `tenant_id → { version → KEK, current = …}`. Wraps and unwraps in process. See [Dev-only filesystem KEK provider](#dev-only-filesystem-kek-provider) for the gating rules. Compiled in only with the `dev-kek-fs` cargo feature; non-alpha binaries cannot construct it.
  - `VaultTransitKekManager` — *intermediate / production-capable*. Hashicorp Vault Transit secrets engine. The KEK is created inside Vault and never leaves. Wrap/unwrap delegates to Transit's `encrypt`/`decrypt` endpoints with the AAD passed as `context`. `non_exportable_kek()` reports the configured key's `exportable` flag; production requires `exportable=false`.
  - `Pkcs11KekManager` — *production*. The KEK is a `CKO_SECRET_KEY` on the HSM with `CKA_EXTRACTABLE=false`. Wrap/unwrap uses an AAD-supporting GCM mechanism (e.g., `CKM_AES_GCM`).
  
  *Not used*: any backend that returns the raw KEK and lacks server-side AAD-bound encryption (Vault KV v2, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, Kubernetes Secrets). With the trait shifted to `wrap`/`unwrap`, fetching raw key material to do AES locally is the dev case only. Also excluded: deliver-at-start mechanisms (systemd-creds, Vault KV v1) — they cannot serve multiple coexisting versions.
- **AAD binding**: every ciphertext binds Additional Authenticated Data to `(tenant_id, issuer_id, key_role, status)`. The `status` component (`active` or `pending_next`) prevents a `pending_next` ciphertext from being silently re-interpreted as `active` by an attacker who can edit a row's status column.
- **KEK versioning**: each ciphertext row records the KEK version under which it was wrapped. Multiple versions can coexist; this is what makes per-tenant KEK rotation lock-free. See [KEK rotation](#kek-rotation) below.

### Why per-tenant rather than global

A leak of a global KEK compromises every tenant's keys at once; per-tenant contains the damage. Deleting a tenant's KEK from the orchestrator makes the tenant's key rows unreadable in old backups too — a clean cryptographic answer to "remove this tenant's data" that does not require sweeping every snapshot. KEK rotation can be staged tenant-by-tenant, or driven by an incident in one tenant, without touching the rest of the fleet. ~75 tenants × one secret each fits comfortably in any of the orchestrator secret stores listed above.

### Symmetric vs asymmetric envelope

We use a **symmetric** envelope (one AES-class KEK per tenant). An asymmetric variant (a keypair per tenant, public part used to encrypt and private part held only by the binary that signs) would split "can write encrypted private keys" from "can decrypt them" — useful if the threat model demands that the management binary never holds decryption capability. The complexity does not earn its keep at the intermediate tier; if the capability split becomes a hard requirement later, the encryption scheme can be revisited without disturbing the schema.

### KEK rotation

A tenant's KEK has to be rotated periodically — driven by a fixed cadence, by suspected compromise, or by a personnel change in the tenant's operations team. The naïve approach is to decrypt and re-encrypt every key row of the tenant in one transaction; that holds row locks across all of a tenant's signing rows and stalls live signing traffic. The keystore is designed to avoid the global-lock approach entirely.

The mechanism is **versioned KEKs**:

- The orchestrator secret store holds one or more KEK versions per tenant, indexed by version. Adding a new version is the first step of any rotation; it does not by itself touch any keystore row.
- Each ciphertext row records the version under which it was wrapped (column `kek_version`). The decrypt path looks up the matching KEK by version. The encrypt path always uses the current (newest non-retired) version.
- Re-encryption is **per-row**, not per-tenant — each row is its own micro-transaction, no global lock. Two driving mechanisms, used together:
  - **Background sweep**: a per-tenant job iterates rows whose `kek_version` is older than the current and re-encrypts them. Throttled, idempotent, restartable. Runs on the management binary, which holds the write capability for the keystore.
  - **Lazy** (optional): when the management binary signs (during a rotation flow) and reads a row whose version is stale, it re-encrypts on the fly before returning. The OIDC binary's signing path stays read-only on the keystore even in the lazy variant — only `KeyManager`-holding code paths re-encrypt.
- An old KEK version is retired (deleted from the orchestrator secret store) once no row references it. Verifiable in one query: `SELECT COUNT(*) WHERE kek_version = old_version`.

This shape extends naturally to compromise-driven rotation: the new version is added immediately, the background sweep is run at maximum throttle, and the old version is retired the moment all rows have migrated. There is no window where any row is unreadable, and no global lock at any point.

`kek_version` is **not** part of the AAD. AAD prevents misinterpretation of one identity tuple's ciphertext as another's; the KEK version is a key-management concern, not an identity concern. Including it in AAD would force every re-encryption to recompute AAD without changing what AAD protects against.

The cost of being able to read rows wrapped under a retired KEK during the migration window is that the orchestrator secret store carries a small set of "retired-but-still-needed" KEK versions per tenant for as long as the sweep takes. That window is bounded by the sweep schedule, not by the operational signing load.

### Dev-only filesystem KEK provider

For local development on a single machine, the operational ceremony of running Vault or pointing at a cloud secret manager is a friction we want to avoid. The keystore therefore admits one — and only one — KEK provider that reads from the filesystem: a TOML file holding a tenant-keyed map of versions, structured to mirror the production multi-version shape so rotation flows can be exercised locally.

This provider is **strictly for developer machines**. It is not used in CI staging tiers, not used in any deployed environment, and not a fallback for misconfigured production. The guards below make accidental production use a hard error rather than a soft drift:

- **Compile-time gate.** The impl lives behind a cargo feature `dev-kek-fs`, off by default. Production build profiles do not enable it; the type is not even reachable in the resulting binary. CI for production-target builds asserts the feature is off.
- **Construction-time refusal by tier.** Even when compiled in, the provider's constructor refuses to return a value if the binary's `MaturityTier` is anything other than `Alpha`. Returns an explicit error, never falls through silently.
- **File permission check.** Refuses to load if the file is group- or world-readable. Catches "I committed it / it landed in a shared directory" mistakes.
- **Path is explicit.** The operator passes the path via config or env var; there is no defaulted location. A missing path is an error, not a fallback to "well, maybe nothing's encrypted today."
- **Loud startup log line at WARN level**, naming the file path and tier, every time the provider is constructed. There is no silent dev mode.

File format (sketch — finalised in [`impl_key_management.md`](impl_key_management.md)):

```toml
[tenant.swiss-canton-zh]
v1 = "<32 hex bytes>"
v2 = "<32 hex bytes>"
current = "v2"
```

The provider exposes the same `KekProvider` interface as the production-grade providers; the only difference is its construction signature (it takes a file path) and its tier check.

## Schema separation

When key material lives in the DB (alpha through intermediate), isolation between key material and the rest of the data is enforced at the schema level:

- `swiyu_issuer_mgmt` — the existing v0.1.x business-data tables (tenants, issuers, credential offers, etc.).
- `swiyu_issuer_keystore` — key material only.

Both schemas live in the same database. Isolation is enforced by Postgres role grants: the application role has no privileges on `swiyu_issuer_keystore` by default. Only the role(s) used by the signing and rotation code paths hold the necessary grants on it. `sqlx migrate` runs from a single migrations directory; migration files create both schemas explicitly.

### Cross-database-portable rotation discipline

The schema split also accommodates a future deployment in which `swiyu_issuer_keystore` is moved to a separate database — for example, by a cantonal IT policy that forbids private keys in the same RDBMS instance as application data. To preserve correctness across both deployment shapes, rotation is written defensively from day one. The fixed order of a rotation:

1. **Stage** the new triple in the keystore as `pending_next`.
2. Sign the rotation log entry with the currently-active `authorized` key.
3. Submit the entry to the registry.
4. On registry acknowledgement, **commit**: in a single keystore transaction, destroy the active triple and promote `pending_next` to `active`.

An orphan `pending_next` (step 1 succeeded, step 3 didn't) is recoverable: either retry the submission, or `discard_pending` and start over. The registry never sees a public key whose private part has been destroyed before the issuer can sign with it — which would be the worse failure mode.

In the single-database deployment, steps 1 and 4 each fit inside one transaction with the matching mgmt-side bookkeeping. In the split-database deployment, steps 1 and 4 are local to the keystore DB and the mgmt-side bookkeeping happens in the other DB; the cross-DB write order is the same. Same call sites, no rewrite required to switch.

### Reconciliation after partial failure

A crash between step 3 (registry ack) and step 4 (local commit) leaves the registry advertising the new keys while the keystore still treats the old triple as active. On startup or on first signing attempt, the issuer reconciles: if the registry's latest log entry advertises an `authorized` public key that doesn't match the keystore's `active` triple, but does match `pending_next`, the issuer completes the commit before serving traffic. If neither matches, the issuer refuses to start.

### Escape hatches

These are options documented for completeness, not built today:

- **Two connection pools** with different DB roles, coordinated via a `SECURITY DEFINER` rotation function in `swiyu_issuer_keystore`. Defence in depth against SQL injection in application code reaching key rows.
- **Two separate databases**, on the same Postgres instance or on different instances. Cost: a second `DATABASE_URL`, a second migration root, a second backup pipeline. Worth paying only on an explicit policy trigger.

## Reuse of `swiyu-didtool`

The crypto primitives in `swiyu-didtool::crypto` (key generation, signing, verification, PEM serialisation for Ed25519 and ECDSA) are reused as a workspace dependency. Same key types, same algorithms, same wire format.

The `swiyu-didtool::keystore` module — the on-disk DID-keyed keystore documented in [`swiyu-didtool/specs/key-store.md`](../../swiyu-didtool/specs/key-store.md) — is **not** used by `swiyu-issuer` at runtime. It stays as the operator's local CLI tool for its own purposes (creating standalone DIDs, signing log entries by hand, etc.). `swiyu-issuer` generates keys programmatically through the management API or its bootstrap tooling.

## Signer abstraction

The signing path is abstracted by a `Signer` / `KeyManager` trait pair. Concrete Rust signatures, the keystore schema, and the DB-backed impl live in [`impl_key_management.md`](impl_key_management.md). The decisions that govern that draft:

- **One backend only: DB-backed.** Issuer private keys always live in `swiyu_issuer_keystore.signing_keys` as AEAD ciphertext, wrapped under the tenant's KEK. There is no HSM or cloud-KMS `Signer` impl — the security boundary is the KEK, hardened at the `KekProvider` layer. This shrinks the trait's polymorphism: `Signer` and `KeyManager` are concrete types, not abstract over storage.
- **Split by capability: `Signer` (read) and `KeyManager: Signer` (write).** The OIDC binary holds a `Signer`; the management binary holds a `KeyManager`. Type-level separation between "can sign" and "can mint or rotate keys"; the OIDC binary cannot accidentally generate keys even with a programming error.
- **`(tenant, issuer, role)` is the universal identity tuple at the trait surface.** No `generation` parameter — there is no historical generation to address; the trait targets the single active triple implicitly. The keystore internally tags each row with a `status` discriminator (`active` vs `pending_next`) but the application above the trait does not see it.
- **Algorithm derived from role**, not chosen by the caller. `Authorized` → EdDSA, `Authentication` and `Assertion` → ECDSA P-256 + SHA-256.
- **No `non_exportable_keys()` flag on `Signer`.** The issuer's private keys always touch process memory after KEK unwrap; the flag would always be false. The equivalent production gate moves to `KekProvider::non_exportable_kek()`.
- **`health_check()`** at boot — refuses startup if the keystore DB isn't reachable. Avoids a class of "issuer is up, signing fails on first wallet request" outages.
- **No public-key lookup on the trait.** Public keys are returned in-memory from `create_initial_triple` and `stage_rotation` for the caller to embed into the next DID log entry; they are not persisted and there is no `public_key(tenant, issuer, role)` method. The DID log in the registry is the source of truth.

## KEK abstraction

The KEK lifecycle is abstracted by a `KekProvider` / `KEKManager` trait pair, parallel to `Signer` / `KeyManager`. `KeyManager` manages a triple of private keys per issuer (always DB-backed); `KEKManager` manages multiple versions of one KEK per tenant (never DB-backed — the KEK lives outside the DB it protects). The two are independent: KEK rotation runs without issuer-key rotation, and vice versa. Concrete Rust signatures and the DB-backed `KeyManager` impl live in [`impl_key_management.md`](impl_key_management.md); per-backend `KEKManager` impls live in a separate orchestrator-specific spec.

The decisions that govern the draft:

- **Wrap/unwrap, not fetch.** The trait surface speaks `wrap(tenant, plaintext, aad) → (Ciphertext, KekVersion)` and `unwrap(tenant, version, ciphertext, aad) → plaintext`. Hardware-rooted backends (HSM, Vault Transit) can satisfy the interface without ever releasing key material; the file-based dev backend does the AES locally. There is no `fetch` method that returns raw KEK bytes — that would be unrepresentable for HSM-rooted backends.
- **AAD is always passed and always bound.** Every `wrap`/`unwrap` call carries the AAD tuple `(tenant, issuer, role, status)`. The impl is responsible for binding it to the ciphertext (via AES-GCM AAD, Vault Transit `context`, PKCS#11 `CKM_AES_GCM` AAD parameter, etc.). Backends that cannot bind AAD natively are excluded.
- **Split by capability: `KekProvider` (read: wrap/unwrap) and `KEKManager: KekProvider` (write: introduce/retire/list versions).** The OIDC binary holds a `KekProvider`; the management binary holds a `KEKManager`. Type-level separation between "can wrap and unwrap with existing versions" and "can mint, retire, or list versions."
- **`(tenant, version)` is the universal identity tuple.** Every method takes the tenant; `unwrap` takes a version explicitly; `wrap` returns the version it used (always the current one).
- **`non_exportable_kek()`** on `KekProvider` — true when the impl's KEK never leaves the trust boundary (HSM, Vault Transit with `exportable=false`). The production binary refuses to start unless it returns true.
- **No DB touch.** `KEKManager` impls talk to the orchestrator secret store directly. The keystore DB stores only the `kek_version` tag that identifies which version wrapped a row.
- **Retirement is gated by the caller, not the impl.** `retire_version` does not query the DB itself — that would couple it to the keystore. The sweep verifies, via the keystore, that no row references the old version, and only then calls `retire_version`. Splits the precondition check from the secret-store mutation.
- **`health_check()`** at boot — refuses startup if the KEK backend isn't reachable or authenticated. Parallel to `Signer::health_check`.
- **Tenant lifecycle.** `create_initial_kek` runs at tenant provisioning, alongside `swiyu_issuer_mgmt.tenants` insertion. `delete_tenant` runs at deprovisioning, after every issuer's keys have been deleted.
- **No DB-backed `KEKManager` impl.** Putting KEKs in the same DB they protect would defeat the threat model. The trait's impls live in their own module (`swiyu-issuer/src/kek/`), each talking to one orchestrator service.

## Code implications

- **Sweep takes both traits.** The re-encryption sweep is a management-binary code path that takes a `KeyManager` (to walk rows and re-`wrap`/`unwrap` them) and a `KEKManager` (to read `list_versions`, perform the wrap/unwrap calls, and ultimately call `retire_version` once the keystore-side gate clears). Throttle, batch size, and per-tenant scoping live in the sweep job's config, not in either trait.
- **KEK backend capability constraint.** Every `KekProvider` impl must (a) support multiple coexisting KEK versions per tenant, (b) offer wrap/unwrap with AAD binding, and (c) for any non-alpha tier, hold the KEK material outside the application process. Backends that ship raw KEK material to the client without server-side AAD-bound encryption (Vault KV v2, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, K8s Secrets) are excluded — the dev `FilesystemKekManager` is the only "raw KEK to local AES" exception, and it's gated.
- **AEAD AAD construction** lives in one helper so callers cannot accidentally bind the wrong identity tuple. The helper feeds the AAD into `KekProvider::wrap`/`unwrap`; impls are responsible for binding it to the ciphertext appropriately for their backend.
- **Atomic rotation** uses the four-step discipline above. The keystore admits at most one `active` row and at most one `pending_next` row per `(tenant_id, issuer_id)`; rotation is the staged transition between them.
- **Reconciliation hook** runs on startup before the issuer accepts traffic: compare the registry's latest authorized key against the keystore. Three cases — match, complete-the-commit, refuse-to-start — and a structured log line for each.
- **Production startup gate.** The production binary refuses to start unless `KekProvider::non_exportable_kek()` returns true and the registry's latest authorized key matches the keystore's active row.

## Open

- **Cantonal IT policy** on whether private keys may share an RDBMS instance with application data. The cross-database-portable rotation discipline above makes this a deployment choice rather than a code constraint, but it still affects backup and monitoring topology.
- **Concrete role grants** on `swiyu_issuer_keystore`. Which DB role holds which privileges; how the application role relates to the signing-and-rotation role.
- **KEK provisioning** for the intermediate tier — orchestrator mechanism, rotation cadence, recovery procedure.
- **KEK rotation cadence and retirement policy** — how often KEKs are rotated routinely, the maximum age of a "retired-but-still-readable" KEK version (i.e., the deadline by which the sweep must have migrated all rows off it), and the operator-facing trigger for an emergency rotation.
- **Reconciliation policy details** — which exact comparisons (current `authorized` key only, or all three roles), and whether a mismatch should ever auto-recover beyond the commit-the-pending case. Lean: minimal auto-recovery, operator-driven for everything else. Not yet locked.
- **Multi-DID / multi-algorithm posture.** Not relevant for v0.1; the `Signer` trait must not preclude it. Tracked as a constraint on the impl rather than an immediate requirement.
