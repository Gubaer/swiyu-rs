# Key management

This document records decisions and open questions about how `swiyu-issuer` generates, persists, and uses the cryptographic key material that backs its issuers' DIDs.

Status: preliminary. Direction agreed; several implementation details still open.

## Scope

Covers:

- Where private and public keys live across the project's maturity levels.
- How private keys are protected at rest.
- How key material is referenced from the rest of the data model.
- Reuse of and divergence from `swiyu-didtool`'s key handling.
- Code-level expectations on the signing path.

Does *not* cover:

- The wire-format details of `did:tdw` and `did:webvh` log entries.
- The internals of HSM provider selection — see [`aspect-persistence.md`](aspect-persistence.md) for the open question.
- Status-list signing (separate slice).

## Issuer model recap

From [`aspect-multi-tenancy.md`](aspect-multi-tenancy.md):

```
tenant 1:{0..n} issuer 1:1 did 1:{1..m} key-triple-generation
```

An issuer is identified by exactly one DID for its lifetime. The DID has one or more generations of a **key triple**, each generation recorded in the DID log. The triple's shape is fixed:

| Role             | Algorithm | Purpose                          |
|------------------|-----------|----------------------------------|
| `authorized`     | EdDSA     | Signs DID log entries            |
| `authentication` | ECDSA     | DID authentication               |
| `assertion`      | ECDSA     | Signs verifiable credentials     |

Both private and public parts of all three keys per generation are persisted (six items per generation). Public keys could be re-derived from privates at runtime; storing them makes export, inspection, and consistency checks trivial and matches the convention already in `swiyu-didtool`'s key store.

## Storage taxonomy

Four integration shapes are conceivable:

1. **Filesystem** — files we open and parse.
2. **RDBMS** — rows we `SELECT`.
3. **Software vault** — a service we RPC to (HashiCorp Vault, KeyHub, cloud KV, etc.). Secrets may be returned to us depending on the engine; the security boundary is the vault process, not hardware.
4. **HSM** — a service we RPC to with hardware-rooted non-exportability and FIPS-attested tamper resistance. May be accessed directly or fronted by a software vault that proxies to it.

`swiyu-issuer` rejects (1). It uses (2) for pre-production and intermediate maturity. (4) is the production target. (3) is permitted as an alternative to (2) at the intermediate tier and is the realistic deployment shape for (4) — a software vault fronting an HSM — but a vanilla software vault by itself does not clear the production bar.

The filesystem option (1) is the design used by `swiyu-didtool`, appropriate for a single-user CLI working on a single DID. It is explicitly **not** reused by `swiyu-issuer` because the issuer's recommended deployment shape is a fleet behind a load balancer (see [`aspect-multi-tenancy.md`](aspect-multi-tenancy.md)) and a filesystem-based key store would force a network filesystem with its own locking and latency pain. Atomic rotation across a DID log entry and a new key generation is one transaction in a DB and a coordination problem on disk; backup is a single `pg_dump` or two pipelines; migration to an HSM at the production tier only changes the `Signer` impl, not the key-reference shape stored in the DB.

The HSM (4) and software-vault (3) options are one bucket from our `Signer` implementation's perspective — both are external services we RPC to — but the spec keeps them distinct because the security contract differs. An HSM offers a hardware boundary and provable non-exportability. A vanilla software vault offers only a process boundary and weaker attestation. Realistic production deployments layer them: Vault Enterprise auto-unsealed by an HSM, cloud KMS HSM-backed. For the cantonal e-government threat model, production demands the hardware-rooted property regardless of whether a software vault sits in front.

## Maturity-tier mapping

| Tier                                       | Storage                       | Private-key column      | At-rest protection             |
|--------------------------------------------|-------------------------------|-------------------------|--------------------------------|
| Alpha / beta                               | RDBMS                         | Ciphertext (AEAD)       | Dev KEK, auto-provisioned      |
| Intermediate (RC / staging without HSM)    | RDBMS                         | Ciphertext (AEAD)       | KEK from orchestrator secret   |
| Production                                 | RDBMS, HSM key handle only    | (no private material)   | HSM hardware boundary          |

Two consequences of this table.

**The encryption code path is on from alpha onward.** Ciphertext is the only shape ever written to the keystore in the DBMS-backed tiers. There are no `if maturity == prod { encrypt() }` branches to forget; what varies across maturity is *KEK strictness*, not whether we encrypt.

**Production breaks the pattern structurally.** With an HSM the private key never enters the application or the database. The keystore row stores an opaque HSM key handle in place of the ciphertext blob. The `Signer` trait makes this transparent to the caller — alpha/beta/intermediate decrypt in-process and sign; production sends to-be-signed bytes to the HSM and receives the signature back, never touching private material.

## Encryption scheme

Where we encrypt at rest (alpha through intermediate), the scheme is:

- **Algorithm**: AES-256-GCM.
- **Granularity**: one symmetric KEK **per tenant**.
- **KEK location**: the deployment's orchestrator secret store — Kubernetes Secret, systemd-creds, AWS Secrets Manager, etc. Indexed by `tenant_id`. The KEK is never on the application filesystem and never in the DB.
- **AAD binding**: every ciphertext binds Additional Authenticated Data to `(tenant_id, issuer_id, key_role, generation)`. An encrypted blob from one identity therefore cannot be replayed under another, even if an attacker holds the KEK and access to the keystore rows.

### Why per-tenant rather than global

A leak of a global KEK compromises every tenant's keys at once; per-tenant contains the damage. Deleting a tenant's KEK from the orchestrator makes the tenant's key rows unreadable in old backups too — a clean cryptographic answer to "remove this tenant's data" that does not require sweeping every snapshot. KEK rotation can be staged tenant-by-tenant, or driven by an incident in one tenant, without touching the rest of the fleet. ~75 tenants × one secret each fits comfortably in any of the orchestrator secret stores listed above.

### Symmetric vs asymmetric envelope

We use a **symmetric** envelope (one AES-class KEK per tenant). An asymmetric variant (a keypair per tenant, public part used to encrypt and private part held only by the binary that signs) would split "can write encrypted private keys" from "can decrypt them" — useful if the threat model demands that the management binary never holds decryption capability. The complexity does not earn its keep at the intermediate tier; if the capability split becomes a hard requirement later, the encryption scheme can be revisited without disturbing the schema.

## Schema separation

When key material lives in the DB (alpha through intermediate), isolation between key material and the rest of the data is enforced at the schema level:

- `swiyu_issuer_mgmt` — the existing v0.1.x business-data tables (tenants, issuers, credential offers, etc.).
- `swiyu_issuer_keystore` — key material only.

Both schemas live in the same database. Isolation is enforced by Postgres role grants: the application role has no privileges on `swiyu_issuer_keystore` by default. Only the role(s) used by the signing and rotation code paths hold the necessary grants on it. `sqlx migrate` runs from a single migrations directory; migration files create both schemas explicitly.

### Cross-database-portable rotation discipline

The schema split also accommodates a future deployment in which `swiyu_issuer_keystore` is moved to a separate database — for example, by a cantonal IT policy that forbids private keys in the same RDBMS instance as application data. To preserve correctness across both deployment shapes, rotation and issuer-creation are written defensively from day one:

- Write order: **keystore first**, then `swiyu_issuer_mgmt`. An orphan key generation (write 1 succeeded, write 2 didn't) is recoverable by re-attempting the log entry write idempotently. The reverse order risks the DID log advertising public keys we have no private parts for, which is the worse failure mode.
- Idempotent retry on partial failure.

In the single-database deployment the same code commits both writes inside one transaction and the retry path is dead. In the split-database deployment the retry path lights up. Same call sites, no rewrite required to switch.

### Escape hatches

These are options documented for completeness, not built today:

- **Two connection pools** with different DB roles, coordinated via a `SECURITY DEFINER` rotation function in `swiyu_issuer_keystore`. Defence in depth against SQL injection in application code reaching key rows.
- **Two separate databases**, on the same Postgres instance or on different instances. Cost: a second `DATABASE_URL`, a second migration root, a second backup pipeline. Worth paying only on an explicit policy trigger.

## Reuse of `swiyu-didtool`

The crypto primitives in `swiyu-didtool::crypto` (key generation, signing, verification, PEM serialisation for Ed25519 and ECDSA) are reused as a workspace dependency. Same key types, same algorithms, same wire format.

The `swiyu-didtool::keystore` module — the on-disk DID-keyed keystore documented in [`swiyu-didtool/specs/key-store.md`](../../swiyu-didtool/specs/key-store.md) — is **not** used by `swiyu-issuer` at runtime. It stays as the operator's local CLI tool for its own purposes (creating standalone DIDs, signing log entries by hand, etc.). `swiyu-issuer` generates keys programmatically through the management API or its bootstrap tooling.

## Signer abstraction

The signing path is abstracted by a `Signer` / `KeyManager` trait pair. Concrete Rust signatures, supporting types, the keystore schema, and per-backend mappings live in [`impl_key_management.md`](impl_key_management.md). The decisions that govern that draft:

- **Operation-centric, not protocol-shaped.** The trait surface speaks `sign`, `public_key`, and `generate_key_triple`. PKCS#11 vocabulary (sessions, slots, mechanisms, attributes), cloud-KMS vocabulary (key IDs, signing-algorithm enums), and DB-backed vocabulary (rows, ciphertext, AAD) all stay inside their respective impls. Mirroring PKCS#11 upward would push ceremony into the wrong layer; translating to it at the impl boundary is the right shape.
- **Split by capability: `Signer` (read) and `KeyManager: Signer` (write).** The OIDC binary holds a `Signer`; the management binary holds a `KeyManager`. Type-level separation between "can sign" and "can mint keys"; the OIDC binary cannot accidentally generate keys even with a programming error.
- **`(tenant, issuer, role, generation)` is the universal identity tuple.** PKCS#11 stores it as `CKA_ID` / `CKA_LABEL`, cloud KMS as tags or aliases, the DB-backed impl as primary key and AEAD AAD. Same tuple, three different physical layouts.
- **Algorithm derived from role**, not chosen by the caller. `Authorized` → EdDSA, `Authentication` and `Assertion` → ECDSA P-256 + SHA-256.
- **Capability flag `non_exportable_keys()`** on the trait — true only when the impl guarantees private-key material never leaves the trust boundary (hardware for HSM impls, process memory for DB-backed impls). The production binary refuses to start unless its `Signer` returns true.
- **`health_check()`** at boot — refuses startup if the backend isn't reachable or authenticated. Avoids a class of "issuer is up, signing fails on first wallet request" outages.
- **No filesystem `Signer` impl.** The `swiyu-didtool` filesystem keystore stays as operator tooling, not a `swiyu-issuer` production code path.

## Code implications

- **KEK fetch** is a per-request lookup keyed by `tenant_id`, delegated to a small `kek_provider` interface so the orchestrator mechanism (env var, Kubernetes API, AWS Secrets Manager, …) can be swapped without touching the signing path.
- **AEAD AAD construction** lives in one helper so callers cannot accidentally bind the wrong identity tuple.
- **Atomic rotation** uses the cross-database-portable discipline above, even in single-database deployments, so no rewrite is needed when the deployment changes.

## Open

- **Cantonal IT policy** on whether private keys may share an RDBMS instance with application data. The cross-database-portable rotation discipline above makes this a deployment choice rather than a code constraint, but it still affects backup and monitoring topology.
- **Concrete role grants** on `swiyu_issuer_keystore`. Which DB role holds which privileges; how the application role relates to the signing-and-rotation role.
- **KEK provisioning** for the intermediate tier — orchestrator mechanism, rotation cadence, recovery procedure.
- **Where DID log entries live.** Lean: `swiyu_issuer_mgmt` (the DID document is public data). Not yet locked.
- **Multi-DID / multi-algorithm posture.** Not relevant for v0.1; the `Signer` trait must not preclude it. Tracked as a constraint on the impl rather than an immediate requirement.
