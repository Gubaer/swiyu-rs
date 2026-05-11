# Persistence

This document captures decisions and open questions about how `swiyu-issuer` persists data and key material across releases.

Status: preliminary. Direction agreed; details still open.

## Vocabulary

Two terms that the rest of this document depends on.

**Maturity level** — the qualitative classification of where the codebase is in its lifecycle: `alpha`, `beta`, `production`. Possibly `rc` between beta and production, if useful. This is the axis that drives the persistence rules.

**Release** — a specific named artifact: alpha-1, beta-2, prod-1, prod-2, …. Each release sits at one maturity level. Once at production maturity, every successive release is an iteration within the same maturity level.

Persistence rules attach to **maturity level transitions**, especially the boundary between pre-production and production maturity. Release transitions within production maturity are routine and governed by migration discipline rather than by changes to the persistence rules.

## Persistence concepts

`swiyu-issuer` recognises two persistence concepts:

| Concept                  | Pre-production maturity                | Production maturity                                            |
|--------------------------|----------------------------------------|----------------------------------------------------------------|
| Structured business data | DBMS                                   | DBMS                                                           |
| Key material             | DBMS (plaintext; dev / test only)      | External KMS (HashiCorp Vault Transit today, canton-operated HSM-backed KMS later) |

The DBMS-backed code path is the same across maturity levels; only configuration differs. The signing path has a real fork and abstracts over the backend (see Code implications). For the full key-management model see [`aspect-key-management.md`](aspect-key-management.md).

## Structured business data

All business-data sub-categories live in the same DBMS in the initial release. Each sub-category has a specific performance or retention signal that would trigger reconsidering its backend; none of those signals applies today.

### Configuration data (cold)

Tenants, admin users, API tokens (hashed), per-tenant SWIYU OAuth2 credentials (client id, client secret, refresh token), issuers, issuer DIDs and their Trust Statement references, credential type configurations, and branding. Low write rate, low volume, frequently read. Reconsider only if the catalogue grows enough to make these tables hot — not a realistic horizon for the cantonal target scenario.

The OAuth2 client secret and refresh token live as plaintext text on the `tenants` row: they are recurring runtime credentials the worker rotates on every successful refresh-token grant, not one-shot bearer tokens. See [`aspect-oauth2.md`](aspect-oauth2.md) for the rotation model.

### Issuance data (warm)

Credential offers, issued-credential records, revocation/suspension state. Moderate write rate during issuance bursts; bounded retention. Reconsider only if write volume saturates the DBMS, well past the volumes implied by the target scenario.

### Status list bitstrings

One row per status list per issuer, with the bitstring as `bytea` and publish-state columns (committed version, published version, last attempt). The signed status-list credential is published to the SWIYU status registry on each change; only a registry pointer is stored on the row — the signed artifact itself is not persisted by `swiyu-issuer`, and there is no public status-list endpoint hosted here.

Bit flips happen inside the same transaction as the credential issuance or revocation; concurrency is the DBMS's problem.

### Worker queue state

Asynchronous worker operations — currently `create_issuer`, `rotate_keys`, `deactivate_issuer` — are queued as `operation_tasks` rows. Each row carries task type, lifecycle state, retry counter, next-attempt timestamp, and a JSONB step payload. Moderate write rate while a task is active (state transitions, attempt updates); rows persist after completion as an operational trace. See [`aspect-issuer.md`](aspect-issuer.md) and [`impl-issuer.md`](impl-issuer.md) for the worker flow. Reconsider partitioning or a dedicated queue only if task throughput saturates the table.

### Hot / ephemeral state

OIDC pre-authorised codes, transaction codes, nonces, in-flight wallet sessions. Implemented as several focused tables (`oidc_access_tokens`, `oidc_nonces`, with transaction codes to follow), not a single table with a kind discriminator — the trade-off favours clearer schema and per-table indexing over generality.

Every row carries an `expires_at`. A periodic-cleanup sweeper (pg_cron, an external sweeper, or a Postgres background worker) is planned but not yet implemented; expired rows currently accumulate until the surrounding flow ignores them on read.

One-shot secrets are stored **hashed**, never as plaintext, with one named exception. Access tokens, `c_nonce`s, and (when they land) transaction codes follow the rule: only `SHA-256(secret)` is on disk, indexed lookup is by hash, and the bare value lives outside the database.

The exception is the **OID4VCI pre-authorised code**. Its by-reference issuance flow forces the bare value to be retrievable at request time: the wallet fetches `/credential-offer/{offer_id}` and the response body must include the bare code. The code therefore lives on the `credential_offers` row in a nullable `pre_auth_code` column during the offer's pending window, and is set to `NULL` at the first terminal-state transition (cancel or issue). The exposure is bounded by the offer's `expires_at` (≤ 1 hour by config). A separate "bridge" table was tried first; it added structural complexity without narrowing the leak surface, since both the row and the bridge sat in the same database with the same access pattern.

Higher write/delete churn than configuration or issuance data, so vacuum/autovacuum behaviour is worth watching.

Reconsider on contention under issuance bursts or vacuum bloat. Escalation path: `UNLOGGED` Postgres tables, then partitioning by hour or day, then a separate cache (Redis or similar) — only when the preceding step has been shown insufficient.

### Audit log (planned)

Not yet implemented. The intended shape: append-only. No `UPDATE` / `DELETE` in normal operation; cleanup only via a retention policy. Schema captures: tenant, issuer (nullable for tenant-level events), actor kind and id, action, target kind and id, timestamp, and a JSONB details payload for the variable bits.

Indexed for the expected query pattern (probably `(tenant_id, occurred_at)`). Partitioning by month is the obvious lever if the table grows large under long retention.

Forwarding to a WORM store, SIEM, or central cantonal audit trail is a later decision; the DBMS-backed log does not preclude any of those (logical replication, batch export, or change-data-capture are all standard from Postgres).

## Key material

Key material is the only persistence concept with a maturity-level fork. The full model lives in [`aspect-key-management.md`](aspect-key-management.md); this section records only what the persistence layer needs to know.

### Pre-production maturity (alpha, beta)

Private keys are stored as plaintext `bytea` rows in a dev keystore table — fine while data is throwaway and the DBMS is not exposed beyond development. AEAD-wrapping with a per-tenant KEK (Kubernetes Secret, systemd-creds, …) is a possible intermediate step before KMS adoption but is not implemented today. The filesystem-based keystore from `swiyu-didtool` is **not** used at runtime by `swiyu-issuer`.

### Production maturity (prod-1 onwards)

Keys live in an external KMS — HashiCorp Vault Transit today, with the canton's HSM-backed KMS available as a future swap. The issuer row holds opaque key references; no private material enters the application or the database. Signing is performed by sending the to-be-signed bytes to the KMS and receiving the signature back.

### Pre-production → production transition

KMS-backed keys are non-exportable by policy. The transition is therefore not a migration of keys *into* the KMS; it is a **key rotation**:

1. For each active issuer, generate a new key triple in the KMS.
2. Append a new generation to the issuer's DID log (a `did:tdw` log entry or equivalent for `did:webvh`) that publishes the new public keys and retires the old ones.
3. From this point on the issuer signs only with the KMS-backed keys.

A fresh issuer that never had a pre-production presence skips the rotation entirely and starts on KMS-generated keys.

A single deployment may legitimately hold a mix of DB-backed and KMS-backed issuers during the transition window.

## Maturity level rules

### Through alpha and beta

- Data is throwaway. Schema can change freely; migrations may simply drop and recreate.
- Keys live in the dev keystore table as plaintext `bytea`. Throwaway.
- Audit log is debug noise; no retention obligation.
- PII rules do not bite (no real subjects).

### Transition to production maturity

By the time prod-1 ships, these have to be settled and exercised:

- DBMS engine choice. Switching after prod-1 is painful and is not planned for.
- Migration tooling and discipline: forward-only, backward-compatible additions, deprecation period before removals.
- Backup and restore procedures, exercised end-to-end at least once.
- KMS keys generated for every active issuer; the previous DB-stored keys retired via DID rotation.
- Audit log retention rules, agreed with the canton.
- PII handling rules.

### Release transitions within production

prod-N to prod-N+1, possibly months or years apart, is a routine operation:

- Forward-only schema migrations. No destructive resets.
- Migrations must handle large version jumps cleanly (a node going from prod-3 to prod-5 may step through prod-4 migrations).
- Backups taken on an earlier release must be restorable on the current release; backup format compatibility is a real concern.
- Down-migration support is a separate decision; default position is forward-only with no rollback.

## Code implications

- **DBMS access** is the same across all maturity levels. No conditional code path on maturity.
- **Signing path** abstracts over the key backend through the `SigningEngine` trait. Two implementations today: `DevSigningEngine` (DB-backed, alpha/beta) and `VaultSigningEngine` (KMS-backed, production). Selection is per deployment configuration, possibly per issuer during the DB-backed → KMS transition window.
- **Key references** stored on issuer records are abstract enough to refer to either a DB-backed dev keystore row or a KMS key handle; the signer interprets the reference.

## Open questions

- **PostgreSQL operational constraints.** Any cantonal IT constraints affecting Postgres deployment (preferred vendors, in-house DBaaS, version pinning)? The engine itself is decided in [`aspect-technology.md`](aspect-technology.md).
- **Canton-side KMS / HSM provider.** Today's production backend is HashiCorp Vault Transit; the canton's eventual KMS or HSM-backed KMS may speak a different protocol (PKCS#11, KMIP, vendor SDK, …) and affects how key references are encoded on issuer records.
- **Audit log retention.** Exact retention period(s), driven by legal requirements rather than engineering.
- **Down-migration support.** Default position is forward-only; whether to invest in down-migrations needs an operational decision.
