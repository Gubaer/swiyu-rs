# Persistence

This document captures decisions and open questions about how
`swiyu-issuer` persists data and key material across releases.

Status: preliminary. Direction agreed; details still open.

## Vocabulary

Two terms that the rest of this document depends on.

**Maturity level** — the qualitative classification of where the
codebase is in its lifecycle: `alpha`, `beta`, `production`. Possibly
`rc` between beta and production, if useful. This is the axis that
drives the persistence rules.

**Release** — a specific named artifact: alpha-1, beta-2, prod-1,
prod-2, …. Each release sits at one maturity level. Once at production
maturity, every successive release is an iteration within the same
maturity level.

Persistence rules attach to **maturity level transitions**, especially
the boundary between pre-production and production maturity. Release
transitions within production maturity are routine and governed by
migration discipline rather than by changes to the persistence rules.

## Persistence concepts

`swiyu-issuer` recognises two persistence concepts:

| Concept                  | Pre-production maturity | Production maturity |
|--------------------------|-------------------------|---------------------|
| Structured business data | DBMS                    | DBMS (same)         |
| Key material             | local filesystem        | HSM                 |

The DBMS-backed code path is the same across maturity levels; only
configuration differs. The signing path has a real fork and abstracts
over the backend (see Code implications).

## Structured business data

All business-data sub-categories live in the same DBMS in the initial
release. Each sub-category has a specific performance or retention
signal that would trigger reconsidering its backend; none of those
signals applies today.

### Configuration data (cold)

Tenants, admin users, API tokens (hashed), issuers, issuer DIDs and
their Trust Statement references, credential type configurations, and
branding. Low write rate, low volume, frequently read. Reconsider only
if the catalogue grows enough to make these tables hot — not a
realistic horizon for the cantonal target scenario.

### Issuance data (warm)

Credential offers, issued-credential records, revocation/suspension
state. Moderate write rate during issuance bursts; bounded retention.
Reconsider only if write volume saturates the DBMS, well past the
volumes implied by the target scenario.

### Status list bitstrings

One row per status list per issuer, with the bitstring as `bytea` and
a version/last-updated stamp. The signed status-list credential (what
the wallet fetches at the well-known URL) is regenerated on each
change and stored alongside, or cached in front of the DB.

Bit flips happen inside the same transaction as the credential
issuance or revocation; concurrency is the DBMS's problem.

Footprint is small: a standard 131 072-bit BitstringStatusList is
16 KB pre-compression.

Reconsider on read latency at the public status-list endpoint under
wallet fan-out (every wallet checking status during verification can
hammer it). The first response is usually a CDN in front of the
existing endpoint, not a different backend.

### Hot / ephemeral state

OIDC pre-authorised codes, transaction codes, nonces, in-flight wallet
sessions. Whether this is a single `oidc_ephemeral` table with a kind
discriminator or several focused tables is a design-level decision
later.

Every row carries an `expires_at`; expired rows are removed by a
periodic cleanup (pg_cron, an external sweeper, or a Postgres
background worker).

One-shot secrets are stored **hashed**, never as plaintext, with one
named exception. Access tokens, `c_nonce`s, and (when they land)
transaction codes follow the rule: only `SHA-256(secret)` is on disk,
indexed lookup is by hash, and the bare value lives outside the
database.

The exception is the **OID4VCI pre-authorised code**. Its by-reference
issuance flow forces the bare value to be retrievable at request
time: the wallet fetches `/credential-offer/{offer_id}` and the
response body must include the bare code. The code therefore lives on
the `credential_offers` row in a nullable `pre_auth_code` column
during the offer's pending window, and is set to `NULL` at the first
terminal-state transition (cancel or issue). The exposure is bounded
by the offer's `expires_at` (≤ 1 hour by config). A separate "bridge"
table was tried first; it added structural complexity without
narrowing the leak surface, since both the row and the bridge sat in
the same database with the same access pattern.

Higher write/delete churn than configuration or issuance data, so
vacuum/autovacuum behaviour is worth watching.

Reconsider on contention under issuance bursts or vacuum bloat.
Escalation path: `UNLOGGED` Postgres tables, then partitioning by
hour or day, then a separate cache (Redis or similar) — only when
the preceding step has been shown insufficient.

### Audit log

Append-only. No `UPDATE` / `DELETE` in normal operation; cleanup only
via a retention policy. Schema captures: tenant, issuer (nullable for
tenant-level events), actor kind and id, action, target kind and id,
timestamp, and a JSONB details payload for the variable bits.

Indexed for the expected query pattern (probably
`(tenant_id, occurred_at)`). Partitioning by month is the obvious
lever if the table grows large under long retention.

Forwarding to a WORM store, SIEM, or central cantonal audit trail is
a later decision; the DBMS-backed log does not preclude any of those
(logical replication, batch export, or change-data-capture are all
standard from Postgres).

## Key material

Key material is the only persistence concept with a maturity-level
fork.

### Pre-production maturity (alpha, beta)

Keys are generated and stored on the local filesystem of the
deploying machine. Format and location follow the conventions already
established in `swiyu-didtool`'s key store, with the adjustments needed
for a multi-tenant, multi-issuer setting.

This is acceptable because pre-production releases have no real
subjects, no real residents' data, and no live Trust Statements. The
material is throwaway.

### Production maturity (prod-1 onwards)

Keys live in an HSM (or HSM-backed KMS) operated by the canton.
Whether the issuer process holds raw keys for the duration of a
request or always signs via the HSM is an open question, but in
either case the long-lived material never leaves the HSM.

### Pre-production → production transition

HSM keys are typically non-exportable by policy. The transition is
therefore not a migration of keys *into* the HSM; it is a **key
rotation**:

1. Generate a new key pair in the HSM for each active issuer DID.
2. Add the new public key to the DID document via a `did:tdw` log
   entry (or equivalent for `did:webvh`).
3. Retire the old on-disk key in the same or the following log entry.
4. From this point on the issuer signs only with the HSM-backed key.

A fresh issuer that never had a pre-production presence skips the
rotation entirely and starts on HSM-generated keys.

A single deployment may legitimately hold a mix of on-disk and
HSM-backed issuers during the transition window.

## Maturity level rules

### Through alpha and beta

- Data is throwaway. Schema can change freely; migrations may simply
  drop and recreate.
- Keys on disk.
- Audit log is debug noise; no retention obligation.
- PII rules do not bite (no real subjects).

### Transition to production maturity

By the time prod-1 ships, these have to be settled and exercised:

- DBMS engine choice. Switching after prod-1 is painful and is not
  planned for.
- Migration tooling and discipline: forward-only, backward-compatible
  additions, deprecation period before removals.
- Backup and restore procedures, exercised end-to-end at least once.
- HSM keys generated for every active issuer; original on-disk keys
  retired via DID rotation.
- Audit log retention rules, agreed with the canton.
- PII handling rules.

### Release transitions within production

prod-N to prod-N+1, possibly months or years apart, is a routine
operation:

- Forward-only schema migrations. No destructive resets.
- Migrations must handle large version jumps cleanly (a node going
  from prod-3 to prod-5 may step through prod-4 migrations).
- Backups taken on an earlier release must be restorable on the
  current release; backup format compatibility is a real concern.
- Down-migration support is a separate decision; default position is
  forward-only with no rollback.

## Code implications

- **DBMS access** is the same across all maturity levels. No
  conditional code path on maturity.
- **Signing path** abstracts over the key backend. A single trait (or
  equivalent abstraction) with two implementations: filesystem and
  HSM. Selection is per deployment configuration, possibly per issuer
  during the on-disk → HSM transition window.
- **Key references** stored in issuer / DID records are abstract
  enough to refer to either an on-disk key file or an HSM key handle;
  the signer interprets the reference.

## Open questions

- **PostgreSQL operational constraints.** Any cantonal IT constraints
  affecting Postgres deployment (preferred vendors, in-house DBaaS,
  version pinning)? The engine itself is decided in
  [`aspect-technology.md`](aspect-technology.md).
- **Hot/ephemeral schema.** One table with a kind discriminator vs.
  several focused tables.
- **HSM provider on the canton side.** Affects how key references are
  encoded in issuer / DID records and which signing protocol the
  signer abstraction speaks (PKCS#11, KMIP, vendor SDK, …).
- **Audit log retention.** Exact retention period(s), driven by legal
  requirements rather than engineering.
- **Down-migration support.** Default position is forward-only;
  whether to invest in down-migrations needs an operational decision.
- **What to store of an issued credential.** Full signed compact JWT
  vs. claims + status-list pointer + issuance metadata only.
