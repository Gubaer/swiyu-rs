# Aspect: Credential Management

This document captures the credential-management concept: what an issued credential is in the issuer's domain, its lifecycle, and what `swiyu-issuer` persists about it after issuance. For terminology around `CredentialType`, `CredentialOffer`, and the type/configuration/schema split, see [`aspect-domain.md`](aspect-domain.md). For the issuer that mints the credential, see [`aspect-issuer.md`](aspect-issuer.md). For status-list bitstring storage, see [`aspect-persistence.md`](aspect-persistence.md).

Status: preliminary; living document.

## Scope

This aspect covers the **issued-credential side** of the issuer: what `swiyu-issuer` records about a credential it has signed and handed to a wallet, and how that record is mutated through the credential's working life (suspend, revoke, expire).

Out of scope here:

- The pre-issuance pipeline — credential offers, pre-authorisation codes, wallet pickup. See `domain::credential_offer` and [`aspect-domain.md`](aspect-domain.md).
- The OID4VCI wire format and proof-of-possession verification. See [`impl_api_oidc.md`](impl_api_oidc.md).
- The mechanics of constructing the status-list token (`SwissTokenStatusList-1.0`, layered on the IETF Token Status List draft) and publishing it to the SWIYU Status Registry. The status list as **storage** is in [`aspect-persistence.md`](aspect-persistence.md); its construction and signing is an implementation concern referenced from the lifecycle operations below.

## Domain entity: `IssuedCredential`

`IssuedCredential` is the domain record `swiyu-issuer` keeps for every credential it has minted. Every `IssuedCredential` originates from exactly one `CredentialOffer`, and a `CredentialOffer` produces **at most one** `IssuedCredential` — none if the offer is cancelled or expires before the wallet picks it up. The cardinality is recorded in [`aspect-domain.md`](aspect-domain.md) as `CredentialOffer → IssuedCredential: 1:{0..1}`.

The record exists from the moment issuance succeeds (the wallet has called the OID4VCI `/credential` endpoint and received a signed SD-JWT VC) until retention policy removes it. Its state evolves independently of the originating offer once issuance is complete.

## What is persisted, what is not

`swiyu-issuer` stores **metadata only**, not the issued credential itself.

What is persisted:

- `IssuedCredentialId`, `TenantId`, `IssuerId`, originating `CredentialOfferId`.
- `vct` — copied from the originating `CredentialType` so queries do not have to join, and so later edits to the type row do not retroactively change what an existing credential reads as.
- Holder binding: the JWK thumbprint (RFC 7638) of the wallet's `cnf` key, stored as `holder_key_jkt`. The full key is not retained — the thumbprint is enough to correlate later presentations and audit trails without keeping key material the issuer has no further use for.
- Status-list reference: `(status_list_id, status_list_index)`. The bit(s) at that index in the named list encode the credential's revocation/suspension state.
- Timestamps: `issued_at`, `expires_at`. `expires_at` is the value of the SD-JWT VC's `exp` claim; it is copied here for housekeeping queries (see *Expiry is a view, not a state* below).
- Lifecycle state: `active` | `suspended` | `revoked`.
- `integrity_hash` — `SHA-256` over the exact bytes the issuer handed back to the wallet (the SD-JWT VC compact serialisation, including disclosures and any KB-JWT placeholder separator the issuer included). This is the only trace of the credential's actual bytes that `swiyu-issuer` keeps.

What is **not** persisted:

- The signed SD-JWT VC itself. Once handed to the wallet, the issuer has no need to replay it; verifiers fetch the issuer's public keys from the DIDLog and validate against those.
- The credential's claims. The validated claim values lived briefly on the originating `CredentialOffer` and are removed when the offer transitions to `Issued`. Keeping them on the `IssuedCredential` would re-introduce the PII the issuer is trying not to retain.
- The wallet's full `cnf` key — only its `jkt`.
- The KB-JWT or any presentation-time artefact. Issuance never sees these.

This resolves the open item in [`aspect-persistence.md`](aspect-persistence.md): *"What to store of an issued credential."* — claims-and-pointer plus integrity hash, not the full JWT.

The `integrity_hash` exists to answer one question: *"is this signed credential something we actually issued?"* Given a presented SD-JWT VC and the matching `IssuedCredentialId` (resolved through the status-list pointer or another correlation path), recomputing `SHA-256` over the compact serialisation either matches the stored hash or it does not. That suffices for dispute resolution and forensics without retaining the bytes themselves.

## Lifecycle states

- `active` — the default state at issuance. The status-list bit at `(status_list_id, status_list_index)` reads as valid.
- `suspended` — the credential is temporarily not honoured. Reversible. The status-list bit reads as suspended.
- `revoked` — terminal. The credential is permanently not honoured. The status-list bit reads as revoked.

Transitions:

- `active ↔ suspended` — both directions allowed.
- `active → revoked` — terminal.
- `suspended → revoked` — terminal.

There is no transition out of `revoked`. Once revoked, the row stays in state `revoked` until retention removes it; the status-list bit stays set for as long as the row exists.

## Expiry is a view, not a state

Expiry is enforced by **verifiers**, against the SD-JWT VC's `exp` claim. The wallet presents, the verifier checks `exp` against the current clock and rejects an expired credential. The issuer does not need a status-list bit for expiry — the credential carries its own clock.

`swiyu-issuer` therefore does not store `expired` as a lifecycle state. It stores `expires_at` for housekeeping: management-API responses derive an `expired` view label when `now() > expires_at`; retention sweeps may use it; metrics may count it. None of this affects what the verifier sees, which depends only on the signed `exp` claim and the status-list bit.

## Lifecycle operations

Each lifecycle operation has two effects: a local state change on the `IssuedCredential` row, and a bit update on the issuer's status list. Both happen in the same database transaction; the signed status-list credential (the wallet-facing artefact at the well-known URL) is regenerated as a follow-up step described under *Status-list integration* below.

### Issue

1. The OID4VCI `/credential` handler validates the wallet's proof of possession and the originating `CredentialOffer`.
2. The signing engine produces the signed SD-JWT VC.
3. A status-list bit index is allocated for this issuer (see *Status-list integration* for the allocation policy). The bit at the allocated index is `valid` by construction.
4. The `IssuedCredential` row is inserted with state `active`, the allocated `(status_list_id, status_list_index)`, the holder binding `jkt`, the `integrity_hash` of the signed credential, and the timestamps. The originating `CredentialOffer` transitions to `Issued` in the same transaction.
5. The signed credential is returned to the wallet.

A failure between steps 2 and 4 is the same as any issuance failure: the offer remains pending (or expires), no `IssuedCredential` row exists, no status-list index is allocated.

### Suspend / unsuspend

1. The management API resolves the `IssuedCredential` by id, scoped to the calling tenant.
2. State precondition: `active` for suspend, `suspended` for unsuspend. Any other state returns a typed error.
3. Update the row's state and flip the status-list bit (`suspended` ↔ `valid`) in one transaction.
4. Trigger regeneration of the signed status-list credential.

### Revoke

1. The management API resolves the `IssuedCredential` by id, scoped to the calling tenant.
2. State precondition: `active` or `suspended`. State `revoked` returns a typed error — `revoke` is **not** silently idempotent at the API boundary, so unexpected double-revocation surfaces rather than being swallowed.
3. Update the row's state to `revoked` and set the status-list bit to `revoked` in one transaction.
4. Trigger regeneration of the signed status-list credential.

Revocation is one-way; there is no `unrevoke`.

### Operations on credentials of a deactivated issuer

When an issuer is `deactivated` per [`aspect-issuer.md`](aspect-issuer.md), its **existing issued credentials remain manageable**: suspend, unsuspend, and revoke are all still allowed. The credentials are still in circulation, the holder may still present them, and the status-list endpoint still serves the issuer's list. The issuer's signing key triple is retained on deactivation specifically to keep producing fresh signed status-list credentials. Issuing *new* credentials from a deactivated issuer is not allowed; that gate sits on the issuance path, not on the lifecycle operations described here.

## Status-list integration

The mechanics of the Token Status List token — bitstring layout, signing, publication to the SWIYU Status Registry — are implementation concerns. This aspect fixes only the contract that the lifecycle operations rely on. The wire format is `SwissTokenStatusList-1.0`, layered on the IETF Token Status List draft; the SD-JWT VC's `status.status_list` pointer carries that type tag verbatim.

**Bit allocation.** Each issuer owns one or more status-list instances. At issuance, an unused index in the issuer's current list is allocated to the new credential. When a list reaches its entry capacity (fixed at the implementation level), a new list is provisioned and subsequent issuances allocate from it. Indices are not reused — once a credential has been bound to `(status_list_id, status_list_index)`, that index stays bound for as long as the row exists, and is not handed out to a different credential even after revocation.

**Bit encoding.** A single status list per issuer carries both `revoked` and `suspended` for each credential, using two bits per credential per the SWIYU profile. The alternative — one list per status purpose, served at parallel endpoints — is heavier on bookkeeping without changing what verifiers see end to end. Lean is the combined list; exact bit-width and on-the-wire encoding lands in the implementation spec.

**Published status-list credential.** The wallet-facing artefact is the *signed* status-list credential, hosted by the **SWIYU Status Registry**. `swiyu-issuer` does not itself serve the wrapper at a well-known URL; verifiers fetch it from the Registry. After every committed bit update, `swiyu-issuer` regenerates and re-signs the wrapper from the current bitstring and publishes it to the Registry. Multiple bit updates that arrive between publishes are naturally coalesced — each publish carries a snapshot of the latest bitstring, not a delta stream — so a burst of revocations produces at most one publish round.

## Asynchronous execution

The credential-management lifecycle operations — `suspend`, `unsuspend`, `revoke` — split into two phases with different consistency stories.

**Phase 1: local commit (synchronous).** The `IssuedCredential` row state change and the status-list bit update happen in one local transaction within the API request. The handler returns success once this transaction is committed. From the BA's perspective, the operation succeeded: `swiyu-issuer`'s admin views, audit log, and management API all reflect the new state immediately.

**Phase 2: publish to the Status Registry (asynchronous).** The signed status-list credential is republished to the SWIYU Status Registry by a background worker. The Status Registry is an external dependency that can be unavailable for minutes or hours during maintenance windows or outages — the same constraint that drives the `operation_task` model in [`aspect-issuer.md`](aspect-issuer.md) for the Identifier Registry. Holding the BA's HTTP request open for the publish round is not viable.

The publish worker uses the same retry discipline as the issuer-lifecycle worker: exponential backoff with jitter, capped at a maximum elapsed wall-clock duration (~24 hours). Retryable failures are HTTP `5xx`, transport errors, and `429 Too Many Requests`; any other Registry response moves the publish attempt to a terminal `failed` state and raises an operational alert. Bit updates that arrive while a publish is pending are coalesced into the next publish, since the wrapper always carries a snapshot of the latest bitstring.

**Visibility to verifiers lags local commit.** Between phase 1 commit and phase 2 publish, verifiers reading the Status Registry see the *previous* status-list snapshot — a revoked credential remains presentable until the publish round completes. This window is a real consequence of the architecture, not an artefact to paper over with synthetic synchrony in the API. It compounds with verifier-side cache TTLs (see *Open*).

**No BA-facing task id in v0.1.0.** Unlike issuer-lifecycle operations, credential lifecycle operations do not return a `task_id` for the BA to poll. The BA receives a synchronous "succeeded" response that reflects the local state only. Operational visibility into publish lag — last-published-at per status list, pending-publish backlog, last-publish error — is exposed through metrics and a management-API status-list view, not through per-operation tasks. If a future use case needs the BA to confirm publish completion before proceeding, the existing `operation_task` machinery is the path of least resistance.

## Tenant and issuer ownership

Each `IssuedCredential` belongs to exactly one issuer, and transitively to that issuer's tenant. The relationships:

- `Issuer → IssuedCredential`: 1:n.
- `Tenant → IssuedCredential`: 1:n through the issuer.

Operations on an `IssuedCredential` require the caller to authenticate as a principal that resolves to the owning tenant. Cross-tenant access — including read — returns the same `404` as a missing credential, per the multi-tenancy convention in [`aspect-multi-tenancy.md`](aspect-multi-tenancy.md).

## Audit trail

Every lifecycle operation is appended to the audit log defined in [`aspect-persistence.md`](aspect-persistence.md) § "Audit log":

- `tenant_id`, `issuer_id`, the actor (BA principal id), the action (`issue`, `suspend`, `unsuspend`, `revoke`), the target (`IssuedCredentialId`), the timestamp.
- The JSONB details payload carries the state transition (`from` → `to`) and, for `revoke`, the optional reason once reasons are modelled (see *Open* below).

Issuance events are recorded by the OID4VCI handler at the same point the `IssuedCredential` row is inserted; lifecycle events by the management-API handler in the same transaction as the row update.

## Open

- **Revocation reasons.** Whether `revoke` carries a typed reason (`compromised`, `superseded`, `holder_request`, `administrative`, …), a free-text note, both, or neither. Open until a real management-API consumer asks. The Token Status List draft itself reserves bit patterns and supports an extension surface for application-defined status semantics; whether to expose ours that way is part of the same decision.
- **Holder-initiated revocation.** Today only the BA can suspend or revoke. Whether the holder gets a wallet-side or out-of-band channel to request revocation of their own credential (lost device, identity theft) is not modelled. v0.1.0 does not commit to one.
- **Retention of `revoked` and post-`expires_at` rows.** Whether `IssuedCredential` rows are kept indefinitely after revocation/expiry, kept for a fixed retention window, or pruned aggressively. Affects audit-trail completeness, status-list re-use, and storage growth. Driven by legal requirements; not engineering.
- **Status-list index re-use after retention.** If `IssuedCredential` rows are eventually pruned, the freed `(status_list_id, status_list_index)` slot could be reclaimed for a new issuance. Default lean: no — once burned, never re-used, even after pruning. Re-use would let a stale presentation observation bind to the wrong row. Revisit only if list growth becomes a real problem.
- **Staleness window between local commit and verifier observation.** Two contributors stack: (a) the publish lag between `swiyu-issuer` and the SWIYU Status Registry, bounded by the publish worker's retry budget but typically seconds; (b) cache TTLs from the Registry to verifiers, set by the Registry and any CDN in front of it. Worst-case staleness is the sum. Whether `swiyu-issuer` should expose the publish lag component to BAs (e.g. on the lifecycle response, or on a status-list view) is open.
- **Bulk operations.** Whether the management API supports `revoke many credentials in one call` or only single-credential operations. Adds little technical risk but real semantic risk (partial failure, auditing, rate-limiting). Defer until a BA asks.
