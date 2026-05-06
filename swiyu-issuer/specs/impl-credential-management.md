# Implementation: Credential Management

This document describes how the credential-management aspect (see [`aspect-credential-management.md`](aspect-credential-management.md)) is realised inside the `swiyu-issuer` crate. Endpoints (HTTP shapes, error codes, OpenAPI) live in [`impl_api_management.md`](impl_api_management.md). The OID4VCI issuance handler that produces `IssuedCredential` rows lives in [`impl_api_oidc.md`](impl_api_oidc.md); this document covers the domain types, persistence schema, status-list publish worker, and Status Registry interaction the handlers sit on top of. For ID-generation conventions and persistence-module shape, see [`impl_persistence.md`](impl_persistence.md). For the operation-task worker that this slice's publish loop runs alongside, see [`impl-issuer.md`](impl-issuer.md).

Status: preliminary; living document.

## Module layout

New code added by this slice:

- `swiyu-issuer/src/domain/issued_credential.rs` — `IssuedCredential` aggregate, `IssuedCredentialState`, `IssuedCredentialId`.
- `swiyu-issuer/src/domain/status_list/` — the issuer aggregate (`StatusList` row with id, bitstring, version, publish-state columns), `StatusListId`, `StatusListIndex`, a re-export of `swiyu_core::statuslist::StatusValue`, and `wrapper.rs` (`build_signed`, the `statuslist+jwt` wrapper builder used by the publish worker). Bit-twiddling routes through `swiyu_core::statuslist::StatusList::from_raw / set_at / value_at / as_bytes`; no local bit-encoding module.
- `swiyu-issuer/src/persistence/issued_credentials.rs` — insert / find / update for issued credentials.
- `swiyu-issuer/src/persistence/status_lists.rs` — bitstring storage, atomic bit updates, allocation counter, publish-state columns.
- `swiyu-issuer/src/worker/status_list_publisher.rs` — second dispatch loop alongside the existing `operation_task` worker; drives publishes to the SWIYU Status Registry.
- `swiyu-issuer/src/api_management/issued_credentials.rs` — handlers for `GET`, `suspend`, `unsuspend`, `revoke`.
- `swiyu-issuer/src/api_oidc/credential.rs` — extended to allocate a status-list bit index, embed the `status` claim, and insert the `IssuedCredential` row in the same transaction as the offer transition.

The HTTP client for the SWIYU Status Registry lives in [`swiyu-registries`](../../swiyu-registries/) under `swiyu-registries::status`, behind the `status` feature. swiyu-issuer enables that feature on its existing `swiyu-registries` dependency.

## Domain types

### `IssuedCredential`

```rust
pub struct IssuedCredential {
    pub id: IssuedCredentialId,
    pub tenant_id: TenantId,
    pub issuer_id: IssuerId,
    pub credential_offer_id: CredentialOfferId,
    pub vct: String,
    pub holder_key_jkt: String,        // RFC 7638 thumbprint, base64url
    pub status_list_id: StatusListId,
    pub status_list_index: StatusListIndex,
    pub state: IssuedCredentialState,
    pub integrity_hash: [u8; 32],      // SHA-256 of the signed compact serialisation
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

pub enum IssuedCredentialState {
    Active,
    Suspended,
    Revoked,
}
```

`expired` is **not** an `IssuedCredentialState` variant. Management-API responses derive an `expired` view label from `expires_at` at read time; see [`aspect-credential-management.md`](aspect-credential-management.md) § "Expiry is a view, not a state".

### `IssuedCredentialId`

Newtype following the project bs58/prefix convention (per [`impl_persistence.md`](impl_persistence.md)). Prefix: `cred`.

### `StatusList`, `StatusListIndex`, `StatusValue`

```rust
// Profile parameters from swiyu_core::statuslist:
//   SWIYU_STATUS_LIST_BITS     = 2
//   SWIYU_STATUS_LIST_CAPACITY = 131_072
pub const BITSTRING_BYTES: usize =
    (SWIYU_STATUS_LIST_CAPACITY as usize) * (SWIYU_STATUS_LIST_BITS as usize) / 8;

pub struct StatusList {
    pub id: StatusListId,
    pub issuer_id: IssuerId,
    pub bitstring: Vec<u8>,            // length == BITSTRING_BYTES
    pub allocated_count: u32,          // next free index = allocated_count
    pub committed_version: u64,
    pub published_version: u64,
    pub last_publish_attempt_at: Option<DateTime<Utc>>,
    pub last_publish_error: Option<String>,
    pub next_publish_attempt_at: Option<DateTime<Utc>>,
    pub publish_attempts: u32,
    pub created_at: DateTime<Utc>,
}

pub struct StatusListIndex(u32);  // bounded by SWIYU_STATUS_LIST_CAPACITY at construction

pub use swiyu_core::statuslist::StatusValue;  // Valid = 0, Revoked = 1, Suspended = 2, Reserved(u8)
```

Bit-encoding lives in `swiyu_core::statuslist`: `StatusList::from_raw(SWIYU_STATUS_LIST_BITS, bytes)` wraps the persisted bitstring, `set_at(idx, value)` and `value_at(idx)` translate `(StatusListIndex, StatusValue)` into byte-and-bit positions and back (LSB-first, per the IETF Token Status List draft as profiled by SWIYU). The semantic mapping (`Valid = 0`, `Revoked = 1`, `Suspended = 2`) is owned by `swiyu_core::statuslist::StatusValue` so producer and consumer agree on every slot's meaning; the issuer crate does not define its own enum. Bit-encoding correctness is tested in `swiyu-core` and not duplicated here.

`StatusListId` follows the bs58/prefix scheme. Prefix: `slist`.

## Persistence schema

Two migration files: one creating `status_lists` and extending `issuers` with the active-list pointer, one creating `issued_credentials`. They sequence after the issuer-management slice's migrations.

### Migration: `status_lists` and `issuers` extension

```sql
CREATE TABLE status_lists (
    id TEXT PRIMARY KEY,
    issuer_id TEXT NOT NULL REFERENCES issuers(id),
    bitstring BYTEA NOT NULL,
    allocated_count INT NOT NULL DEFAULT 0,
    committed_version BIGINT NOT NULL DEFAULT 0,
    published_version BIGINT NOT NULL DEFAULT 0,
    last_publish_attempt_at TIMESTAMPTZ,
    last_publish_error TEXT,
    next_publish_attempt_at TIMESTAMPTZ,
    publish_attempts INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CHECK (allocated_count <= 131072),
    CHECK (octet_length(bitstring) = 32768)
);

CREATE INDEX status_lists_issuer ON status_lists (issuer_id);

-- Publish worker's "find next runnable" probe.
CREATE INDEX status_lists_dirty
    ON status_lists (next_publish_attempt_at NULLS FIRST)
    WHERE committed_version > published_version;

-- Pointer to the issuer's current "active" status list. NULL means no
-- list has been provisioned yet; the issuance path provisions one
-- lazily on the first issued credential.
ALTER TABLE issuers
    ADD COLUMN current_status_list_id TEXT REFERENCES status_lists(id);
```

- `bitstring`: 32 KB at `bits = 2`, `LIST_CAPACITY = 131_072` entries. Stored in full on every bit-flip update; row-level locking via the standard `UPDATE ... WHERE id = ?` is sufficient at v0.1.0 write volumes.
- `allocated_count`: next free index. Atomically incremented inside the issuance transaction; once it reaches `LIST_CAPACITY` the issuance path provisions a new row and re-points `issuers.current_status_list_id`.
- `committed_version` increments on every committed bit update (issuance, suspend, unsuspend, revoke). `published_version` increments after a successful publish round.

### Phase-2 schema additions: registry coordinates

Phase 2 adds two columns to `status_lists` so the publish worker can address the right registry entry:

```sql
ALTER TABLE status_lists
    ADD COLUMN registry_entry_id TEXT,
    ADD COLUMN registry_url TEXT;
```

- `registry_entry_id` — the entry UUID returned by `create_status_list_entry`; the path segment of every subsequent `update_status_list_entry` PUT.
- `registry_url` — the `statusRegistryUrl` returned alongside it; the `uri` value embedded in every issued credential's `status.status_list` claim, and the `sub` of the published JWT.

Both are nullable: a row stays in the *unallocated-on-registry* state from local insert until the first time the publish worker (or whichever component owns this — see *Open*) successfully calls `create_status_list_entry`. Issuance against a list with `registry_url IS NULL` cannot mint an SD-JWT VC the verifier can dereference, so allocation against the registry must happen before a list is offered to issuance.

### Migration: `issued_credentials`

```sql
CREATE TABLE issued_credentials (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    issuer_id TEXT NOT NULL REFERENCES issuers(id),
    credential_offer_id TEXT NOT NULL REFERENCES credential_offers(id),
    vct TEXT NOT NULL,
    holder_key_jkt TEXT NOT NULL,
    status_list_id TEXT NOT NULL REFERENCES status_lists(id),
    status_list_index INT NOT NULL,
    state TEXT NOT NULL DEFAULT 'active',
    integrity_hash BYTEA NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,

    UNIQUE (status_list_id, status_list_index),
    UNIQUE (credential_offer_id)
);

CREATE INDEX issued_credentials_tenant_issuer
    ON issued_credentials (tenant_id, issuer_id, issued_at DESC);

CREATE INDEX issued_credentials_holder
    ON issued_credentials (tenant_id, issuer_id, holder_key_jkt);
```

- `UNIQUE (status_list_id, status_list_index)` codifies "indices are not reused" from the aspect spec.
- `UNIQUE (credential_offer_id)` codifies the `1:{0..1}` cardinality from `CredentialOffer` to `IssuedCredential`.
- `holder_key_jkt` is base64url; no fixed-width CHECK (RFC 7638 produces 43 characters for SHA-256, but allowing other hashes future-proofs the column).
- `state` is `TEXT`, matching the rest of the schema's enum-as-text convention.

## Lifecycle operations

### Issuance (extends OIDC `/credential` handler)

Inside the existing `api_oidc::credential` handler, after PoP verification and offer validation:

1. Begin transaction.
2. Resolve the issuer's current status list via `issuers.current_status_list_id`. If `NULL` or the pointed list is at capacity, provision a fresh `status_lists` row with a zero-filled bitstring and update the pointer in the same transaction.
3. Atomically allocate the next index:
   ```sql
   UPDATE status_lists
       SET allocated_count = allocated_count + 1,
           committed_version = committed_version + 1
       WHERE id = $1 AND allocated_count < 131072
       RETURNING allocated_count - 1 AS allocated_index;
   ```
   The capacity guard in the `WHERE` clause races safely against capacity overflow: a losing concurrent issuance gets zero rows and falls back to step 2's provisioning branch.
4. Build the SD-JWT VC payload with the `status.status_list` claim carrying `{ "type": "SwissTokenStatusList-1.0", "idx": allocated_index, "uri": status_list_url(list_id) }`.
5. Sign via the issuer's assertion key.
6. Compute `integrity_hash = SHA-256(compact_serialisation)`.
7. Insert the `issued_credentials` row.
8. Transition the `credential_offers` row to `Issued` and clear `pre_auth_code`.
9. Commit.
10. Return the signed credential to the wallet.

Failure between steps 5 and 9 leaves `allocated_count` incremented without a corresponding `issued_credentials` row — an "index leak". The leak is bounded by issuance failure rate; at 131 072 indices per list the practical impact is negligible. Reclaiming leaked indices is explicitly not modelled (see [`aspect-credential-management.md`](aspect-credential-management.md) § *Open*).

### Suspend / unsuspend / revoke (management API)

Each is one transaction:

```rust
pub async fn revoke(
    tx: &mut PgConnection,
    tenant: TenantId,
    credential_id: IssuedCredentialId,
) -> Result<IssuedCredential, ManagementError> {
    let credential = persistence::issued_credentials::find(tx, tenant, credential_id)
        .await?
        .ok_or(ManagementError::NotFound)?;

    match credential.state {
        IssuedCredentialState::Active | IssuedCredentialState::Suspended => {}
        IssuedCredentialState::Revoked => return Err(ManagementError::AlreadyRevoked),
    }

    persistence::issued_credentials::set_state(
        tx, tenant, credential_id, IssuedCredentialState::Revoked,
    ).await?;

    persistence::status_lists::write_bit(
        tx,
        credential.status_list_id,
        credential.status_list_index,
        StatusValue::Revoked,
    ).await?;

    // audit log entry appended in the same transaction;
    // see aspect-persistence.md § "Audit log"

    persistence::issued_credentials::find(tx, tenant, credential_id)
        .await?
        .ok_or(ManagementError::NotFound)
}
```

`status_lists::write_bit` takes the row-level lock, applies the bit update to `bitstring`, and increments `committed_version`. The publish worker observes the version bump on its next dispatch tick.

`suspend` and `unsuspend` follow the same shape with different state preconditions (`Active` for suspend, `Suspended` for unsuspend) and `StatusValue` arguments.

## Publish worker

A second dispatch loop in `swiyu-issuer/src/worker/`, alongside the existing `operation_task` loop. Both run inside the same `tokio::spawn`-ed worker process launched by `issuer-mgmt` at startup.

### Dispatch loop

```rust
loop {
    let dirty = persistence::status_lists::acquire_next_dirty(&pool, now()).await?;
    match dirty {
        Some(list) => publish(list, &deps).await,
        None => sleep_until_next_runnable_or_poll_interval().await,
    }
}
```

`acquire_next_dirty` selects the oldest dirty list (`committed_version > published_version` and `next_publish_attempt_at IS NULL OR <= now()`) and stamps its `next_publish_attempt_at` to a near-future "lease expiry" so a concurrent worker would skip it. Single-worker for v1; the query is written for the future multi-worker switch.

### Wrapper format

The wallet-facing artefact is a JWT in compact serialisation, content-typed `application/statuslist+jwt`, layered on the IETF Token Status List draft (`SwissTokenStatusList-1.0` profile). It is **not** a W3C Verifiable Credential; the `status.status_list.type` tag on the issued SD-JWT VC names this profile so verifiers know how to decode the bitstring.

JOSE header (compact-encoded, base64url):

```json
{
  "alg": "ES256",
  "typ": "statuslist+jwt",
  "kid": "<issuer.did>#assertion-key-01"
}
```

Payload claims:

- `iss` — the issuer DID (matches the `iss` of credentials it covers).
- `sub` — the URL the JWT is hosted at (the `statusRegistryUrl` returned by the registry when the list's entry was allocated; until then the publish step has nothing to send).
- `iat` — moment of signing (Unix seconds). `validFrom` in the substep 2.2 plan refers to this claim.
- `status_list`:
  - `bits`: `2`
  - `lst`: zlib-compressed, base64url-encoded (`URL_SAFE_NO_PAD`) bitstring. Compression is the IETF default; the Registry contract does not allow opting out.

`build_signed(list, issuer, signing_engine)` lives in `swiyu-issuer/src/domain/status_list/wrapper.rs`. It zlib-compresses `list.bitstring`, base64url-encodes the result, builds the header and payload above, computes `SHA-256(header_b64 || "." || payload_b64)`, and signs that digest via `SigningEngine::sign` against `issuer.assertion_key_id`. The returned `String` is the compact JWT (`header_b64.payload_b64.signature_b64`).

### Publish step

1. Read the dirty list's current `bitstring` and capture `committed_version` as `published_target`. Coalescing happens here: any bit updates that arrive after this read are observed only by subsequent publish rounds.
2. Build and sign the status-list JWT via `domain::status_list::wrapper::build_signed`.
3. PUT to the SWIYU Status Registry via `swiyu_registries::status::StatusRegistryClient::update_status_list_entry(partner_id, registry_entry_id, jwt)`. The `registry_entry_id` is the value returned by `create_status_list_entry` at provisioning time (see *Open*).
4. On success:
   ```sql
   UPDATE status_lists
       SET published_version = $published_target,
           last_publish_attempt_at = now(),
           last_publish_error = NULL,
           next_publish_attempt_at = NULL,
           publish_attempts = 0
       WHERE id = $list_id AND published_version < $published_target;
   ```
   The conditional `WHERE` is a no-op if a concurrent worker already published a newer version.
5. On retryable failure (HTTP `5xx`, `429`, transport): increment `publish_attempts`, compute `next_publish_attempt_at = now() + backoff(publish_attempts)`, record `last_publish_error`. There is **no give-up threshold** — a list whose latest snapshot we cannot publish is a real outage that needs human intervention, not a quiet `Failed` state. The 24-hour wall-clock budget familiar from the operation-task worker is here only an alerting threshold (metrics).
6. On terminal failure (any other 4xx): record `last_publish_error`, raise an alert, and back off to a long retry interval (e.g. 1 hour). Same reasoning as point 5 — the publish is still semantically required.

### Backoff

Same shape as the issuer-lifecycle worker: full-jitter exponential, base `1m`, cap `1h`. The 24-hour mark is an *alert* threshold, not a give-up threshold.

### Crash recovery

A worker restart picks up dirty lists on the next dispatch tick. The bitstring read in step 1 is captured from the row at execution time, so any state from a previous attempt is irrelevant; idempotency is automatic because the wrapper is a function of the bitstring snapshot.

## SWIYU Status Registry client

`swiyu-registries::status`, behind the `status` feature. Mirrors the shape of the existing `identifier` module. swiyu-issuer pulls it in by enabling the feature on its existing `swiyu-registries` dependency.

### Operations used by v1

- `create_status_list_entry(partner_id) -> StatusListEntry { id, registry_url }` — `POST /api/v1/status/business-entities/{partner_id}/status-list-entries/`. Allocates a registry-side entry. **Not idempotent** — every successful call mints a fresh entry. Called once per `status_lists` row, when the row is first provisioned (see *Open* for where exactly that call lands).
- `update_status_list_entry(partner_id, entry_id, status_list_jwt) -> ()` — `PUT /api/v1/status/business-entities/{partner_id}/status-list-entries/{entry_id}`, `Content-Type: application/statuslist+jwt`, body is the JWT verbatim. Idempotent; the publish worker may re-call it freely.

### Configuration

The client is constructed in the `issuer-mgmt` startup path from environment variables:

- `SWIYU_STATUS_REGISTRY_URL` — base URL of the SWIYU Status Registry.
- `SWIYU_ACCESS_TOKEN` — bearer token (shared with the Identifier Registry; same SWIYU credential).
- `SWIYU_PARTNER_ID` — already used by the Identifier Registry client; reused here.

### Failure classification

The client returns the shared `swiyu_registries::common::RegistryError`, with the same `is_retryable()` semantics already in use for the Identifier Registry client:

- `Transport` → retryable.
- `HttpStatus` with `status == 429` or `status >= 500` → retryable.
- `HttpStatus` with any other 4xx → terminal (alert; long retry).
- `Decode` → terminal (unexpected response shape; waiting will not help).

## Endpoints

Defined in [`impl_api_management.md`](impl_api_management.md). This spec deliberately does not duplicate request/response shapes.

The endpoints exposed by this slice:

- `GET /api/v1/issued-credentials/{credential_id}` — fetch a single issued credential.
- `GET /api/v1/issued-credentials` — list issued credentials belonging to the tenant; supports filtering by `issuer_id`, `state`, `vct`.
- `POST /api/v1/issued-credentials/{credential_id}/suspend` — synchronous; returns the updated record.
- `POST /api/v1/issued-credentials/{credential_id}/unsuspend` — synchronous.
- `POST /api/v1/issued-credentials/{credential_id}/revoke` — synchronous.

The owning tenant is **never in the URL**. It is derived from the API token by the existing `TenantContext` extractor (per [`impl_api_management.md`](impl_api_management.md) and [`impl_auth.md`](impl_auth.md)). Cross-tenant access returns `404`.

No `task_id` is returned for credential-lifecycle operations in v0.1.0; see [`aspect-credential-management.md`](aspect-credential-management.md) § "No BA-facing task id in v0.1.0".

## Tests

- Unit tests in `domain/status_list/` cover the issuer aggregate (`StatusList::new` zeros, `is_at_capacity`, `is_dirty`, version semantics) and `StatusListIndex` bounds. Bit-encoding correctness — LSB-first layout, the `Valid=0 / Revoked=1 / Suspended=2` mapping, and the `(index, value) → bytes → (index, value)` round-trip — lives in `swiyu_core::statuslist` and is not duplicated here.
- Unit tests in `domain/status_list/wrapper.rs`: the JWT signature verifies under the issuer's assertion public key; `iat` matches the `now` passed in. (Bitstring encode/decode round-trip is a property of `swiyu_core::statuslist`.)
- Unit tests in the publish worker module against a stubbed `StatusRegistryClient` (success, retryable failure, terminal failure, conditional-update no-op when a concurrent publish already advanced the version).
- Integration tests under `swiyu-issuer/tests/` driving full flows with a real Postgres pool (via `sqlx::test`) and a stubbed Status Registry:
  - Issuance happy-path: inserts an `issued_credentials` row with the expected `(status_list_id, status_list_index)`, increments `allocated_count`, bumps `committed_version`, transitions the offer to `Issued`.
  - Concurrent issuance race: two simultaneous issuances on the same list allocate adjacent indices without overlap.
  - Capacity overflow: filling a list provisions a second `status_lists` row and re-points `issuers.current_status_list_id`.
  - Suspend / unsuspend / revoke round-trip flips the bit, bumps `committed_version`, and rejects illegal state transitions.
  - Publish worker observes a dirty list, posts to the stub, and bumps `published_version`.
  - Publish retry on `503` then success: `publish_attempts` rises, then resets after success.

## Out of scope for v1

- **Bulk lifecycle endpoints.** Single-credential operations only; bulk lands when a BA asks.
- **Holder-initiated revocation.** Tracked as open in [`aspect-credential-management.md`](aspect-credential-management.md).
- **Retention sweeper** for `revoked` and post-`expires_at` rows. Rows accumulate; a sweeper lands when retention policy is settled.
- **Reuse of freed status-list indices.** Indices stay bound for the row's lifetime; the open question in the aspect spec governs whether this ever changes.
- **Multi-purpose status lists.** One combined list per issuer at `bits: 2`; a separate revocation list and suspension list is a future-only knob.
- **Dedicated status-list signing key.** The wrapper is signed with the issuer's assertion key in v0.1.0; a separate key role is not introduced.
- **Reclaim of leaked indices** on issuance failure between signing and row-insert. Document the leak rate via metrics; reclaim machinery is future-only.
- **Operator admin endpoints** for status lists (force-publish, inspect publish state). Operators interact with `status_lists` directly via DB.

## Open

- **Allocation under capacity overflow.** The current sketch auto-provisions a new `status_lists` row in the same transaction as issuance and re-points the active-list pointer. The alternative — surface a typed error to the caller and let a separate provisioning endpoint run — is heavier on operations but isolates the provisioning-failure mode. Lean: auto-provision; provisioning is cheap.
- ~~**Where `create_status_list_entry` is called from.**~~ Resolved: option **(a)** — bootstrap at `create_issuer` time. The operation-task worker calls `create_status_list_entry(partner_id)` and provisions the issuer's first `status_lists` row with the returned `id` and `registry_url` populated, so issuance is unblocked from the start. Failure of the registry call propagates as a retryable operation-task error. See `plan-credential-management.md` § "Cross-phase decisions / Eager registry-side provisioning at issuer-creation time (phase 2)".
- **Status-list URL the verifier sees.** Resolved against the Registry contract: it is the `statusRegistryUrl` returned by `create_status_list_entry`. The OIDC handler reads it from `status_lists.registry_url` and embeds it as `status.status_list.uri` on every issued credential.
- **Stuck-publish escalation.** What "human intervention" means in practice when a publish stays stuck past the 24-hour alerting threshold: a separate "needs operator attention" flag on the row, a paging integration, or a CLI surface to inspect and force-retry. Lands with the operations runbook, not in this spec.
- **Acquire-next-dirty lease semantics.** Whether to use `SELECT ... FOR UPDATE SKIP LOCKED` from the start (matching the operation-task worker convention) or rely on the `next_publish_attempt_at` lease until multi-worker dispatch is needed. Lean: `FOR UPDATE SKIP LOCKED` for consistency, even though it is overkill for a single worker.
