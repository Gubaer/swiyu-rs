# Aspect: Issuer

This document captures the issuer concept: what an issuer is, its lifecycle, and its contract with the SWIYU Identifier Registry. For the key-triple substrate, see [`aspect-key-management.md`](aspect-key-management.md). For tenant ownership rules, see [`aspect-multi-tenancy.md`](aspect-multi-tenancy.md). For credential-related vocabulary, see [`aspect-domain.md`](aspect-domain.md).

Status: preliminary; living document.

## What an issuer is

For every tenant, swiyu-issuer manages zero or more issuers. An issuer is a registered credential-issuing entity that:

- has a stable identity expressed as a DID (`did:tdw:...` for now; see *DID method scope* below);
- holds a current key triple — one private key per role (`Authorized`, `Authentication`, `Assertion`) per [`aspect-key-management.md`](aspect-key-management.md);
- has a DIDLog published in the SWIYU Identifier Registry, which is the canonical source of truth for the issuer's public keys and verification history;
- has human-readable identification — a `display_name` (e.g. "Gemeinde Buchs — Einwohnerverwaltung") and a `description` — both required, so the issuer is reliably identifiable to humans in management responses, logs, and wallet displays.

## Tenant ownership

Each issuer belongs to exactly one tenant; the relationship is `Tenant → Issuer = 1:{0..n}`, per [`aspect-multi-tenancy.md`](aspect-multi-tenancy.md). Operations on an issuer require the calling business application to authenticate as a principal that resolves to the owning tenant. Cross-tenant access returns the same `404` as a missing issuer.

The owning tenant is fixed at creation. There is no operation to transfer an issuer to a different tenant.

## Lifecycle states

- `active` — the default state after creation. The issuer can issue credentials and rotate keys.
- `deactivated` — terminal. The issuer's DIDLog has been closed in the registry; no further key rotations, no new credential issuance.

The transition `active → deactivated` is one-way. There is no reactivation: a deactivated issuer stays deactivated.

## Lifecycle operations

Each operation is a coordinated change across three substrates: the SigningEngine (private keys), the SWIYU Identifier Registry (DIDLog), and swiyu-issuer's local domain state (issuer record + key-id mapping).

### Create

1. Allocate a DID with the SWIYU Identifier Registry.
2. Generate the initial key triple via the SigningEngine.
3. Build the initial DIDLog entry, embedding the three new public keys.
4. Sign the entry with the freshly generated `Authorized` private key.
5. Publish the entry to the registry.
6. Persist the issuer locally with state `active` and the three current `KeyPairId` values.

### Rotate keys

A rotation rotates **one, two, or all three** of the issuer's keys in a single operation. Roles that are not rotated keep their existing key pair; their public keys still appear in the new DIDLog entry, since every entry carries the issuer's complete current key set.

1. The caller specifies a non-empty subset of `{Authorized, Authentication, Assertion}` to rotate.
2. For each rotated role, generate a new key pair via the SigningEngine. For non-rotated roles, the existing `KeyPairId` is reused unchanged.
3. Build a DIDLog rotation entry whose payload announces all three current public keys — the new ones for rotated roles, the unchanged ones for the rest.
4. Sign the entry with the **outgoing** `Authorized` private key — the key that was active *before* this rotation. This holds even when `Authorized` is itself among the rotated roles: the old `Authorized` key signs the rotation entry; the new one takes over for subsequent entries.
5. Publish the entry to the registry.
6. Atomically swap the issuer's `(issuer, role) → current_id` mapping for the rotated roles only. Non-rotated roles' mappings stay as they were.
7. Optionally delete the old key pair for each rotated role from the SigningEngine. Whether deleted or not, an old key is never used for signing again.

The choreography matches the rotation choreography described in [`aspect-key-management.md`](aspect-key-management.md): swiyu-issuer owns the active-id mapping; the SigningEngine has no concept of rotation. A rotation that targets the empty subset is rejected — every rotation must change at least one role.

### Deactivate

1. Build a DIDLog deactivation entry.
2. Sign the entry with the current `Authorized` private key.
3. Publish the entry to the registry.
4. Update the issuer's local state to `deactivated`.

The current key triple is not deleted from the SigningEngine on deactivation: existing credential proofs may still need it for verification by relying parties (which fetch public keys from the DIDLog), and there is no benefit to making that resolution rely on engine-side removal.

## Asynchronous execution

The lifecycle operations that touch the SWIYU Identifier Registry — `create`, `rotate keys`, `deactivate` — execute asynchronously. The registry is an external dependency that can be unavailable for minutes or hours during maintenance windows or outages; holding an HTTP request open for the full duration is not viable. A business application starts such an operation by submitting a request that creates an **operation task**. The submit response carries a `task_id`; the BA polls the task to observe state changes until it reaches a terminal state.

### Task states

BA-facing states:

- `pending` — accepted; not yet picked up by a worker.
- `in_progress` — a worker is processing the task, including time spent paused for retry timers. The BA does not distinguish active execution from paused-for-retry; both surface as `in_progress`.
- `completed` — terminal success; the response references the resulting `issuer_id`.
- `failed` — terminal failure; the response carries a typed error.

Cancellation is not supported in v1.

A task additionally carries an internal `step` recording its current sub-operation (e.g. `allocate_did`, `publish_log`). The step is for diagnostics, observability, and crash recovery; the BA does not act on it.

### Step classification

Each sub-operation is classified as:

- **retryable** — transient registry failures (HTTP `5xx`, transport errors, `429 Too Many Requests`). The worker schedules another attempt with exponential backoff and jitter, capped at a maximum elapsed wall-clock duration (~24 hours). For `create_issuer` the retryable steps are `allocate_did` and `publish_log`.
- **terminal on failure** — any local error (SigningEngine, log construction, local persistence) and any registry response other than the retryable set above (notably `4xx` with codes that mean the request is malformed or unauthorised). The task moves directly to `failed`.

### Crash recovery

External side effects already performed (a DID assigned by the registry, a log entry accepted by the registry) are not rewound on worker crash. The task row records intermediate results — the assigned DID, the published-entry identifier, and so on — *before* the step that produced them is marked complete. On resume, the worker reads what is already done and skips ahead to the next un-done step.

### Worker placement

For v1 a **single in-process worker** runs alongside the management API server, dispatching one task at a time in submission order. The worker code is factored so a future split into a dedicated worker binary, or multi-worker dispatch via Postgres `SELECT ... FOR UPDATE SKIP LOCKED`, is a mechanical change rather than a redesign.

### v1 scope

All three registry-touching operations (`create`, `rotate keys`, `deactivate`) are designed to run through the task model. v1 implements only `create_issuer`. `rotate_keys` and `deactivate_issuer` follow the same pattern in subsequent slices.

### Notification

Polling-only in v1. Callback URLs (push notification on terminal state) are deferred to a later slice; implementing them well — signed delivery, retry on callback failure, timeouts — is its own design problem.

## DIDLog: the registry is authoritative

The SWIYU Identifier Registry holds the issuer's DIDLog. swiyu-issuer treats the registry as the canonical source for everything the DIDLog already encodes — public keys (current and historical), rotation history, deactivation status.

What swiyu-issuer **persists locally** is a small projection sufficient for issuance and OIDC metadata:

- `IssuerId`, `TenantId`, `DID` string;
- the three current `KeyPairId` values (one per role);
- lifecycle state (`active` | `deactivated`);
- human-readable identification: `display_name`, `description`.

What swiyu-issuer **does not persist locally**:

- public keys — read from the DIDLog when needed, optionally cached;
- DIDLog entries — fetched from the registry;
- historical key pairs — older `KeyPairId` values may linger in the SigningEngine but are not referenced from the issuer record.

## DID method scope

`did:tdw` 0.3 is the only DID method currently supported end-to-end against the SWIYU integration registry. `did:webvh` 1.0 is the planned successor; the relevant code paths exist in `swiyu-didtool` and `swiyu-core` but cannot be validated against any backend in the present setup. `did:webvh` is treated as unverified until a test backend is available.

The aspect spec itself is method-agnostic; method-specific differences (entry format, hash-chain semantics, allocation details) are absorbed by the DIDLog construction code that the implementation spec will reference.

## Open

- **In-flight credential offers on deactivate.** What happens to `pending` offers belonging to an issuer at the moment of deactivation: cancel them automatically? Reject redemption with a specific error? To be decided.
- **DIDLog caching.** Whether swiyu-issuer keeps a local copy of the DIDLog (or recent slices of it) for offline operation or performance. Default lean: no — fetch on demand, since the credential-issuance hot path does not need the log.
