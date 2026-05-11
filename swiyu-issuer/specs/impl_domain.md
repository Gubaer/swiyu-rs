# Implementation: domain layer

This document is a structural map of `swiyu-issuer/src/domain/`. It describes what each module owns and points at the slice-specific impl docs that carry the depth. The vocabulary and modelling decisions behind the entities live in [`aspect-domain.md`](aspect-domain.md); the persistence shape lives in [`impl_persistence.md`](impl_persistence.md).

Status: living document. Reflects the current layout of the domain module.

## Layering

The domain layer:

- **Owns** the identifier newtypes, the entity structs, the value enums, the value objects (including bare-secret / hash-pair types), the `TokenProvider` and `SigningEngine` traits and their concrete implementations, and a small shared `DomainError` enum.
- **Does not own** SQL or DB row types (those are `persistence`), HTTP / OIDC4VCI wire shapes (those are the API layers), the worker step executors or task-loop machinery (those are `worker`), or any HTTP transport for the SWIYU registries (that is `swiyu-registries`).
- Is mostly pure and synchronous. Two exceptions are deliberate: `oauth2/` performs HTTP and DB I/O because the OAuth2 grant is a domain operation, not a transport detail, and `signing_engine/` performs network I/O against Vault because the signer is the domain abstraction over a KMS — both expose async fns through traits whose `&dyn` use is replaced by enum dispatch (`AnyTokenProvider`, `AnySigningEngine`).

## Public surface

`mod.rs` declares the modules and re-exports the entity structs, ID newtypes, value enums, and the small shared `DomainError`. Consumers reach domain types via `crate::domain::TypeName`; intra-domain code uses the submodule path.

`DomainError` carries two generic variants — `InvalidInput { details }` and `StateTransitionNotAllowed` — that any aggregate may use; aggregate-specific errors live with their aggregates (`SigningEngineError`, `TokenProviderError`, `BuildError`, …) and do not funnel through `DomainError`.

## Module map

### Identifiers — `ids.rs`

Newtypes for every aggregate: `TenantId`, `IssuerId`, `CredentialOfferId`, `IssuedCredentialId`, `StatusListId`, `ApiTokenId`, `TaskId`. All share one scheme — 10 CSPRNG bytes, base58-encoded, ~14 chars; `Display` / `Serialize` produce a prefixed form (`tenant_…`, `issuer_…`, `offer_…`, `credential_…`, `status_list_…`, `apitok_…`, `task_…`); `FromStr` / `Deserialize` accept only the prefixed form; `bare()` returns the unprefixed body used at the persistence boundary and inside the wallet-facing offer URL. The base58 alphabet is checked in the constructor; the database stores the bare body without a `CHECK` constraint.

### Bare-secret / hash pairs — `access_token.rs`, `api_token.rs`, `nonce.rs`

Each pair gives the secret two distinct types: `…Secret` carries the bare value and offers `generate()`, `from_stored()`, `as_str()`, `hash()`, plus a redacting `Debug`; `…Hash` is the persistable form (SHA-256 of the bare value, base58-encoded). Persistence-layer signatures take the hash, never the secret. `AccessToken` is the persisted access-token row carrying `(token_hash, tenant_id, issuer_id, offer_id, expires_at)`. `ApiToken` (the row companion to `ApiTokenSecret`) carries `id`, `tenant_id`, `name`, `token_hash`, timestamps; the `tok_<base58>` wire form is parsed by `ApiTokenSecret::from_wire` and reattached by `as_wire`. See [`impl_auth.md`](impl_auth.md) for the API-token slice end-to-end.

### Credential offer — `credential_offer.rs`, `pre_auth_code.rs`

`CredentialOffer` is the OID4VCI offer aggregate: `(id, tenant_id, issuer_id, vct, claims, pre_auth_code, expires_at, state, …)`. `CredentialOfferState` is `Pending` → `{Issued, Cancelled, Expired}`; expiry is evaluated on read against `expires_at`. `PreAuthCode` is the bare-secret companion held plaintext on the row during the pending window because the OID4VCI by-reference flow makes the value retrievable, then NULLed at the first terminal-state transition. See [`impl-credential-management.md`](impl-credential-management.md) for the offer + issuance flow.

### Issuer — `issuer.rs`

`Issuer` aggregates the issuing entity: `(id, tenant_id, did, state, key triple, …)`. `IssuerState` is `Active` → `Deactivated` (terminal; no reactivation). The three `KeyPairId` fields (`authorized_key_id`, `authentication_key_id`, `assertion_key_id`) are `Option` because the seeded dev fixture predates the issuer-management task flow; issuers minted through the create-issuer task have all three populated. See [`impl-issuer.md`](impl-issuer.md).

### Issued credential — `issued_credential.rs`

`IssuedCredential` is the issuer's record of a signed credential: `(id, tenant_id, issuer_id, credential_offer_id, vct, holder_key_jkt, status_list_id, status_list_index, integrity_hash, expires_at, state, …)`. `IssuedCredentialState` is `Active ↔ Suspended`, with `Revoked` terminal; expiry is a derived view, not a state. The signed SD-JWT VC bytes are not persisted — the wallet keeps the only copy, and `INTEGRITY_HASH_LEN`-byte `integrity_hash` (SHA-256) is the only trace that survives. See [`impl-credential-management.md`](impl-credential-management.md).

### Status list — `status_list/`

`StatusList` is one issuer-owned status list whose `bitstring` is a fixed `BITSTRING_BYTES`-long buffer (derived from the SWIYU profile in `swiyu-core`); `StatusListIndex` is a bounded `u32` newtype that fails construction outside `SWIYU_STATUS_LIST_CAPACITY`. `StatusValue` is re-exported from `swiyu-core::statuslist`. The submodule's `wrapper.rs` carries the small read/write helpers used by the worker. The status-registry transport, JWT signing, and publication cadence live in [`impl-credential-management.md`](impl-credential-management.md) and [`aspect-credential-management.md`](aspect-credential-management.md).

### Tenant — `tenant.rs`

`Tenant` is the organisation row: `(id, partner_id, oauth_client_id, oauth_client_secret, oauth_refresh_token)`. `partner_id` is the SWIYU Identifier Registry partner UUID, required by `allocate_did`. The two OAuth2 secrets are wrapped in `secrecy::SecretString` so accidental `Debug`/`Display` prints elide the value and memory is zeroized on drop; `Tenant` deliberately does not derive `PartialEq` because `secrecy` rejects it. See [`aspect-multi-tenancy.md`](aspect-multi-tenancy.md) and [`impl-oauth2.md`](impl-oauth2.md).

### OAuth2 — `oauth2/`

The OAuth2 token lifecycle for the SWIYU registries. `TokenProvider` is the in-memory state machine for one credential set (`get` returns a valid access token, `invalidate` discards the cache and forces a fresh `refresh_token` grant). `OAuth2TokenProvider` is the real backend (cache + single-flight refresh + transactional grant against the tenant row). `StaticTokenProvider` is a test-only fixture. `AnyTokenProvider` is the dispatch enum so multi-tenant code can hold one type. `ProviderRegistry` owns the `tenant_id → Arc<AnyTokenProvider>` map. `TokenProviderError` / `TokenAwareError` carry the retryability classification. The 401-retry wrappers that pair `TokenProvider` with `RegistryFacade` live in `worker::registry_facades`, not here, to keep the `domain → worker` direction clean. See [`impl-oauth2.md`](impl-oauth2.md) and [`aspect-oauth2.md`](aspect-oauth2.md).

### Signing engine — `signing_engine/`

The KMS abstraction. `SigningEngine` is the trait (key-pair generation per `KeyRole`, raw signing, public-key fetch); `KeyAlgorithm::for_role` fixes the `KeyRole → algorithm` mapping (Ed25519 for `Authorized`, P-256 for `Assertion` / `Authentication`). `DevSigningEngine` keeps key material in Postgres (dev/test only); `VaultSigningEngine` is the production backend talking to HashiCorp Vault Transit. `AnySigningEngine` is the dispatch enum. `build_from_env` is the runtime selector consulted by the binaries. `test_support` (publicly compiled but `#[doc(hidden)]`) is a hand-rolled mock used by inline tests across the worker, status-list wrapper, and OIDC issuance code paths. See [`impl-key-management.md`](impl-key-management.md) and [`aspect-key-management.md`](aspect-key-management.md).

### Operation task — `operation_task.rs`

`OperationTask` is the row for one long-running worker operation: `(id, tenant_id, issuer_id, task_type, state, step, attempts, next_attempt_at, error_*, payload, timestamps)`. `TaskState` is `Pending → InProgress → {Completed, Failed}`; `TaskType` covers `CreateIssuer`, `DeactivateIssuer`, `RotateKeys`. `StepResult` / `StepOutcome` are the per-step return shapes the worker reads to decide retry vs terminal. The worker loop, per-step executors, and retry policy live in `worker/`.

### Credential type catalogue — `vct.rs`

A single `CATALOGUE: &[VctEntry]` constant holds the supported `vct` strings paired with their compile-time-bundled JSON Schema. v0.1.x supports one type (`urn:communal:local-residence-id`). The DB-backed `CredentialType` entity that [`aspect-domain.md`](aspect-domain.md) describes has not yet shipped; this constant is the current source of truth for the management API's claims validation and the OIDC metadata's `credential_configurations_supported`. See [`impl_credential_schema.md`](impl_credential_schema.md).

## Conventions

- **Free functions and methods, not traits**, except where multiple implementations genuinely exist (`TokenProvider`, `SigningEngine`).
- **State transitions as methods on the aggregate.** The only way to change state is through `try_*` methods that enforce preconditions and return `DomainError` (or an aggregate-specific error) when invalid. The convention covers lifecycle state only; saga-data writes such as `OperationTask`'s `advance_step` and `schedule_retry` are deliberately persistence-side helpers, not aggregate methods.
- **Type-level discipline for secrets.** Bare-secret types (`*Secret`, `PreAuthCode`) are distinct from their persisted forms (`*Hash`, `SecretString` for OAuth2 secrets). Persistence-layer signatures take the hashed/wrapped form. The OID4VCI pre-auth code is the documented exception: by-reference offer fetch requires the bare value to be persisted on `credential_offers.pre_auth_code` during the pending window.
- **Redacting `Debug`** on every bare-secret type. A grep for `redacted` returns the assertions backing this in the unit tests.
- **Pragmatic serde / sqlx coupling.** Domain types carry `Serialize` / `Deserialize` directly, and every newtype / state enum that crosses the database boundary carries `sqlx::Type` + `Decode` + `Encode` so aggregates `#[derive(sqlx::FromRow)]` without per-file row mappers. Splitting wire / DB / domain shapes is deferred until they actually diverge.
- **Submodule layout** uses `<module>/mod.rs` with siblings (`<module>/<submodule>.rs`); single-file modules stay as `<module>.rs`. Matches the layout under `persistence/` and `worker/`.
