# Implementation: domain (v0.1.0)

This document captures concrete implementation decisions for the domain
layer as of release v0.1.0. For tenant/issuer concepts see
[`aspect-multi-tenancy.md`](aspect-multi-tenancy.md). For the
identifier strategy that the domain reflects see
[`impl_persistence.md`](impl_persistence.md).

Status: preliminary; living document. Reflects the v0.1.0
walking-skeleton scope — credential offers as the first aggregate.

## Module layout

`swiyu-issuer/src/domain/`:

- `mod.rs` — module declarations and re-exports.
- `errors.rs` — `DomainError` enum.
- `ids.rs` — placeholder for identifier newtypes (empty at v0.1.0).
- `credential_offer.rs` — placeholder for the v0.1.0 aggregate
  (empty at v0.1.0).
- `pre_auth_code.rs` — placeholder for the pre-auth code value
  objects (empty at v0.1.0).

## Public surface

- `domain::DomainError` — typed error enum.
- `domain::credential_offer` — submodule, namespaced.
- `domain::ids` — submodule, namespaced.
- `domain::pre_auth_code` — submodule, namespaced.

Submodules stay namespaced; the next slice adds re-exports at the
domain root for the public types each submodule introduces
(`CredentialOffer`, `TenantId`, `PreAuthCode`, etc.).

## Layering

The domain layer:

- **Owns**: identifier newtypes, domain entities, value enums, value
  objects, pure operations (state transitions, validation, hashing),
  and a typed error.
- **Does not own**: SQL or DB row types (that is `persistence`),
  HTTP / OIDC4VCI wire shapes (those are the API layers), or any
  cryptographic signing or KMS calls (that is `issuance`).
- Performs no I/O. The domain is sync, dependency-light, and
  trivially unit-testable.

## What ships in v0.1.0

The scaffolding step ships the foundation only:

- `mod.rs` declaring the four submodules and re-exporting
  `DomainError`.
- `errors.rs` with two generic variants (`InvalidInput`,
  `StateTransitionNotAllowed`) that any aggregate can use;
  aggregate-specific variants are added with their aggregates.
- Empty `ids.rs`, `credential_offer.rs`, `pre_auth_code.rs` as
  placeholders for the next slice.

The next slice fills in:

- `ids.rs` — `TenantId`, `IssuerId`, `CredentialOfferId` newtypes
  with `Display`/`Serialize` producing the prefixed form
  (`tenant_…`, `issuer_…`, `offer_…`),
  `FromStr`/`Deserialize` accepting that form, a `bare()` accessor,
  a `generate()` constructor (10-byte CSPRNG, base58-encoded), and
  validation. Prefix discipline per
  [`impl_persistence.md`](impl_persistence.md).
- `credential_offer.rs` — `CredentialOffer` aggregate,
  `CredentialOfferState` enum, `CredentialTypeName` newtype, and
  state-transition methods (`new`, `try_issue`, `cancel`,
  `is_expired`).
- `pre_auth_code.rs` — `PreAuthCode` value object with
  `generate()`, `from_stored()`, and `as_str()` operations. The
  bare value is persisted on `credential_offers.pre_auth_code`
  during the pending window and NULLed at the first terminal-state
  transition; see [`aspect-persistence.md`](aspect-persistence.md)
  for the by-reference offer-fetch exception that requires this.

## Cargo dependencies (current)

No new dependencies at the scaffolding step. The next slice pulls in:

- `bs58` for base58 encoding/decoding of identifiers.
- A CSPRNG source (likely `rand`; already a transitive dep, otherwise
  added explicitly).
- A hash crate (likely `sha2`) for the pre-auth code hash.

## Conventions established

- **Free functions and methods, not traits.** A single domain
  implementation; introducing traits would be premature.
- **State transitions as methods on the aggregate.** The only way
  to change state is through `try_*` methods that enforce
  preconditions and return `DomainError` when invalid.
- **Type-level discipline for secrets.** Bare-secret types are
  distinct from their hashed/stored forms (e.g. `ApiTokenSecret` /
  `ApiTokenHash`, `AccessTokenSecret` / `AccessTokenHash`), and
  persistence-layer signatures take the hash form. The OID4VCI
  pre-auth code is the documented exception: by-reference offer
  fetch requires the bare value to be persisted on
  `credential_offers.pre_auth_code` during the pending window
  (see [`aspect-persistence.md`](aspect-persistence.md)).
- **Pragmatic serde / sqlx coupling.** Domain types may carry
  `Serialize`, `Deserialize`, and `sqlx::FromRow` derives directly.
  Splitting wire / DB / domain shapes is deferred until they
  actually diverge.

## What is deliberately not in v0.1.0

- `Tenant` and `Issuer` entity bodies. With a single seeded tenant
  and issuer, the planned `TenantId` / `IssuerId` newtypes are
  enough; entity structs land when onboarding and the admin UI
  require them.
- Strongly-typed claims per credential type. `serde_json::Value` is
  the planned starting shape on `CredentialOffer.claims`.
- Status list, issued-credential, audit-log, and other aggregate
  types. Wait for their respective slices.
- Strictly-separated DTO types for OIDC4VCI wire formats. See the
  pragmatic coupling note above.

## Open

- Whether `DomainError` keeps a small set of generic variants and
  grows aggregate-specific variants over time, or whether each
  aggregate gets its own error type that funnels into `DomainError`.
  Current lean: one shared enum until variant explosion makes it
  unwieldy.
- Hash function for the pre-auth code. Current lean: SHA-256
  (one-shot, short-lived secret with high entropy; no need for
  password-hashing cost). Revisit if the pre-auth code policy
  changes.
