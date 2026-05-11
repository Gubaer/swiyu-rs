# Domain concepts and terminology

This document records vocabulary decisions for domain concepts that recur in the issuer's data model, code, and specifications. Where the relevant standards differ on terminology, this fixes which term we use internally and why.

Status: preliminary; living document.

## Verifiable credentials: type, configuration, schema

Three related but distinct concepts in the standards. We use the terminology precisely, while collapsing two of them into a single domain entity (see *Domain entity model* below).

### CredentialType — the kind of credential

The identity of what the credential certifies. Maps to:

- **W3C VC Data Model**: an entry in the JSON-LD `type` array beyond `VerifiableCredential`, e.g. `ProofOfResidencyCredential`.
- **SD-JWT VC** (the format SWIYU uses): the `vct` claim (Verifiable Credential **T**ype). A short string or URI identifying the type.
- Informally: "VC type" or "credential type".

### CredentialConfiguration — the issuer's declaration

What an issuer declares in its OID4VCI metadata to say *"I can issue credentials of this kind, in this format, with these display properties, requiring these proofs."* Maps to:

- **OID4VCI**: an entry in the `credential_configurations_supported` map on the issuer, identified by a `credential_configuration_id`.

### CredentialSchema — claim validation

The JSON Schema (or other schema document) that validates the claims of a credential instance. Maps to:

- **W3C VC Data Model**: the `credentialSchema` property of a credential, pointing at a JSON Schema 2020-12 (or other) validation document.

## Domain entity model

We collapse `CredentialType`, `CredentialConfiguration`, and `CredentialSchema` into a single domain entity called **`CredentialType`**. The reasoning:

- The relationship between the W3C `CredentialType` and the OID4VCI `CredentialConfiguration` is 1:1 in our deployment shape (one configuration per type per issuer), so keeping them as two entities would only add boilerplate.
- The relationship between `CredentialType` and `CredentialSchema` is also 1:1 within a tenant. The tenant ownership model (see [`aspect-credential-type.md`](aspect-credential-type.md)) rules out cross-tenant sharing of either, so a separate schema entity earns no reuse benefit.

The unified `CredentialType` carries:

- the type identity (`vct`);
- the OID4VCI configuration (format, display, signing algorithm, binding methods, accepted proof types);
- the JSON Schema validating the credential's claims, stored as a document blob on the `CredentialType` row.

A separate `CredentialConfiguration` entity may be split out later only if a real reason appears — for example, the same type exposed by the same issuer in two different formats (`vc+sd-jwt` plus `mso_mdoc`). A separate `CredentialSchema` entity may be revisited if cross-tenant schema sharing or schema versioning ever becomes a real requirement; neither is a current need.

## Cardinalities

- **Tenant → Issuer**: 1:{0..n}; see [`aspect-multi-tenancy.md`](aspect-multi-tenancy.md).
- **Tenant → CredentialType**: 1:n. Each `CredentialType` belongs to exactly one tenant. Issuer ↔ `CredentialType` is an n:m assignment within a tenant — see [`aspect-credential-type.md`](aspect-credential-type.md).
- **CredentialType → CredentialOffer**: 1:n.
- **CredentialOffer → IssuedCredential**: 1:{0..1}.

The JSON Schema validating a credential's claims is a property of `CredentialType` (1:1 within the row), not a separate entity in the cardinality graph. Schema versioning is a future concern, not modelled today.

### `vct` sharing across issuers

The `vct` value (the protocol-level type identifier) is a string field on `CredentialType`. **Different issuers can have `CredentialType` rows with the same `vct` value** — for example, when many communes adopt a federal standard `ProofOfResidency` type. Each issuer holds its own row because:

- Tenant isolation is the default; no cross-tenant data sharing.
- Each issuer decides independently when to start issuing.
- Schemas can drift slightly between issuers (e.g., an optional field one commune carries that another doesn't).

The redundancy is the right tradeoff for our multi-tenant model.

## Naming rules

- Use **`CredentialType`** as the primary domain entity. It carries the type identity (`vct`), the OID4VCI configuration (format, display, signing algorithm, binding methods), and the JSON Schema validating the credential's claims.
- Use **`CredentialSchema`** as a *concept name* for the JSON Schema validation document. It is **not** a separate domain entity; it is a property of `CredentialType` stored as a document blob.
- *"CredentialConfiguration"* is **not a separate entity** in our domain. Keep the term for protocol-level discussion (when referencing OID4VCI's `credential_configurations_supported`), but expect to find its data on `CredentialType`.
- Avoid the bare term *"VC schema"* — in the standards it specifically means the validation document, narrower than how the phrase is often used colloquially.
- Avoid `VcType` / `VCType` in Rust type names. `CredentialType` reads better and matches CLAUDE.md's preference for full names.
- The literal claim names from the wire format (`vct`, `credentialSchema`, `credential_configuration_id`) stay as-is wherever the protocol requires them. Do not rename them in serialised output.

## Layering

The domain entities live in their own modules when they are added:

- `domain::credential_type` — type identity, OID4VCI configuration, and the JSON Schema validating the credential's claims.

Relationship: a `CredentialOffer` references a `CredentialType`. An issued credential embeds the `vct` (from its `CredentialType`) and optionally a `credentialSchema` reference per W3C semantics; that reference resolves to a route on the issuer that serves the schema document held on the `CredentialType` row.

## Open

- When (if ever) to re-introduce `CredentialConfiguration` as a separate entity. Trigger: the same type exposed by the same issuer in two different formats, or other 1:n divergence between type and configuration.
- Schema versioning model. Trigger: a deployed standard schema evolves and the issuer needs to validate already-issued credentials against the schema in force at issuance time.
