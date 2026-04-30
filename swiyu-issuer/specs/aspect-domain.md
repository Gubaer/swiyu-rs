# Domain concepts and terminology

This document records vocabulary decisions for domain concepts that
recur in the issuer's data model, code, and specifications. Where
the relevant standards differ on terminology, this fixes which term
we use internally and why.

Status: preliminary; living document.

## Verifiable credentials: type, configuration, schema

Three related but distinct concepts in the standards. We use the
terminology precisely, while collapsing two of them into a single
domain entity (see *Domain entity model* below).

### CredentialType — the kind of credential

The identity of what the credential certifies. Maps to:

- **W3C VC Data Model**: an entry in the JSON-LD `type` array beyond
  `VerifiableCredential`, e.g. `ProofOfResidencyCredential`.
- **SD-JWT VC** (the format SWIYU uses): the `vct` claim
  (Verifiable Credential **T**ype). A short string or URI identifying
  the type.
- Informally: "VC type" or "credential type".

### CredentialConfiguration — the issuer's declaration

What an issuer declares in its OID4VCI metadata to say *"I can issue
credentials of this kind, in this format, with these display
properties, requiring these proofs."* Maps to:

- **OID4VCI**: an entry in the
  `credential_configurations_supported` map on the issuer,
  identified by a `credential_configuration_id`.

### CredentialSchema — claim validation

The JSON Schema (or other schema document) that validates the
claims of a credential instance. Maps to:

- **W3C VC Data Model**: the `credentialSchema` property of a
  credential, pointing at a JSON Schema 2020-12 (or other)
  validation document.

## Domain entity model

We collapse `CredentialType` and `CredentialConfiguration` into a
single domain entity called **`CredentialType`**. At v0.1.0 the
relationship between the two standards' concepts is 1:1 in our
deployment shape (one configuration per type per issuer), so
keeping them as two entities would only add boilerplate. The
unified `CredentialType` carries:

- the type identity (`vct`, claim schema reference);
- the OID4VCI configuration (format, display, signing algorithm,
  binding methods, accepted proof types).

`CredentialSchema` remains a **separate entity**: it can be shared
or standardised independently, and it represents a specific concern
(claim validation) distinct from type identity and protocol
configuration.

A separate `CredentialConfiguration` entity may be split out later
only if a real reason appears — for example, the same type exposed
by the same issuer in two different formats (`vc+sd-jwt` plus
`mso_mdoc`).

## Cardinalities

- **Tenant → Issuer**: 1:{0..n}; see
  [`aspect-multi-tenancy.md`](aspect-multi-tenancy.md).
- **Issuer → CredentialType**: 1:n. Each `CredentialType` belongs
  to exactly one issuer.
- **CredentialType → CredentialSchema**: 1:1 at any given time.
  Schema versioning is a future concern, not modelled in v0.1.0.
- **CredentialType → CredentialOffer**: 1:n.
- **CredentialOffer → IssuedCredential**: 1:{0..1}.

### `vct` sharing across issuers

The `vct` value (the protocol-level type identifier) is a string
field on `CredentialType`. **Different issuers can have
`CredentialType` rows with the same `vct` value** — for example,
when many communes adopt a federal standard `ProofOfResidency`
type. Each issuer holds its own row because:

- Tenant isolation is the default; no cross-tenant data sharing.
- Each issuer decides independently when to start issuing.
- Schemas can drift slightly between issuers (e.g., an optional
  field one commune carries that another doesn't).

The redundancy is the right tradeoff for our multi-tenant model.

## Naming rules

- Use **`CredentialType`** as the primary domain entity. It carries
  both the type identity (`vct`, schema reference) and the OID4VCI
  configuration (format, display, signing algorithm, binding
  methods).
- Use **`CredentialSchema`** for the JSON Schema validation
  document. It is a separate entity from `CredentialType`.
- *"CredentialConfiguration"* is **not a separate entity** in our
  domain. Keep the term for protocol-level discussion (when
  referencing OID4VCI's `credential_configurations_supported`),
  but expect to find its data on `CredentialType`.
- Avoid the bare term *"VC schema"* — in the standards it
  specifically means the validation document, narrower than how the
  phrase is often used colloquially.
- Avoid `VcType` / `VCType` in Rust type names. `CredentialType`
  reads better and matches CLAUDE.md's preference for full names.
- The literal claim names from the wire format (`vct`,
  `credentialSchema`, `credential_configuration_id`) stay as-is
  wherever the protocol requires them. Do not rename them in
  serialised output.

## Layering

The domain entities live in their own modules when they are added:

- `domain::credential_type` — type identity, schema reference, and
  OID4VCI configuration.
- `domain::credential_schema` — JSON Schema document.

Relationship: a `CredentialOffer` references a `CredentialType`.
An issued credential embeds the `vct` (from its `CredentialType`)
and optionally the schema reference per W3C semantics.

## Open

- Whether `CredentialSchema` is stored inline as `JSONB` on the
  `CredentialType` row, or referenced by URL only (with a cached
  copy for stability and offline validation). Defer until schema
  usage becomes concrete.
- When (if ever) to re-introduce `CredentialConfiguration` as a
  separate entity. Trigger: the same type exposed by the same
  issuer in two different formats, or other 1:n divergence between
  type and configuration.
- Schema versioning model. Trigger: a deployed standard schema
  evolves and the issuer needs to validate already-issued
  credentials against the schema in force at issuance time.
