# Multi-tenancy

This document captures decisions and open questions about how `swiyu-issuer`
hosts multiple organisational entities and the SWIYU issuers that belong to
them.

Status: preliminary. Direction agreed; details still open.

## Tenant vs. issuer

Two distinct concepts that the rest of this document depends on.

**Tenant** — an organisational entity in the deployment environment.
Examples: the canton as a whole, an individual commune, an administrative
unit within the cantonal or communal administration, or another public-
sector entity. "Tenant" is purely an internal concept of `swiyu-issuer`;
wallets and SWIYU infrastructure never see it.

**Issuer** — a SWIYU protocol concept. An issuer is always a SWIYU
Business Partner with an entry in the SWIYU Base Registry, and is
identified by exactly one DID linked to that Business Partner record
by a SWIYU Trust Statement. The issuer is what the wallet sees as the
credential's authority.

**Relationship** — `tenant 1:{0..n} issuer 1:1 did`.

- A tenant has zero or more issuers. The zero case is real and supported
  (see Lifecycle).
- An issuer belongs to exactly one tenant.
- An issuer has exactly one DID for its entire lifetime. The DID is set
  at issuer creation and never changes. Key rotation happens *inside*
  the DID log (a new generation of the key triple), not by minting a
  new DID. A tenant that needs both a `did:tdw` and a `did:webvh`
  presence creates two issuers.

## Target scenario

The reference deployment is a Swiss canton operating an e-government
issuer service for its communes. Two issuer populations are expected:

- ~75 communes, each running an Einwohnerkontrolle (residents'
  registration office), issuing proofs of residency under the commune's
  identity.
- ~70 communal commercial registers, each issuing VCs under their own
  identity.

Total: **200–500 active issuers**, distributed across a smaller number of
tenants (the canton, communes, and administrative units that operate
them). Per-issuer volume is low; small communes may issue only a handful
of credentials per day.

How communes map to tenants is a deployment choice: a commune may be a
single tenant with two issuers (Einwohnerkontrolle and commercial
register), or its administrative units may be modelled as separate
tenants.

## Decision: multi-tenant, not per-tenant containers

`swiyu-issuer` is designed to host many tenants and their issuers in a
single process. Running one container per issuer (or per tenant) is
rejected as the deployment shape.

### Reasoning

- **Operational mass.** 500 deployments mean 500 log streams, 500
  certificate renewals, 500 upgrade rollouts, 500 monitoring targets.
  This dominates every other concern for a cantonal IT operation.
- **Resource waste.** A Rust HTTP service idles at roughly 30–80 MB.
  500 × 50 MB ≈ 25 GB of RAM doing nothing useful for a workload where
  most issuers are quiet most of the time.
- **Onboarding friction.** Per-container onboarding means provisioning a
  container, database, secrets, and DNS for every new commune or new
  issuer. Multi-tenant reduces this to a configuration entry.
- **Same trust domain.** All tenants belong to the same canton and run
  on the same operator's infrastructure. Container isolation is not
  buying a meaningful security boundary here; the canton is the boundary.

### Workload profile

Many tenants and issuers, each independent in identity but homogeneous
in behaviour, each with low individual load. This is the textbook
profile for shared-runtime multi-tenancy.

## Recommended deployment shape

A small fleet of multi-tenant `swiyu-issuer` instances behind a load
balancer, rather than a single instance:

- Provides horizontal scalability and HA.
- Optional segmentation by issuer class — for example, one pool for
  Einwohnerkontrolle issuers and one for commercial-register issuers — if
  the two populations diverge in schemas, retention rules, or admin
  groups.

Per-tenant or per-issuer containers are explicitly not a goal at any
scale below a few thousand high-volume issuers.

## Resources by scope

### Tenant-level (organisational)

- Tenant identity: legal name, type (canton / commune / administrative
  unit / other), contact information.
- Admin users — humans who log into the admin web UI.
- API tokens used by the tenant's business applications.
- Audit log of administrative actions taken within the tenant.
- The set of issuers belonging to this tenant.

### Issuer-level (SWIYU protocol)

- The SWIYU Business Partner record this issuer corresponds to.
- The issuer's DID and its associated Trust Statement.
- Signing keys for that DID. The DID has one or more generations of
  the key triple recorded in its DID log; key rotation happens inside
  the log. Stored on the local filesystem in pre-production maturity,
  in an HSM (or HSM-backed KMS) operated by the canton from production
  maturity onwards. See [`aspect-persistence.md`](aspect-persistence.md)
  for details.
- The set of credential types this issuer is configured to issue, with
  their schemas and per-type configuration.
- Status lists for credentials issued by this issuer.
- Credential offers, issued-credential records, and revocation/suspension
  state for credentials issued by this issuer.
- Branding surfaced in the OIDC issuer metadata (display name, logo,
  locale information). These belong to the issuer because that is what
  the wallet sees, not to the tenant.

### Cross-cutting

- Per-admin-user permissions: a user belongs to one tenant, and may be
  authorised on a subset of that tenant's issuers.
- API token scope: a token belongs to one tenant, and may further be
  restricted to a subset of that tenant's issuers.

## Routing and URLs

The wallet- and business-facing surfaces use different scoping.

- **Wallet-facing OIDC** is **issuer-scoped**. The wallet hits an
  issuer-specific base URL — e.g.,
  `https://issuer.zh.ch/i/<issuer-slug>/.well-known/openid-credential-issuer`,
  or a per-issuer subdomain. The wallet has no notion of a tenant.
- **Management API** is **tenant-authenticated, issuer-per-request**.
  An API token authenticates the tenant; the issuer is selected per
  call (e.g., as a path segment `/api/issuers/<issuer-id>/…` or in the
  request body). The server enforces that the authenticated tenant
  owns the chosen issuer.
- **Admin web UI** is **tenant-scoped** by login. Within the UI the
  operator picks which of the tenant's issuers to act on.

## Lifecycle

A tenant with **zero issuers** is valid and supported. It enables staged
onboarding: a commune can be admitted to the system (admin users
provisioned, contact information recorded) before its SWIYU Business
Partner registration and Trust Statement are in place. Issuance is
gated until at least one issuer is registered for the tenant.

Registering a new issuer for a tenant requires evidence of the SWIYU
Business Partner record and the DID covered by a Trust Statement.
The exact registration flow is an open question.

## Risks and mitigations

The core risk of multi-tenancy is **scoping**: every query and operation
must be bound to the correct tenant and, where applicable, the correct
issuer within that tenant. A missed scope is a cross-tenant or
cross-issuer data leak.

Mitigations to apply consistently:

- Newtypes `TenantId` and `IssuerId`, both carried explicitly by every
  repository function rather than via thread-local or implicit context.
- A `TenantContext` produced by authentication at the request boundary
  and threaded into handlers as an extractor argument.
- A single helper at the request boundary that validates `(tenant_id,
  issuer_id)` ownership, called from every handler that takes an
  issuer.
- Postgres row-level security as defense in depth: the database itself
  refuses to return rows for the wrong tenant or issuer, even if
  application code omits the filter.
- Integration tests that always run with at least two tenants and at
  least two issuers per tenant populated, asserting isolation in both
  directions.

## Open questions

- **Tenant and issuer identification per request.** Subdomain, URL path
  prefix, or derivation from the auth token — and the choice may differ
  between the wallet-facing surface (issuer) and the business-facing
  surface (tenant).
- **Isolation strength.** Logical (shared schema with `tenant_id` /
  `issuer_id` columns) vs. schema-per-tenant vs. database-per-tenant.
  Default is logical; raise the strength only if a concrete compliance
  or noisy-neighbour concern appears.
- **Tenant and issuer onboarding flows.** Self-service via the admin UI?
  Operator-managed via CLI? Pre-provisioned from the canton's identity
  directory? Issuer registration in particular needs a defined flow that
  ties a Business Partner record and a Trust Statement to a tenant.
- **Cross-tenant roles.** Whether a canton-level "platform admin" role
  exists with read-only visibility across tenants, and how that surface
  is exposed.
