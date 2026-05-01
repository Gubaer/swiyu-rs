# Implementation: management API (v0.1.0)

This document captures concrete implementation decisions for the
management API layer (`issuer-mgmt` binary) as of release v0.1.0. For
the multi-tenancy concepts the layer enforces see
[`aspect-multi-tenancy.md`](aspect-multi-tenancy.md). For the
identifier strategy reflected on the wire see
[`impl_persistence.md`](impl_persistence.md). For the framework lean
see [`aspect-technology.md`](aspect-technology.md).

Status: preliminary; living document. Reflects the v0.1.0
walking-skeleton scope — a single endpoint that creates a credential
offer.

## Frame

The first durchstich is "a business application submits a request to
create a credential offer." The single endpoint that has to work
end-to-end is `POST .../credential-offers`. Everything else in
`issuer-mgmt` is the minimum plumbing needed to make that endpoint
reachable, observable, testable, and tenant-scoped.

## Module layout

`swiyu-issuer/src/api_management/`:

- `mod.rs` — `router(state) -> axum::Router`; re-exports.
- `state.rs` — `AppState` (pool, clock, config), cheaply cloneable.
- `error.rs` — `ApiError` enum and `IntoResponse` mapping; `From`
  conversions for `DomainError` and `PersistenceError`.
- `auth.rs` — `TenantContext` axum extractor (stub at v0.1.0).
- `dto.rs` — request and response shapes for the management API.
- `credential_offers.rs` — POST handler for creating credential
  offers.

`swiyu-issuer/src/bin/issuer-mgmt.rs` stays thin: load config →
connect pool → run migrations → build `Router` → bind and serve with
graceful shutdown.

## Public surface

- `api_management::router(state)` — single entry point; the binary
  and integration tests share the same router.
- `api_management::AppState` — handle to pool, clock, and config.
- Everything else is internal.

## v0.1.0 endpoint

`POST /api/v1/issuers/{issuer_id}/credential-offers`

- Path segment: bare base58 issuer id (per
  [`impl_persistence.md`](impl_persistence.md) URL convention).
- Request body:
  ```json
  {
    "vct": "urn:communal:local-residence-id",
    "claims": {
      "family_name": "...",
      "given_name": "...",
      "birth_date": "...",
      "commune_bfs": 4003,
      "commune_name": "Buchs SG",
      "valid_until": "..."
    },
    "expires_in_seconds": 600
  }
  ```
- Response body (201 Created):
  ```json
  {
    "id": "offer_…",
    "pre_auth_code": "…",
    "offer_deeplink": "openid-credential-offer://?credential_offer_uri=…",
    "expires_at": "2026-05-01T12:34:56Z"
  }
  ```
- The `pre_auth_code` is returned exactly once at offer creation;
  only its hash is persisted (per
  [`aspect-persistence.md`](aspect-persistence.md)).
- JSON bodies use the **prefixed** form for ids (`offer_…`,
  `issuer_…`); URL paths use the bare form. The add/strip happens
  inside the `Serialize`/`Deserialize` of `domain::ids`, not in
  handlers.
- The `vct` field is the SD-JWT VC type identifier (a URI). It
  replaces the earlier `credential_type` working name. See
  [`impl_credential_schema.md`](impl_credential_schema.md) for the
  schema lookup and validation step that runs against this value
  before the offer is persisted.

Operational endpoints:

- `GET /healthz` — always 200; liveness only.
- `GET /readyz` — 200 if `pool.acquire()` succeeds, 503 otherwise.

## Claims validation

Before persisting the offer, the handler validates `claims` against
the JSON Schema bundled for the requested `vct`:

- `AppState` carries a `HashMap<Vct, Arc<jsonschema::Validator>>`
  built once at startup from
  `swiyu-issuer/schemas/` (see
  [`impl_credential_schema.md`](impl_credential_schema.md)).
- An unknown `vct` returns `ApiError::UnknownVct` (400).
- A schema mismatch returns `ApiError::ClaimsValidationFailed`
  (400) with JSON-Pointer paths and validator messages in
  `details`.
- v0.1.0 ships exactly one schema:
  `urn:communal:local-residence-id`.

## Tenant scoping at the request boundary

Per [`aspect-multi-tenancy.md`](aspect-multi-tenancy.md):

- `TenantContext` is an axum extractor. At v0.1.0 it returns the
  seeded tenant id from the `DEFAULT_TENANT_ID` env var. Real
  API-token authentication replaces the body of the extractor in a
  later slice; handler signatures do not change.
- A single helper
  `require_issuer_owned_by_tenant(&mut conn, &tenant_id, &issuer_id)`
  runs once at the start of every handler that takes an `issuer_id`
  from the path. Returns `ApiError::NotFound` on miss. This is the
  request-boundary ownership check the multi-tenancy spec calls for.
- Persistence functions already require `TenantId` and `IssuerId` by
  signature, so the boundary check is defense in depth, not the only
  gate.

## Error mapping

A single `ApiError` enum implements `IntoResponse` with a fixed
status-code table:

| Source                                     | HTTP          |
|--------------------------------------------|---------------|
| `PersistenceError::NotFound`               | 404           |
| `PersistenceError::UniqueViolation`        | 409           |
| `PersistenceError::Db`                     | 500 (logged)  |
| `DomainError::InvalidInput`                | 400           |
| `DomainError::StateTransitionNotAllowed`   | 409           |
| `ApiError::Unauthorised`                   | 401           |
| `ApiError::Forbidden`                      | 403           |
| `ApiError::UnknownVct`                     | 400           |
| `ApiError::ClaimsValidationFailed`         | 400           |
| `axum::extract::rejection::JsonRejection`  | 400           |

Response body uses a small fixed shape:

```json
{ "error": "invalid_input", "details": "..." }
```

`application/problem+json` is deferred until there is a reason to
adopt it.

## Configuration

Environment variables consumed by `issuer-mgmt`:

- `DATABASE_URL` — Postgres connection string.
- `BIND_ADDR` — listen address, e.g. `0.0.0.0:8080`.
- `ISSUER_BASE_URL` — public base URL embedded into the
  `offer_deeplink` (used as the host of the wallet-facing
  `credential_offer_uri`).
- `DEFAULT_TENANT_ID` — bare base58 tenant id used by the
  `TenantContext` stub. Removed when API-token auth lands.

No config file at v0.1.0.

## Cargo dependencies

Added to `swiyu-issuer/Cargo.toml`:

```toml
axum = "0.8"
tower = "0.5"
tower-http = { version = "0.6", features = ["trace"] }
chrono = { version = "0.4", features = ["serde"] }
jsonschema = "0.30"
```

`jsonschema` is added by this slice for claims validation; rationale
in [`impl_credential_schema.md`](impl_credential_schema.md).

`utoipa` (OpenAPI) deliberately absent. The HTTP-framework decision
is recommended-but-not-decided in
[`aspect-technology.md`](aspect-technology.md); OpenAPI generation
can be retrofitted once axum is formally committed.

## Conventions established

- **Single router builder.** `api_management::router(state)` is the
  only place routes are assembled. The binary and integration tests
  use it identically.
- **Handlers stay thin.** A handler validates input, runs the
  ownership check, calls into `domain` and `persistence`, and maps
  the result. Business logic lives in `domain`; SQL lives in
  `persistence`.
- **Prefix add/strip at the boundary.** Handlers and DTOs use
  `domain::ids` newtypes; serde derives carry the prefix discipline
  through.
- **Error conversions via `?`.** `DomainError` and `PersistenceError`
  reach the handler as `ApiError` through `From` impls; no manual
  match-and-remap in handlers.
- **No global state beyond `AppState`.** Pool, clock, and config are
  threaded explicitly. No `lazy_static`, no thread-locals.

## Tests

- Unit tests inside the handler module exercising request/response
  shapes against an in-process router and a real Postgres pool.
- One integration test under `swiyu-issuer/tests/` driving the happy
  path end-to-end: create offer → assert row in `credential_offers`
  → assert response shape and that `pre_auth_code` is returned only
  in the body, with the row holding only `pre_auth_code_hash`.
- The integration test seeds a **second** tenant and issuer and
  asserts that creating an offer under tenant A's issuer while the
  `TenantContext` resolves to tenant B returns 404. Every
  multi-tenant test added from now on carries this asymmetry.

## Suggested slice ordering

The handler depends on domain and persistence pieces still in
placeholder form:

1. Fill `domain::ids` and `domain::pre_auth_code` (already the
   next-slice work in [`impl_domain.md`](impl_domain.md)).
2. Implement `persistence::credential_offers::insert` and
   `find_by_id`.
3. Land the scaffolding above with the single POST endpoint wired
   through.
4. Smoke test against the seeded tenant and issuer with `curl`.

Steps 1 and 2 may land together or separately. Step 3 must come last.

## What is deliberately not in v0.1.0

- API-token authentication. `TenantContext` is a stub reading from
  env.
- OpenAPI generation (`utoipa` or equivalent).
- OIDC-side endpoints (`/.well-known/openid-credential-issuer`,
  token, credential). Those belong to the `issuer-oidc` binary and
  ship in a separate slice.
- Rate limiting, CORS policy, cross-service request-id propagation.
  Wait until there is a real client.
- Listing, pagination, cancellation, and status endpoints on
  credential offers. Only creation in v0.1.0.
- Admin web UI of any kind. Decision deferred per
  [`aspect-technology.md`](aspect-technology.md).
- `application/problem+json` error bodies.

## Open

- **HTTP framework lock-in.** This spec commits to `axum`;
  [`aspect-technology.md`](aspect-technology.md) still records the
  decision as deferred. If the commitment stands, that document
  needs updating in the same slice. Cost of switching frameworks
  once one endpoint exists is still small.
- **Offer deeplink construction.** Exact shape of the
  `credential_offer_uri` (and how it is embedded in the
  `openid-credential-offer://` URI) is OID4VCI-driven; pin the
  format when implementing the handler.
- **Integration-test database.** `testcontainers` (hermetic, slow
  first run) vs. relying on a local `DATABASE_URL`. Affects CI more
  than code shape; default to local URL with a documented setup
  step.
- **`expires_in_seconds` bounds.** Minimum and maximum bounds and
  the default when omitted. Lean: default 10 minutes, max 1 hour;
  finalise with the handler.
