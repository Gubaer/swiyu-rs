# Implementation: management API (v0.1.1)

This document captures concrete implementation decisions for the management API layer (`issuer-mgmt` binary) as of release v0.1.1. For the multi-tenancy concepts the layer enforces see [`aspect-multi-tenancy.md`](aspect-multi-tenancy.md). For the identifier strategy reflected on the wire see [`impl_persistence.md`](impl_persistence.md). For the framework lean see [`aspect-technology.md`](aspect-technology.md).

Status: preliminary; living document. v0.1.0 shipped the walking skeleton — POST and GET on credential offers, plus liveness and readiness probes. v0.1.1 extends the surface with cancel, list, and status endpoints; everything else from v0.1.0 carries forward unchanged.

## Frame

The v0.1.0 durchstich was "a business application submits a request to create a credential offer." That endpoint and its GET read-back are in place. v0.1.1 closes the gaps a business application hits next: cancelling an offer it no longer wants honoured, listing the offers it has open, and polling a lightweight status endpoint without pulling the full offer body each time.

## Module layout

`swiyu-issuer/src/api_management/`:

- `mod.rs` — `router(state) -> axum::Router`; re-exports.
- `state.rs` — `AppState` (pool, clock, config), cheaply cloneable.
- `error.rs` — `ApiError` enum and `IntoResponse` mapping; `From` conversions for `DomainError` and `PersistenceError`.
- `auth.rs` — `TenantContext` axum extractor (stub at v0.1.0).
- `dto.rs` — request and response shapes for the management API.
- `schemas.rs` — startup-time loading of the bundled JSON Schemas keyed by `vct`.
- `credential_offers.rs` — handlers for the credential-offer endpoints (create, fetch, cancel, list, status).

`swiyu-issuer/src/bin/issuer-mgmt.rs` stays thin: load config → connect pool → run migrations → build `Router` → bind and serve with graceful shutdown.

## Public surface

- `api_management::router(state)` — single entry point; the binary and integration tests share the same router.
- `api_management::AppState` — handle to pool, clock, and config.
- Everything else is internal.

## Endpoints

The management API at v0.1.1 exposes five offer endpoints under `/api/v1/issuers/{issuer_id}` plus the two operational probes. Path segments use bare base58 ids (per [`impl_persistence.md`](impl_persistence.md) URL convention); JSON bodies use the prefixed form (`offer_…`, `issuer_…`). Add/strip happens inside the `Serialize`/`Deserialize` of `domain::ids`, never in handlers.

### POST .../credential-offers — create (v0.1.0)

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
- The `pre_auth_code` is returned exactly once at offer creation; only its hash is persisted (per [`aspect-persistence.md`](aspect-persistence.md)).
- The `vct` field is the SD-JWT VC type identifier (a URI). See [`impl_credential_schema.md`](impl_credential_schema.md) for the schema lookup and validation step that runs against this value before the offer is persisted.

### GET .../credential-offers/{offer_id} — fetch (v0.1.0, extended in v0.1.1)

Returns the full offer record. The `state` field reports `expired` whenever the stored state is `pending` but `expires_at` has passed; stored state is not rewritten on read.

Response (200):

```json
{
  "id": "offer_…",
  "issuer_id": "issuer_…",
  "vct": "urn:communal:local-residence-id",
  "claims": { "...": "..." },
  "state": "pending",
  "expires_at": "2026-05-01T12:34:56Z",
  "created_at": "2026-05-01T12:24:56Z",
  "issued_at": null,
  "cancelled_at": null
}
```

`issued_at` and `cancelled_at` are added in v0.1.1 alongside the [schema additions](#schema-additions-for-v011); both are `null` until the offer transitions into the corresponding state. The hand-written [`openapi.yml`](../openapi.yml) needs a matching update when this slice lands.

### POST .../credential-offers/{offer_id}/cancel — cancel (v0.1.1)

Marks an offer `cancelled` and stamps `cancelled_at`. Returns the full offer body (same shape as fetch). Idempotent.

- 200 if the offer transitioned to `cancelled`, or was already `cancelled`.
- 409 if the offer is in a terminal state other than `cancelled` (i.e. `issued`).
- 404 if the offer is not found or owned by another tenant.

Cancelling a stored-`pending` offer whose `expires_at` has passed is allowed and reported back as `cancelled`. The expiry-on-read rule governs how `state` is reported in fetch and list responses; it does not gate state transitions.

### GET .../credential-offers — list (v0.1.1)

Lists offers belonging to the issuer, newest first. Cursor-paginated.

Query parameters:

- `limit` — page size, 1..=100, default 25.
- `cursor` — opaque cursor from the previous page; omitted on the first page.
- `state` — optional filter on the **observed** state, one of `pending` | `issued` | `cancelled` | `expired`.

Response (200):

```json
{
  "items": [
    /* same shape as GET /{offer_id} */
  ],
  "next_cursor": "…"
}
```

`next_cursor` is `null` when the last page is reached. Pagination sorts by `(created_at DESC, id DESC)`; the cursor encodes those two values opaquely (clients must not parse it). State filtering applies to the observed projection, so a row stored as `pending` past its `expires_at` is returned by `state=expired`, not `state=pending`.

### GET .../credential-offers/{offer_id}/status — status (v0.1.1)

Lightweight status check for polling business applications. No claims, no PII.

Response (200):

```json
{
  "id": "offer_…",
  "state": "pending",
  "expires_at": "2026-05-01T12:34:56Z",
  "issued_at": null,
  "cancelled_at": null
}
```

`state` follows the same observed-state rule as fetch and list. `issued_at` and `cancelled_at` are `null` until the offer transitions into the corresponding state.

### Operational probes

- `GET /healthz` — always 200; liveness only.
- `GET /readyz` — 200 if `pool.acquire()` succeeds, 503 otherwise.

## Claims validation

Before persisting the offer, the handler validates `claims` against the JSON Schema bundled for the requested `vct`:

- `AppState` carries a `HashMap<Vct, Arc<jsonschema::Validator>>` built once at startup from `swiyu-issuer/schemas/` (see [`impl_credential_schema.md`](impl_credential_schema.md)).
- An unknown `vct` returns `ApiError::UnknownVct` (400).
- A schema mismatch returns `ApiError::ClaimsValidationFailed` (400) with JSON-Pointer paths and validator messages in `details`.
- v0.1.0 ships exactly one schema: `urn:communal:local-residence-id`.

## Schema additions for v0.1.1

The cancel and status endpoints surface two new timestamp columns on `credential_offers`:

- `cancelled_at TIMESTAMPTZ NULL` — set when the offer transitions to `cancelled`; null otherwise.
- `issued_at TIMESTAMPTZ NULL` — set when wallet redemption succeeds and state moves to `issued`. The transition itself is driven by the OIDC binary in a later slice; the column ships now so the management API contract is stable.

A new migration adds both columns nullable. `cancel` lives in `persistence::credential_offers` (this slice). `mark_issued` lives in the separate `persistence::oidc::credential_offers` namespace introduced by [`impl_api_oidc.md`](impl_api_oidc.md), so the management binary cannot accidentally invoke it.

## Tenant scoping at the request boundary

Per [`aspect-multi-tenancy.md`](aspect-multi-tenancy.md):

- `TenantContext` is an axum extractor. As of v0.1.2 it derives the tenant from the API token presented in `Authorization: Bearer tok_<base58>`; see [`impl_auth.md`](impl_auth.md). Handler signatures are unchanged from v0.1.0 — the swap was local to the extractor body, as promised when the stub was introduced.
- A single helper `require_issuer_owned_by_tenant(&mut conn, &tenant_id, &issuer_id)` runs once at the start of every handler that takes an `issuer_id` from the path. Returns `ApiError::NotFound` on miss. This is the request-boundary ownership check the multi-tenancy spec calls for.
- Persistence functions already require `TenantId` and `IssuerId` by signature, so the boundary check is defense in depth, not the only gate.

## Error mapping

A single `ApiError` enum implements `IntoResponse` with a fixed status-code table:

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

`application/problem+json` is deferred until there is a reason to adopt it.

## Configuration

Environment variables consumed by `issuer-mgmt`:

- `DATABASE_URL` — Postgres connection string.
- `BIND_ADDR` — listen address, e.g. `0.0.0.0:8080`.
- `ISSUER_BASE_URL` — public base URL embedded into the `offer_deeplink` (used as the host of the wallet-facing `credential_offer_uri`).
- (Authentication is now driven by API tokens; the `DEFAULT_TENANT_ID` stub from v0.1.0 is gone. See [`impl_auth.md`](impl_auth.md) for the dev-token convenience used by `cargo run` and the `test-commands.txt` examples.)

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

`jsonschema` is used for claims validation; rationale in [`impl_credential_schema.md`](impl_credential_schema.md). `axum` is the HTTP framework in use across both binaries.

`utoipa` (OpenAPI generation) deliberately absent. The hand-written [`swiyu-issuer/openapi.yml`](../openapi.yml) is the contract for now; generation can be retrofitted later if drift between the spec and the handlers becomes a real problem.

## Conventions established

- **Single router builder.** `api_management::router(state)` is the only place routes are assembled. The binary and integration tests use it identically.
- **Handlers stay thin.** A handler validates input, runs the ownership check, calls into `domain` and `persistence`, and maps the result. Business logic lives in `domain`; SQL lives in `persistence`.
- **Prefix add/strip at the boundary.** Handlers and DTOs use `domain::ids` newtypes; serde derives carry the prefix discipline through.
- **Error conversions via `?`.** `DomainError` and `PersistenceError` reach the handler as `ApiError` through `From` impls; no manual match-and-remap in handlers.
- **No global state beyond `AppState`.** Pool, clock, and config are threaded explicitly. No `lazy_static`, no thread-locals.

## Tests

- Unit tests inside the handler module exercising request/response shapes against an in-process router and a real Postgres pool.
- Integration tests under `swiyu-issuer/tests/` cover each endpoint end-to-end:
- Create: offer is persisted, the bare `pre_auth_code` is returned in the body and stored on the row until the first terminal-state transition.
- Fetch: returns the offer; reports `expired` for a stored `pending` row past `expires_at`.
- Cancel (v0.1.1): idempotent on already-cancelled, 409 on `issued`, succeeds on a stored-`pending` row past expiry.
- List (v0.1.1): paginates across at least two pages, `state=expired` returns rows stored as `pending` past `expires_at`.
- Status (v0.1.1): returns the lightweight projection in each of `pending`, `expired`, `cancelled`, and `issued` states.
- Every test seeds a **second** tenant and issuer and asserts cross-tenant access returns 404. Every multi-tenant test added from now on carries this asymmetry.

## Suggested slice ordering (v0.1.1)

1. Migration adding `cancelled_at` and `issued_at` columns to `credential_offers`.
2. Domain: a `cancel` transition on `CredentialOffer` plus a state-machine guard rejecting transitions out of `issued`. Optionally a small `OfferStatus` projection type for the status endpoint.
3. Persistence: `cancel(conn, tenant, issuer, offer_id)`, `list(conn, tenant, issuer, page)`, and `find_status(conn, tenant, issuer, offer_id)`.
4. DTOs and handlers for the three new endpoints, wired into the single `router(state)`.
5. Integration tests per the Tests section above.

Steps 1–3 may land together or in separate commits. Step 4 must come last.

## What is deliberately not in v0.1.1

- API-token authentication. `TenantContext` is still a stub reading from env.
- OpenAPI generation (`utoipa` or equivalent). The hand-written `swiyu-issuer/openapi.yml` is the contract for now.
- OIDC-side endpoints (`/.well-known/openid-credential-issuer`, token, credential). Those belong to the `issuer-oidc` binary and ship in a separate slice.
- Rate limiting, CORS policy, cross-service request-id propagation. Wait until there is a real client.
- Filtering offers by `vct`, by date range, or by free-text claim search. Only `state` filtering at v0.1.1.
- Webhook notifications when an offer transitions state. Polling via the status endpoint is the v0.1.1 contract.
- Admin web UI of any kind. Decision deferred per [`aspect-technology.md`](aspect-technology.md).
- `application/problem+json` error bodies.

## Open

- **Cursor encoding.** Current lean: an opaque base64 of `created_at|id`, server-validated. Acceptable to clients but a schema change to the cursor format breaks paging in flight; pin the encoding before the management API gains real consumers.
- **`state=expired` filter semantics.** Filtering by an observed (not stored) state forces the SQL to project `expires_at` against `now()`. Confirm this is the right ergonomic trade-off versus a separate `expired_after` query parameter that lets clients filter on stored state and time directly.
- **Integration-test database.** `testcontainers` (hermetic, slow first run) vs. relying on a local `DATABASE_URL`. Affects CI more than code shape; default to local URL with a documented setup step.
