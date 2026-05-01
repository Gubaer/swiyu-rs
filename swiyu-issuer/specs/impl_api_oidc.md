# Implementation: OIDC API (v0.1.3)

This document captures concrete implementation decisions for the
wallet-facing OIDC API layer (`issuer-oidc` binary). For the
multi-tenancy model that governs URL shape see
[`aspect-multi-tenancy.md`](aspect-multi-tenancy.md). For the
identifier strategy reflected on the wire see
[`impl_persistence.md`](impl_persistence.md). For the management-side
counterpart see [`impl_api_management.md`](impl_api_management.md).
For the ephemeral-state model see
[`aspect-persistence.md`](aspect-persistence.md).

Status: preliminary; living document. Earlier slices stood up the
management API, persistence, and API-token auth. This slice adds
the wallet-facing surface that turns a `pending` credential offer
into an `issued` SD-JWT VC.

## Frame

The management API hands a business application a deeplink
(`openid-credential-offer://?credential_offer_uri=…`) and a
pre-authorised code. From the wallet's point of view nothing has
been issued yet: the deeplink is a pointer to a `credential_offer`
body the wallet still has to fetch, redeem at the token endpoint,
and convert into a credential at the credential endpoint.

This slice provides those wallet-facing endpoints and is the first
writer of the `issued` state on `credential_offers`.

## Scope

**In scope (v0.1.3):**

- Pre-authorised code grant flow only. No authorisation code grant,
  no DPoP, no `client_id` registration, no PAR.
- One credential format: SD-JWT VC (`vc+sd-jwt`). One credential
  configuration: `urn:communal:local-residence-id`.
- Issuer signing keys loaded from the `swiyu-didtool` filesystem
  key store, same convention used elsewhere in the codebase.
- `did:tdw` 0.3 issuer DIDs, validated end-to-end against the SWIYU
  integration registry. `did:webvh` 1.0 code paths exist but are
  not exercised in tests; treat any `did:webvh` behaviour as
  unverified (per `CLAUDE.md`).
- One pre-issuance state-list reservation per offer is **out of
  scope** — credentials issued in v0.1.3 carry no `status` claim.
  Status integration lands once the status-list slice is in.

**Deliberately not in v0.1.3** (full list at the end):

- Transaction codes (the second-factor on the pre-auth grant).
- Issuer-set `c_nonce` rotation tied to access-token usage.
- `credential_response_encryption`.
- Batch credential endpoint, deferred credential endpoint.
- Notification endpoint.

## Module layout

`swiyu-issuer/src/api_oidc/`:

- `mod.rs` — `router(state) -> axum::Router`; re-exports.
- `state.rs` — `AppState` (pool, clock, config, signer registry).
- `error.rs` — `OidcError` enum and `IntoResponse` mapping. Error
  bodies follow the OAuth/OID4VCI shape (`{ "error": "...",
  "error_description": "..." }`), not the management API's
  `{ "error", "details" }` shape.
- `metadata.rs` — handlers for the well-known endpoints.
- `credential_offer.rs` — handler for the offer-uri endpoint.
- `token.rs` — handler for the token endpoint.
- `credential.rs` — handler for the credential endpoint.
- `proof.rs` — wallet `proof` parsing and verification (JWT proof
  type only at v0.1.3).
- `nonce.rs` — `c_nonce` issuance and lookup.
- `signer.rs` — issuer-side credential signing: maps an `IssuerId`
  to its DID and `KeyStore` handle, signs an SD-JWT VC, embeds
  `cnf` from the wallet proof.

`swiyu-issuer/src/persistence/oidc/` (new namespace):

- `mod.rs` — module declarations and re-exports.
- `credential_offers.rs` — `find_by_pre_auth_code_hash` and
  `mark_issued`. Kept separate from
  `persistence::credential_offers` so the management binary
  cannot accidentally call `mark_issued` (resolves the open
  question recorded in
  [`impl_api_management.md`](impl_api_management.md)).
- `access_tokens.rs` — insert, find-by-hash, delete-expired.
- `nonces.rs` — insert, consume-by-hash, delete-expired.

The bare OID4VCI pre-auth code lives in a nullable `pre_auth_code`
column on `credential_offers` directly — see *GET
/credential-offer/{offer_id}* and `aspect-persistence.md` for the
"pending-window plaintext" rationale. An earlier design used a
separate `oidc_offer_bridge` table; that table added complexity
without isolating a leak surface from its parent row, and the column
on `credential_offers` is the simpler design that covers the same
durability and lifecycle requirements.

`swiyu-issuer/src/bin/issuer-oidc.rs` stays thin: load config →
connect pool → run migrations → load issuer signing keys →
build `Router` → bind and serve with graceful shutdown.

## Public surface

- `api_oidc::router(state)` — single entry point; the binary and
  integration tests share the same router.
- `api_oidc::AppState` — handle to pool, clock, config, signer
  registry.
- `persistence::oidc` — namespaced; submodules accessed as
  `persistence::oidc::credential_offers::mark_issued`, etc.
- Everything else internal.

## URL and routing model

Wallet-facing OIDC is **issuer-scoped** per
[`aspect-multi-tenancy.md`](aspect-multi-tenancy.md). The
`issuer-oidc` binary mounts every wallet route under
`/i/{issuer_id}/…`. The `{issuer_id}` segment is the **bare**
base58 form (no `issuer_` prefix) — same convention the
management API uses for path segments, kept here so QR-encoded
URLs stay short.

The management API's `offer_deeplink` is built as

```
openid-credential-offer://?credential_offer_uri=
  {issuer_base_url}/i/{issuer_id}/credential-offer/{offer_id}
```

so the OIDC binary owns the `{issuer_id}/credential-offer/{offer_id}`
path. The tenant is **not** in the URL: the wallet has no notion of
a tenant, and the issuer-to-tenant resolution happens server-side
when the request lands.

## Endpoints

All under `/i/{issuer_id}` unless noted. JSON shapes follow the
OID4VCI draft we target (see *Open*); the snippets below are
illustrative, not normative.

### GET /.well-known/openid-credential-issuer

Issuer metadata. Returns the static-plus-config document the
wallet uses to discover the credential endpoint, supported
credential configurations, signing algorithms, and display
metadata.

`credential_configurations_supported` carries one entry at v0.1.3,
keyed by `urn:communal:local-residence-id`, with format
`vc+sd-jwt`, `cryptographic_binding_methods_supported = ["jwk"]`,
and the issuer's supported signing algorithms (single algorithm
per issuer at v0.1.3, derived from the loaded key).

Display metadata (name, logo, locale) comes from the `issuers`
row — the schema column for it lands with this slice (see
*Schema additions*).

### GET /.well-known/oauth-authorization-server

OAuth authorization server metadata. Required by the OID4VCI
draft when the issuer is also the authorization server, which is
the only mode v0.1.3 supports.

Advertises:

- `token_endpoint`
- `grant_types_supported = ["urn:ietf:params:oauth:grant-type:pre-authorized_code"]`
- `pre-authorized_grant_anonymous_access_supported = true`

### GET /credential-offer/{offer_id}

Returns the OID4VCI `CredentialOffer` body the wallet expects
behind the `credential_offer_uri` from the deeplink:

```json
{
  "credential_issuer": "{issuer_base_url}/i/{issuer_id}",
  "credential_configuration_ids": ["urn:communal:local-residence-id"],
  "grants": {
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "pre-authorized_code": "..."
    }
  }
}
```

The pre-auth code in this body is **the bare secret** the
management API minted at offer creation. The bare value lives on
the `credential_offers` row in a nullable `pre_auth_code` column
during the offer's pending window — the by-reference flow forces
this exception to the otherwise-strict "store secrets hashed" rule
(see [`aspect-persistence.md`](aspect-persistence.md)). The OIDC
binary reads the column directly here; this endpoint is the only
path on which the bare code ever leaves the server.

The column is set to `NULL` at the first terminal-state transition:
the management binary clears it on cancellation (in the same
UPDATE that flips `state` to `cancelled`), and the OIDC binary
clears it on issuance (in the same UPDATE that flips `state` to
`issued`). The exposure window is bounded by `expires_at` (≤ 1h
per offer config); a periodic cleanup sweep that NULLs expired
rows lands with the wider OIDC sweeper slice.

The offer body is sensitive in transit: it carries a single-use
bearer secret. Two consequences:

- The endpoint is HTTPS-only in any non-development deployment.
- The endpoint is rate-limited per `offer_id` (deferred — see
  *Open*) and 404s after the first successful fetch (also
  deferred — see *Open*).

The minimum behaviour at v0.1.3:

- 200 with the body above for a `pending`, unexpired offer.
- 404 if the offer is unknown, cancelled, or issued.
- 410 if the stored state is `pending` but `expires_at` has
  passed (observed-state rule).

### POST /token

Exchanges a pre-auth code for an access token plus a `c_nonce`.

Request: `application/x-www-form-urlencoded`, fields
`grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code`
and `pre-authorized_code=…`.

Behaviour:

1. Hash the presented `pre-authorized_code` (SHA-256, base58) via
   `domain::pre_auth_code::PreAuthCode::hash`.
2. `persistence::oidc::credential_offers::find_by_pre_auth_code_hash`
   under the path's `issuer_id`. 404-equivalent maps to OAuth
   `invalid_grant`.
3. Reject if the offer is not `pending` or its `expires_at` has
   passed (`invalid_grant`).
4. Mint an access token (opaque, 16 random bytes, base58) bound
   to the `offer_id` and an expiry of `now + access_token_ttl`
   (default 5 min). Persist its **hash** in `oidc_access_tokens`,
   never the bare value.
5. Mint a `c_nonce` (opaque, 16 random bytes, base58) with the
   same TTL. Persist its **hash** in `oidc_nonces`, scoped to the
   `offer_id`.
6. Return:
   ```json
   {
     "access_token": "...",
     "token_type": "Bearer",
     "expires_in": 300,
     "c_nonce": "...",
     "c_nonce_expires_in": 300
   }
   ```

Notes:

- The token endpoint does **not** transition the offer to
  `issued`. Until the credential endpoint succeeds the offer
  remains `pending`. A wallet that drops out after the token
  endpoint leaves the offer pending until expiry.
- A second token request for the same offer is rejected
  (`invalid_grant`) because the pre-auth code is consumed once
  on first use. (Implementation: the access-token row carries
  the offer id with a unique constraint so a second insert
  fails — see *Schema additions*.)

### POST /credential

Exchanges an access token plus a wallet `proof` for a signed
SD-JWT VC.

Request body (JSON):

```json
{
  "format": "vc+sd-jwt",
  "vct": "urn:communal:local-residence-id",
  "proof": {
    "proof_type": "jwt",
    "jwt": "eyJ..."
  }
}
```

Behaviour:

1. Extract the bearer token from `Authorization: Bearer …`.
   Hash and look up; reject if missing or expired
   (`invalid_token`).
2. Resolve the offer the access token was minted for. Reject if
   not `pending` or expired (`invalid_token`).
3. Reject if the request `vct` does not match the offer `vct`
   (`unsupported_credential_format` if format mismatch,
   `invalid_credential_request` if `vct` mismatch).
4. Verify the wallet proof:
   - `proof_type = "jwt"`. The JWT carries the wallet public
     key in its header (`jwk`), `iss` claim absent, `aud` =
     issuer URL, `iat` recent, `nonce` = a `c_nonce` previously
     issued for this offer.
   - Consume the `c_nonce` (delete the row, atomic).
5. Build the SD-JWT VC: claims from the offer row, `iss` = the
   issuer DID, `cnf` = the wallet `jwk` from the proof. Sign
   with the issuer's signing key from `swiyu-didtool`'s key
   store.
6. Transition the offer: `mark_issued(conn, tenant, issuer,
   offer_id, now)` in the same transaction that deletes the
   access token. The unique constraint on
   `oidc_access_tokens.offer_id` prevents a second redemption
   from racing through.
7. Issue a fresh `c_nonce` for any subsequent batch request
   (deferred for now: respond with the issued credential and
   stop).

Response:

```json
{
  "credential": "eyJ..."
}
```

Errors follow the OID4VCI/OAuth shape:
`{ "error": "invalid_token" | "invalid_credential_request" |
"unsupported_credential_format" | "invalid_proof", "error_description": "..." }`.

## OID4VCI draft version

Pin one specific OID4VCI draft and reference it in this section
once confirmed against the SWIYU integration registry. The wire
shapes above match the draft 13 shape closely enough to be a
defensible starting point; the SWIYU registry's actual choice
governs (see *Open*).

## Schema additions for v0.1.3

`migrations/202605…_oidc_state.sql`:

- `oidc_access_tokens(token_hash text primary key, tenant_id
  text not null, issuer_id text not null, offer_id text not
  null unique, expires_at timestamptz not null, created_at
  timestamptz not null default now())`. The unique constraint
  on `offer_id` is the row-level guard against double redemption.
  `(tenant_id, issuer_id)` denormalised for the same reasons
  given on `credential_offers`.
- `oidc_nonces(nonce_hash text primary key, tenant_id text not
  null, issuer_id text not null, offer_id text not null,
  expires_at timestamptz not null, created_at timestamptz not
  null default now())`. No unique constraint on `offer_id`:
  multiple nonces may be live for one offer (current spec uses
  one, future batch credential issuance uses several).
- `credential_offers.pre_auth_code text` (nullable) — replaces the
  earlier `pre_auth_code_hash` column outright. Carries the **bare**
  pre-auth code for the by-reference offer fetch (see *GET
  /credential-offer/{offer_id}*). Written at offer creation by the
  management binary, NULLed in the same UPDATE as the state
  transition by both the cancel and issue paths. An earlier design
  used a separate `oidc_offer_bridge` table; that added complexity
  without isolating a leak surface from the parent row, so the
  column-on-credential_offers form is what we use.
- Indexes: `oidc_access_tokens(expires_at)` and
  `oidc_nonces(expires_at)` for the periodic cleanup sweep.

The `issuers` row gains the columns the issuer metadata endpoint
needs to render display metadata and locate the signing key:

- `did text not null` — issuer DID (`did:tdw` or `did:webvh`).
- `signing_key_id text not null` — handle into the `swiyu-didtool`
  key store. Format is the keystore's own — opaque to the issuer
  binary.
- `display_name text`, `logo_uri text`, `locale text` — display
  metadata, all nullable; the metadata handler omits absent
  fields. Real branding is wired in by a later admin slice.

These columns ship as a single migration. Existing seed rows are
backfilled with the dev DID and key-id used in the developer
fixture (see [`swiyu-didtool/specs/key-store.md`](
../../swiyu-didtool/specs/key-store.md)).

## Configuration

Environment variables consumed by `issuer-oidc`:

- `DATABASE_URL` — Postgres connection string.
- `BIND_ADDR` — listen address, e.g. `0.0.0.0:8081`.
- `ISSUER_BASE_URL` — public base URL embedded into issuer
  metadata (`credential_issuer`, `token_endpoint`, …). The
  management binary already publishes a deeplink against the
  same value, so the two binaries must agree on it; deployments
  serve the `/i/…` paths under that base URL via reverse proxy.
- `KEY_STORE_PATH` — root of the `swiyu-didtool` filesystem
  keystore.
- `ACCESS_TOKEN_TTL_SECONDS` — default 300.
- `C_NONCE_TTL_SECONDS` — default 300.

No config file at v0.1.3.

## Deployment topology

`issuer-mgmt` and `issuer-oidc` are separate binaries, but they
must be reachable to external clients at the same external base
URL — `ISSUER_BASE_URL`. The management binary publishes deeplinks
that resolve into the OIDC binary's `/i/{issuer_id}/credential-
offer/{offer_id}` path; if the two binaries answered on different
hosts the wallet would chase a URL that does not exist on the
issuer it was directed to.

A reverse proxy in front of both binaries is the canonical layout:

```
                    ┌────────────────────────────┐
client / wallet ──▶ │  reverse proxy (nginx,    │
                    │  Caddy, k8s ingress, …)   │
                    └────────────────────────────┘
                          │           │
                          │           │
   /api/v1/…              │           │   /i/…
   /healthz              ▼           ▼   /.well-known/…
              ┌────────────┐   ┌────────────┐
              │ issuer-mgmt│   │ issuer-oidc│
              └────────────┘   └────────────┘
```

Routing rules:

- `/api/v1/…` and `/healthz`, `/readyz` → `issuer-mgmt`.
- `/i/…` and `/.well-known/…` → `issuer-oidc`.
- Both binaries set `ISSUER_BASE_URL` to the **external** base
  URL (the proxy's host), not their own listen address. The
  deeplink the management binary emits and the issuer metadata
  the OIDC binary advertises must agree on this value.

Single-host development is fine without a proxy: run the two
binaries on different ports and point business-app smoke tests
at each port directly. Wallet flows still need a reachable URL
that resolves both path prefixes, so a local proxy (or
`ISSUER_BASE_URL` pointing at the OIDC binary alone, with
`/api/v1/…` traffic going elsewhere) is needed for end-to-end
wallet testing.

## Error mapping

`OidcError` implements `IntoResponse` and maps onto the OAuth /
OID4VCI fixed status-code table:

| Error variant                            | HTTP | `error`                          |
|------------------------------------------|------|----------------------------------|
| `OidcError::InvalidGrant`                | 400  | `invalid_grant`                  |
| `OidcError::InvalidToken`                | 401  | `invalid_token`                  |
| `OidcError::InvalidProof`                | 400  | `invalid_proof`                  |
| `OidcError::InvalidRequest`              | 400  | `invalid_request`                |
| `OidcError::InvalidCredentialRequest`    | 400  | `invalid_credential_request`     |
| `OidcError::UnsupportedCredentialFormat` | 400  | `unsupported_credential_format`  |
| `OidcError::OfferNotFound`               | 404  | (plain JSON `error: not_found`)  |
| `OidcError::OfferExpired`                | 410  | (plain JSON `error: expired`)    |
| `PersistenceError::Db`                   | 500  | logged, body `error: server_error` |

Bodies use the OAuth shape `{ "error": "...", "error_description": "..." }`
**only on the token and credential endpoints**. The metadata and
offer-uri endpoints use the management API's
`{ "error", "details" }` shape — they are not OAuth surfaces.

## Tenant resolution

Although wallet routes don't carry a tenant, every persistence
function still requires a `TenantId` (defense in depth from
[`impl_persistence.md`](impl_persistence.md)). The handler
resolves `tenant_id` from `issuer_id` once at the request
boundary via a small helper
`resolve_tenant_for_issuer(&mut conn, &issuer_id) ->
Result<TenantId, OidcError>`, then threads the resolved tenant
into every persistence call within the handler. A miss returns
404 — the wallet must not learn whether an issuer id exists in
another tenant's namespace.

## Tests

- Unit tests inside the handler modules exercising request /
  response shapes against an in-process router with a real
  Postgres pool and a real signing key (the dev key from the
  fixture keystore).
- Integration tests under `swiyu-issuer/tests/` cover the full
  redemption flow:
  - **Happy path**: management API creates an offer; the OIDC
    binary fetches the offer body, exchanges the pre-auth code
    for a token + nonce, presents a wallet proof, receives a
    valid SD-JWT VC. The offer row is `issued` with `issued_at`
    set.
  - **Expired offer**: token endpoint returns `invalid_grant`.
  - **Replayed pre-auth code**: second token request returns
    `invalid_grant` (unique constraint on access-token offer_id).
  - **Wrong nonce**: credential endpoint returns `invalid_proof`.
  - **Wrong vct**: credential endpoint returns
    `invalid_credential_request`.
  - **Cross-issuer access**: a token minted for issuer A is
    rejected at issuer B's credential endpoint
    (`invalid_token`).
- Every multi-tenant test seeds a second tenant + issuer and
  asserts cross-tenant access returns the expected error.
- Signature of the issued SD-JWT VC is verified against the
  issuer's DID document fetched from the same registry the
  rest of the codebase uses.

## Suggested slice ordering (v0.1.3)

1. Migration: `oidc_access_tokens`, `oidc_nonces`, and the new
   columns on `issuers`. Backfill the dev seed.
2. Domain: lift the `try_issue` transition that already exists on
   `CredentialOffer`; add `AccessToken` and `Nonce` newtypes with
   the same hash-on-creation pattern as `PreAuthCode`.
3. Persistence: `persistence::oidc::credential_offers`,
   `persistence::oidc::access_tokens`,
   `persistence::oidc::nonces`. Free functions, `&mut PgConnection`,
   tenant + issuer in every signature.
4. Signer: load issuer DIDs and key-store handles at startup,
   keyed by `IssuerId`. Sign SD-JWT VCs.
5. Handlers and DTOs for the five endpoints, wired into a single
   `api_oidc::router(state)`.
6. Integration tests per the Tests section.

Steps 1–4 may land together or in separate commits. Step 5 must
come last.

## What is deliberately not in v0.1.3

- **Authorisation code grant.** Pre-auth grant only.
- **Transaction codes.** No second factor on the pre-auth grant.
  Adding it later is a `tx_code` field on `oidc_access_tokens`
  plus a `transaction_code` column on `credential_offers`.
- **DPoP, PAR, mTLS, `client_id` registration.** Not required by
  the SWIYU pre-auth flow.
- **Batch credential endpoint.** Single credential per token.
- **Notification endpoint.** No `notification_id` minted; no
  POST `/notification` handler.
- **Credential response encryption.**
  `credential_response_encryption` advertised as `false`.
- **Rate limiting on the offer-uri endpoint, single-fetch
  semantics.** A wallet that loses the body can refetch it.
  Tighten this once a real rate-limiting layer lands.
- **Status-list integration.** Issued credentials carry no
  `status` claim. The status-list slice adds it.
- **`did:webvh` end-to-end coverage.** Per `CLAUDE.md`, only
  `did:tdw` 0.3 is testable end-to-end against the SWIYU
  integration registry. `did:webvh` paths exist but are not
  validated against any registry in this slice.
- **OpenAPI generation.** `swiyu-issuer/openapi.yml` is
  hand-written; the OIDC routes are added there manually.
- **`application/problem+json` error bodies.** Not introduced
  here either.

## Open

- **OID4VCI draft version.** Confirm against the SWIYU
  integration registry which exact draft (12 vs. 13 vs. 14)
  governs wire shapes — affects the issuer metadata structure,
  proof JWT claim names, and the credential-endpoint request
  body. Pin before any wire-format change is hard to roll back.
- **`c_nonce` lifetime.** Per-token (current lean: tied to
  access-token TTL) vs. independent (rotated on every credential
  request). Per-token is simpler; rotation is the OAuth-canonical
  pattern. Revisit when batch issuance is on the roadmap.
- **Offer-uri single-fetch.** Should fetching the offer body via
  `GET /credential-offer/{offer_id}` mark the offer such that a
  second fetch returns 404, or remain idempotent until the token
  endpoint consumes the pre-auth code? Idempotent is friendlier
  to flaky wallets; single-fetch closes a wider exposure window
  on the bearer secret. Lean: idempotent, paired with
  rate-limiting once a rate-limit layer lands.
- **Per-issuer signing-algorithm advertising.** v0.1.3 advertises
  exactly the algorithm the issuer's loaded key supports. A
  future multi-key issuer (key rotation, dual-algorithm during
  migration) needs `credential_configurations_supported` to
  enumerate all available algorithms and the credential endpoint
  to choose one based on the wallet's request — design when the
  second algorithm appears.
- **Display metadata source of truth.** The `issuers` row carries
  display metadata (`display_name`, `logo_uri`, `locale`). Real
  branding flows are an admin-UI concern; whether the OIDC
  binary reads display metadata directly from `issuers` or via
  a future cached metadata projection is open. v0.1.3 reads from
  `issuers` directly.
