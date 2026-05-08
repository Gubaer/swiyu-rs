# Aspect: OAuth2 access to SWIYU registries

This document describes the OAuth2-protected protocol that the SWIYU registries expose, what credentials a partner receives from SWIYU, and how the registry clients in this crate expect bearer tokens to be supplied. It is conceptual: it captures the wire-level reality of talking to SWIYU's OAuth2-protected APIs.

The runtime mechanics of acquiring and refreshing tokens — the OAuth2 client itself, the multi-tenant `TokenProvider` abstraction, refresh-token rotation handling, the seven-day cliff, persistence questions — live one layer up in [`swiyu-issuer/specs/aspect-oauth2.md`](../../swiyu-issuer/specs/aspect-oauth2.md). This crate stays a thin HTTP wrapper: it exposes registry clients that accept a bearer token per call.

## The two registries we talk to

`swiyu-registries` calls into two HTTP services operated by the Swiss federal SWIYU infrastructure:

- **Identifier Registry.** Allocates DIDs to onboarded partners and serves their DIDLogs.
- **Status Registry.** Hosts signed status-list documents that verifiers dereference to check whether a credential has been suspended or revoked.

Both registries are reached via separate hostnames (e.g. `identifier-reg-api.trust-infra.swiyu-int.admin.ch` and `status-reg-api.trust-infra.swiyu-int.admin.ch` for the integration environment) but are fronted by the same OAuth2 authorization server — a Keycloak realm operated by the federal API gateway team, sitting behind a WSO2 API Manager gateway. One partner identity therefore yields one access token that works against both. (Empirically confirmed: the access token's `subscribedAPIs` claim from the production realm covers all three SWIYU registries — identifier, status, and trust — with a single credential set.)

## What is protected and what is public

The endpoints split cleanly into two categories.

**Public, unauthenticated:**

- DIDLog read (`GET …/api/v1/did/{uuid}/did.jsonl`) on the Identifier Registry. Any verifier in the wild reads this; the URL is encoded inside the DID itself. This client's `fetch_log` operation deliberately does *not* send an `Authorization` header against this path.
- Status-list document read on the Status Registry. Same reasoning: a verifier on the open internet must be able to dereference the URL embedded in the credential's `status.status_list.uri` claim. This client does not perform that read; it is the verifier's concern.

**Partner-write, OAuth2-protected (Bearer):**

- Identifier Registry: DID allocation (`POST`), DIDLog publication (`PUT`), DIDLog deactivation (`PUT`).
- Status Registry: status-list create, update, list operations.

Every protected request carries `Authorization: Bearer <access_token>`. Nothing else (no mTLS, no signed request envelopes, no IP allow-listing at the application layer).

## What the partner receives from SWIYU

A SWIYU integration partner is provisioned through the Swiss ePortal. After completing the onboarding click-path under the partner's business profile, the portal exposes four credential values:

1. **`client_id`** — long-lived, identifies the partner's OAuth2 client.
2. **`client_secret`** — long-lived, authenticates the partner's OAuth2 client.
3. **`access_token`** — short-lived bearer token (hours).
4. **`refresh_token`** ("renewal token") — medium-lived, used to mint new access tokens without re-presenting the client secret.

Three of these four are durable per-tenant state: `client_id`, `client_secret`, and the **`refresh_token`** (which the ePortal labels "renewal token"). The pre-issued `access_token` is a session artefact — useful for one-off probes but not stored. The `refresh_token` must be seeded from the ePortal before the runtime can mint its first access token: the SWIYU API gateway forbids the `client_credentials` grant for partner Anwendungen (it returns `403` with WSO2 error code `900908` before reaching the realm), so a `refresh_token` is the only way in. Once seeded, the runtime keeps the value current automatically — every successful grant returns a new refresh token, which replaces the previous value.

## Token endpoint

A single OAuth2 token endpoint mints access tokens that authenticate against every protected SWIYU registry. Its URL is supplied via configuration — never hardcoded, never discovered. The production endpoint is `https://keymanager-prd.api.admin.ch/keycloak/realms/APIGW/protocol/openid-connect/token` (a Keycloak realm fronted by WSO2 API Manager); non-production URLs follow the same shape with different hostnames and are provisioned to the partner alongside the credentials. The endpoint is a standard OAuth2 token endpoint (RFC 6749 §3.2): `POST` with an `application/x-www-form-urlencoded` body and a JSON response.

### Grant type: `refresh_token`

The runtime uses exactly one grant type to obtain access tokens.

```
POST /protocol/openid-connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&client_id=<client_id>
&client_secret=<client_secret>
&refresh_token=<refresh_token>
```

The response carries a fresh `access_token`, a fresh `refresh_token`, and the usual `expires_in` / `refresh_expires_in` / `token_type` / `scope` fields. Both tokens supersede their predecessors; the SWIYU Keycloak realm rotates refresh tokens on every grant (with a short grace window during which the previous refresh token also still works — see *Empirically confirmed* below).

The runtime keeps a refresh token per partner (initially seeded by an operator from the ePortal, then rotated by every grant). Each grant uses the current value and replaces it with whatever the realm returned. After a process restart the runtime re-reads the same value from durable storage and continues from there.

### Why not `client_credentials`?

In standard OAuth2 machine-to-machine setups, `client_credentials` is the natural cold-start path: a confidential client presents its credentials and receives an access token, no refresh token needed. The SWIYU API gateway does not allow this grant for partner Anwendungen. A `client_credentials` request to the production realm returns `403 Forbidden` with WSO2 error code `900908` — the gateway rejects the request before it even reaches the realm. Partners are expected to seed a refresh token from the ePortal instead, which is why the refresh token is mandatory per-tenant state and there is no fallback path for a runtime whose refresh token expires or is revoked.

### No other grants

`password`, `authorization_code`, and `device_code` grants are not used and are not part of the partner OAuth2 surface. The partner deployment is a confidential machine-to-machine client; there is no end user in the loop.

## How tokens flow through this crate

The registry clients in this crate (`IdentifierRegistryClient`, `StatusRegistryClient`) take an `&AccessToken` as a per-call argument — the same shape as `partner_id`. They do not acquire tokens, do not cache them, do not refresh them, and do not maintain any OAuth2 state. The token is constructed by the caller and supplied per registry operation.

A `401` response from a protected endpoint is surfaced to the caller as `RegistryError::HttpStatus { status: 401, .. }`. The decision to refresh and retry is the caller's; in `swiyu-issuer` this is handled around a `TokenProvider` (see [`swiyu-issuer/specs/aspect-oauth2.md`](../../swiyu-issuer/specs/aspect-oauth2.md)). `fetch_log` is the one exception: it hits the unauthenticated public DID-resolver path and takes no token argument.

The crate exposes no `TokenProvider` trait and holds no OAuth2 state. The `AccessToken` newtype it owns ([`swiyu-registries/src/common/auth.rs`](../src/common/auth.rs)) is the only token-related type; it ensures the value is masked in `Debug` output and zeroized on drop. Refresh tokens never appear in this crate at all — they are an implementation detail of the OAuth2 client in `swiyu-issuer`.

## Empirically confirmed against the SWIYU production realm

The following facts were validated by probing the production realm with a real partner Anwendung's credentials. They are committed details of the SWIYU integration environment, not assumptions.

- **Token endpoint:** `https://keymanager-prd.api.admin.ch/keycloak/realms/APIGW/protocol/openid-connect/token`. Same realm fronts every protected SWIYU API.
- **Single credential set covers all SWIYU APIs.** A token minted from one Anwendung's credential set carries a `subscribedAPIs` claim listing all three SWIYU registries (`swiyucorebusiness_identifier`, `swiyucorebusiness_status`, `swiyucorebusiness_trust`). One credential set per tenant suffices for every registry the tenant talks to, including the trust registry that this crate does not yet front.
- **Access-token TTL:** 25 hours (`expires_in` = 90 000 s).
- **Refresh-token TTL:** 7 days (`refresh_expires_in` = 604 800 s).
- **Refresh-token rotation:** ON, with a short **grace window** — a `refresh_token` grant returns a new refresh token, but the old one continues to work briefly thereafter. This means a missed scheduler tick or a brief race between two replicas does not strand the deployment; both branches converge.
- **Scope:** `offline_access` (OIDC standard).
- **`environment` claim:** `prod` (custom claim injected by WSO2; useful for sanity-checking which realm a token was minted by).
- **`client_credentials` is not available** for partner Anwendungen: the gateway responds with `403 Forbidden` and WSO2 error `900908` before reaching the realm. A refresh token seeded from the ePortal is therefore mandatory, not an optimisation.
- **Custom `bproles` claim** maps the Anwendung UUID to a list of fine-grained role identifiers (e.g. `ti_@identifier_#read`, `ti_@status_#write`). Not consumed by this crate today; useful context if the gateway ever exposes role-restricted endpoints we need to discriminate.
