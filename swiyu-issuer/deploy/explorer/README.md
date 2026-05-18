# swiyu-issuer explorer

Run the SWIYU credential issuer locally without cloning the repo or
installing a Rust toolchain. This directory ships a standalone
`docker-compose.yml` that pulls prebuilt images from GitHub Container
Registry; you only need Docker, an [ePortal](https://eportal.admin.ch/) account, and the two
files in this directory.

For the contributor flow (building from source), see
`swiyu-issuer/.env.example` and `swiyu-issuer/docker-compose.yml` in
the repo instead.

## Not for production use

These images are **not hardened** and the bundled stack is built for
convenience, not security:

- Vault runs in **dev mode** — in-memory storage, single fixed root
  token, no seal/unseal, no real auth. All Vault state, including
  the per-tenant Transit keys that protect your signing keys and
  OAuth2 secrets, is lost on every container restart.
- The stack defaults to the **Vault** signing and secret-encryption
  engines, so private keys and OAuth2 secrets do not sit in
  plaintext in Postgres — but the only thing protecting them is the
  dev-mode Vault above. The `dev` engines remain available as a
  fallback (override `SIGNING_ENGINE` / `SECRET_ENCRYPTION_ENGINE`
  in `.env`); their master key is the publicly known string baked
  into `.env.example`, so anything encrypted with them is, in
  effect, plaintext.
- Postgres uses **well-known default credentials** (`swiyu_issuer` /
  `swiyu_issuer`) and is published on the host loopback.
- No TLS, no reverse proxy, no rate limiting, no audit logging
  beyond `RUST_LOG`.
- OAuth2 refresh tokens for your real ePortal account end up on disk
  via `.env` and inside the Postgres volume — treat the host like
  you'd treat any machine holding production credentials, even
  though everything else around it is dev-grade.

Use this stack to **experiment** with the issuer and the SWIYU
integration registries. Do not point it at production endpoints; do
not expose it on a public network; do not issue credentials anyone
will rely on. A production deployment needs a real sealed Vault (not
the dev container here), a properly secured Postgres, a reverse
proxy terminating TLS, and scoped auth tokens.

## 1. Prerequisites

- **Docker Engine 25+** with **Compose v2**. Verify with
  `docker --version` and `docker compose version`.
- An **[ePortal](https://eportal.admin.ch/) account** with a Business Partner registered (or
  the ability to register one). The bootstrap step seeds your tenant
  from credentials issued there.
- The published images are **`linux/amd64` only**. On Apple Silicon,
  arm64 Linux, or Windows on ARM, Docker will pull and run them under
  Rosetta or QEMU emulation if it's set up for that, but we haven't
  verified the issuer binaries on emulated arm64 hosts — your mileage
  may vary. Native `linux/arm64` images are a planned follow-up.

## 2. Download

Grab the two files into an empty directory:

```sh
curl -O https://raw.githubusercontent.com/Gubaer/swiyu-rs/master/swiyu-issuer/deploy/explorer/docker-compose.yml
curl -O https://raw.githubusercontent.com/Gubaer/swiyu-rs/master/swiyu-issuer/deploy/explorer/.env.example
```

By default the compose file pulls the floating `:swiyu-beta` tag. To
pin to a specific release, set `IMAGE_TAG=<version>-swiyu-beta` in
`.env` (e.g. `IMAGE_TAG=0.1.12-swiyu-beta`). The `-swiyu-beta` suffix
is intentional — it marks both the issuer software and the wider
SWIYU ecosystem as beta.

## 3. Onboard a Business Partner on the ePortal

Sign in to the [ePortal](https://eportal.admin.ch/) and gather four values from your Business
Partner record:

1. **Partner ID** — a UUID identifying your business entity in SWIYU.
   Paste as `DEV_TENANT_PARTNER_ID`.
2. **Customer key** — the OAuth2 client identifier, issued from the
   credentials section of the Partner record. Paste as
   `DEV_TENANT_CLIENT_ID`.
3. **Customer secret** — the OAuth2 client secret paired with the
   customer key. Treat it like a password. Paste as
   `DEV_TENANT_CLIENT_SECRET`.
4. **Renewal token** — a long-lived OAuth2 refresh token, roughly 7
   days lifetime. Paste as `DEV_TENANT_REFRESH_TOKEN`. This one
   expires; you'll rotate it occasionally (see *Troubleshooting*).

If you don't yet have a registered Business Partner, follow section 2
*Register Organization* of the
[SWIYU onboarding guide](https://swiyu-admin-ch.github.io/cookbooks/onboarding-base-and-trust-registry/)
before returning here.

## 4. Fill in `.env`

Copy the template and paste the four ePortal values:

```sh
cp .env.example .env
```

Edit `.env` and set the four `DEV_TENANT_*` variables. Optionally also
set `DEV_TENANT_DISPLAY_NAME` and `DEV_TENANT_DESCRIPTION` — they're
written to the tenant row on first creation and surface in operator
views. Everything else can stay at defaults: the `SWIYU_*` URLs point
at the SWIYU integration (INT) environment, the dev Vault + Postgres
come bundled with the stack, and `IMAGE_TAG=swiyu-beta` pulls the
latest beta.

The `DEV_TENANT_*` prefix is historical — the same seeding code path
provisions your real tenant. The prefix has no audience-specific
meaning.

## 5. Run

Start everything:

```sh
docker compose up -d
```

The first run pulls four images (Postgres, Vault, and the three
`swiyu-issuer` images) and brings them up in dependency order.

When `bootstrap-dev-tenant` finishes, it prints the bare tenant id.
Surface it:

```sh
docker compose logs bootstrap-dev-tenant
```

Look for the line `bootstrap-dev-tenant: dev tenant id = <id>` and
copy that id. Mint a bearer token for the management API:

```sh
docker compose run --rm swiyu-issuer-cli \
    tenant api-token mint --tenant <id> --name explorer
```

The CLI prints a `tok_<base58>` token. Save it and curl the health
endpoints to confirm both binaries are up:

```sh
TOKEN=tok_...

curl -fsS http://localhost:8080/healthz
curl -fsS http://localhost:8081/healthz
curl -fsS -H "Authorization: Bearer $TOKEN" http://localhost:8080/issuers
```

From here you can drive the credential-offer flow against the
management API (port 8080) and verify the OIDC binary (port 8081)
serves the credential offer back to a wallet.

## 6. What gets provisioned

After `docker compose up -d` finishes, the dev tenant database
carries a complete, end-to-end issuable baseline:

- **One tenant** — seeded from `DEV_TENANT_PARTNER_ID` and the rest
  of the `DEV_TENANT_*` env vars by the `bootstrap-dev-tenant`
  sidecar. Every API token you mint is scoped to this tenant.
- **One issuer** owned by that tenant — provisioned by the
  `bootstrap-dev-issuer` sidecar, which enqueues the same
  `CreateIssuer` operation task `POST /api/v1/issuers` would and
  waits for the mgmtapi worker to drive the saga to completion.
  Display name `${DEV_TENANT_DISPLAY_NAME} - dev issuer`; the DID
  is registered against the SWIYU integration registry and resolves
  end-to-end.
- **One dummy credential type** owned by the tenant —
  `vct = urn:dummy:dummy-credential`, with claim schema, display
  metadata, and per-claim labels (en-US + de-CH) bundled into the
  `swiyu-issuer-cli` image. Schema accepts a minimal
  `{ first_name, last_name }` payload.
- **One assignment row** linking the dummy credential type to the
  issuer. Without this row a `POST /credential-offers` would fail
  with `409 Conflict` ("credential type is not assigned to issuer"),
  so the assignment is what makes the type actually issuable through
  the seeded issuer.

The net effect: an end-to-end credential issuance against this stack
needs no further provisioning before you point a wallet at it. The
demo path is exercised by the `credential_lifecycle_smoke` and
`credential_status_lifecycle_smoke` examples in the source repo
(which spin up their *own* additional issuer + assignment per run,
so they do not mutate the baseline above).

The bootstrap is idempotent on subsequent `docker compose up -d`
runs against an existing volume; wipe with `docker compose down -v`
to start fresh (see *Troubleshooting*).

## Troubleshooting

**Refresh token expired (after ~7 days).** Issue a fresh renewal token
on the ePortal, then either wipe state and re-bootstrap from `.env`:

```sh
docker compose down -v
# paste the new renewal token into .env
docker compose up -d
```

…or rotate in place without wiping the database:

```sh
docker compose run --rm swiyu-issuer-cli \
    tenant import-oauth-refresh-token --tenant <id> --token-stdin
```

**Wipe all state.**

```sh
docker compose down -v
```

Removes containers and the Postgres + Vault volumes. Next
`docker compose up -d` starts from a clean slate; `bootstrap-dev-tenant`
re-runs and re-seeds.

**Logs.**

```sh
docker compose logs -f swiyu-issuer-mgmtapi
docker compose logs -f swiyu-issuer-oidcapi
```

`RUST_LOG` in `.env` controls verbosity. The default
(`info,swiyu_issuer=debug`) is reasonable; raise to `debug` for noisier
output or `trace` for everything.
