# Technology choices

This document records the technology and product choices that `swiyu-issuer` makes — both committed decisions and recommendations that have been discussed but not yet committed.

Status: preliminary; living document.

Each entry below carries a status:

- **Decided** — committed; only revisited on a clear new need.
- **Recommended** — leaning, with reasoning recorded; awaiting formal commitment.
- **Deferred** — explicitly set aside until later, with a priority.

## Relational DBMS

**Decided: PostgreSQL.** From the initial release through production. Other engines are evaluated and supported only on a clear production-driven need in a specific deployment.

Implications:

- Postgres-specific features are used directly, without an abstraction layer: row-level security, `JSONB`, `bytea`, partitioning, `pg_cron`, `LISTEN`/`NOTIFY`. The persistence spec already counts on several of these.
- The database access crate is configured Postgres-only.
- Schema and migrations use Postgres types (`uuid`, `timestamptz`, …) directly.

## Database access

**Decided: `sqlx`.**

Reasoning:

- Explicit SQL is auditable for tenant scoping — a requirement from the multi-tenancy spec.
- Compile-time-checked queries via `sqlx::query!` catch column and type mismatches before runtime.
- No abstraction layer hiding what hits the DB.

ORM alternatives considered (`sea-orm`, `diesel`) and rejected: they add abstraction cost for a domain that fits relational mapping cleanly, and obscure the SQL surface that needs to be auditable for multi-tenant scoping.

## Schema migrations

**Decided: `sqlx migrate`.** Built into `sqlx` and sufficient for our needs. Alternatives (`refinery`, `sqitch`) considered and rejected as unnecessary additions.

## Key material storage

**Pre-production and intermediate maturity: DBMS-backed keystore.** Decided. Private keys live AEAD-encrypted in a dedicated `swiyu_issuer_keystore` schema, with a per-tenant KEK held by the deployment's orchestrator secret store. The filesystem-based keystore from `swiyu-didtool` is not reused at runtime.

**Production maturity: HSM (or HSM-backed KMS).** Provider choice **deferred**.

See [`aspect-key-management.md`](aspect-key-management.md) for the full model and [`aspect-persistence.md`](aspect-persistence.md) for the persistence-layer view.

## HTTP framework

**Recommended: `axum`.** Decision **deferred**.

Reasoning for the lean:

- Boring choice; built on hyper + tower by the tokio team.
- Tower middleware (auth, tracing, request id, rate limiting) reuses cleanly across both binary services.
- Type-safe extractors fit the multi-tenancy spec: `TenantContext` and the `(tenant_id, issuer_id)` ownership check land naturally as axum extractors at the request boundary.
- Active maintenance, large user base, good Swiss/EU presence.
- OpenAPI available via `utoipa` (not as native as `poem`, but sufficient for the management API).

Alternatives considered:

- **`poem`** — better built-in OpenAPI; smaller ecosystem; no tower middleware. The tradeoff is worth revisiting if OpenAPI generation becomes a primary concern of the management API.
- **`actix-web`** — fast in micro-benchmarks (irrelevant at our volumes); divergent runtime model; not recommended.

## Admin web UI

**Decision deferred — priority 2.** Lean: SPA.

Options on the table:

- **SPA** (React, Vue, or Svelte). The admin UI consumes the same JSON API a power user could call directly. Modern interactive UX. Cost: two toolchains (Rust + Node), two build pipelines, larger attack surface.
- **Server-rendered HTML** (`askama`, `maud`, or `minijinja`). Single toolchain, single binary, simpler auth (server-set HttpOnly cookies, no token juggling). Cost: clunkier interactive forms; admin UI logic and the management API risk being implemented twice unless carefully shared.
- **HTMX middle path** — server-rendered HTML with attribute-driven AJAX swaps. Keeps the single-toolchain simplicity of server rendering, recovers most interactive UX without a JS framework. A common choice for internal admin UIs of this size.

If SPA is picked, three sub-choices follow:

- **Framework**: React (largest ecosystem), Vue (opinionated and simpler), or Svelte (smallest bundle, simpler mental model).
- **Location**: same Cargo workspace under e.g. `swiyu-issuer-admin-ui/`, or a separate repository. Same workspace keeps versions in lockstep with the backend; separate repo lets the frontend evolve independently.
- **Serving**: bundled into the `issuer-mgmt` binary via `rust-embed` (single-binary deployment), or served by a separate web server / CDN.

## Open

- HTTP framework: formally commit to `axum`, or revisit `poem` if OpenAPI generation becomes a primary requirement of the management API?
- Admin UI: HTMX middle path vs. SPA — when to make the decision.
- HSM provider on the canton side (see persistence spec).
