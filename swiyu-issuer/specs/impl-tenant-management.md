# Implementation: Tenant management

This document describes how operators manage tenant rows in `swiyu-issuer` — creation, metadata updates, and the CLI surface that exposes those operations. For the multi-tenancy concepts the tenant row implements, see [`aspect-multi-tenancy.md`](aspect-multi-tenancy.md). For the underlying schema, see [`impl_persistence.md`](impl_persistence.md). For OAuth2-credential subcommands (`tenant set-oauth-credentials`, `tenant import-oauth-refresh-token`), see [`impl-oauth2.md`](impl-oauth2.md). For API-token subcommands (`tenant api-token mint`), see [`impl_auth.md`](impl_auth.md).

Status: preliminary; living document.

## CLI binary

Operator commands live in the `swiyu-issuer-cli` binary, separate from the long-running `swiyu-issuer-mgmtapi` daemon. Tenant is the primary resource; everything operators do is either a verb on a tenant or on a sub-resource owned by a tenant. The CLI mirrors that hierarchy:

```
swiyu-issuer-cli tenant <verb-or-subresource> [args]
```

All tenant-scoped commands the binary currently ships, grouped by which spec slice introduced them:

```
# Tenant lifecycle (this document)
swiyu-issuer-cli tenant create                      --partner-id <uuid> [--display-name <name>] [--description <text>]
swiyu-issuer-cli tenant update                      --tenant <bare-tenant-id> [--partner-id <uuid>] [--display-name <name>] [--description <text>]

# OAuth2 credentials (impl-oauth2.md)
swiyu-issuer-cli tenant set-oauth-credentials       --tenant <bare-tenant-id> --client-id <id> --client-secret-stdin
swiyu-issuer-cli tenant import-oauth-refresh-token  --tenant <bare-tenant-id> --token <refresh-token>

# API tokens (impl_auth.md)
swiyu-issuer-cli tenant api-token mint              --tenant <bare-tenant-id> --name <label> [--expires-in 30d]
```

The nested subcommand structure lets future verbs (`tenant list`, `tenant deactivate`, `tenant api-token list`, `tenant api-token revoke`, …) land without restructuring.

## `tenant create`

Mints a fresh `TenantId` server-side (the bare base58 id is printed once on stdout — the operator captures it for subsequent commands and audit) and inserts the row with the operator-supplied `partner_id` and the optional `display_name` / `description`. Schema columns written: `id`, `partner_id`, `display_name`, `description`; the OAuth2 columns and any API tokens are left at their defaults (NULL) and land via the dedicated subcommands.

SWIYU Business Partner registration is a precondition (see [`aspect-multi-tenancy.md`](aspect-multi-tenancy.md) Lifecycle); `--partner-id` is required and validated as a UUID at parse time. `--display-name` and `--description` are optional — both columns are nullable, and the UI layer derives a fallback display name from the bare id when `display_name` is NULL.

There is intentionally no `--id` / `--tenant` flag on `tenant create`: id generation is always server-side so operators cannot collide with existing rows or push tenant ids through shell history.

## `tenant update`

Writes any subset of `partner_id`, `display_name`, `description` for the named tenant. Omitted flags leave the column untouched; partial updates are supported. `--partner-id` is validated as a UUID on the rare typo-correction path — SWIYU Business Partner records are not expected to rotate in normal life, so the typical operator never touches this flag.

There are no `--clear-*` flags in v1. Operators that need to NULL a `display_name` or `description` do so with a direct `UPDATE` until a real use case appears.

`tenant update` rejects an unknown bare tenant id with a non-zero exit and a message naming the missing tenant; this matches the behaviour of `tenant set-oauth-credentials` and `tenant import-oauth-refresh-token`.

## Persistence module

```
swiyu-issuer/src/persistence/tenants.rs   — extended with:
    fn insert(...)                                    — INSERT INTO tenants
    fn update_metadata(...)                           — partial UPDATE of partner_id / display_name / description
```

Both take `&mut PgConnection`; transaction boundaries are owned by the calling CLI handler (one transaction per CLI invocation, committed if all writes succeed).

## Out of scope (this implementation)

- `tenant list`, `tenant deactivate`, `tenant delete`, and admin-user management — load-bearing only once the admin web UI / multi-operator workflow lands.
- A management-API counterpart to these CLI verbs. Tenant lifecycle is operator-only today; the BA-facing surface stops at issuers and credential offers.
- Bulk import / export of tenant rows. Not a current need.
- `--clear-display-name` / `--clear-description` flags. Add when an operator actually needs them.
