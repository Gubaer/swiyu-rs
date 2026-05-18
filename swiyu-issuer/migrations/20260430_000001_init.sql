-- Initial schema for swiyu-issuer.
--
-- This file is the consolidation of pre-production migrations into a
-- single baseline. The originals covered 0001 through 0015 (status-
-- list, issued-credentials, registry-coordinate additions), the
-- OAuth2 credential columns on tenants (originally a separate
-- `tenants_oauth` migration), the re-type of those secret columns
-- from TEXT to BYTEA for encryption-at-rest (originally
-- `tenants_oauth_encrypted`), the tenant-metadata slice that
-- tightened `partner_id` to `UUID NOT NULL` and added `display_name`
-- / `description`, the follow-up that pinned `partner_id` UNIQUE,
-- and the credential-type slice (originally three migrations adding
-- `credential_types`, `issuer_credential_types`, and the
-- `credential_offers.credential_type_id` column). The project is
-- still pre-production; collapsing was cheaper than carrying the
-- expand/contract history. Subsequent schema changes go in their own
-- numbered migration on top of this one.
--
-- See specs/impl_persistence.md and
-- specs/impl-credential-management.md for design rationale.

-- ============================================================================
-- Tenants
-- ============================================================================
--
-- Organisational entities operating issuers.
--
-- `partner_id` is the SWIYU Business Partner UUID; the worker's
-- allocate_did step reads it when calling the registry. NOT NULL
-- because SWIYU Business Partner registration is a precondition for
-- tenant creation, and UNIQUE because aspect-multi-tenancy.md
-- declares the tenant ↔ Business Partner mapping as 1:1.
--
-- `display_name` and `description` are operator-supplied tenant
-- metadata, both nullable. The UI layer derives a fallback display
-- name from the bare id when `display_name` is NULL.
--
-- The three OAuth2 columns hold per-tenant SWIYU credentials and are
-- all NULLable: tenants that do not call SWIYU registries leave them
-- unset, and workers requesting a token for such a tenant fail
-- Terminal with 'tenant_missing_oauth_credentials'.
--   `oauth_client_id`     — ePortal "customer key". Not a secret;
--                           stored as TEXT.
--   `oauth_client_secret` — ePortal "customer secret". Persisted as a
--                           self-describing ciphertext blob produced
--                           by the SecretEncryptionEngine; the bare
--                           value never reaches the database.
--   `oauth_refresh_token` — ePortal "renewal token". Same shape and
--                           protection as oauth_client_secret;
--                           rotated by the runtime on every
--                           successful refresh_token grant.
-- See specs/impl-oauth2.md and specs/impl-secret-management.md.

CREATE TABLE tenants (
    id TEXT PRIMARY KEY,
    partner_id UUID NOT NULL UNIQUE,
    display_name TEXT,
    description TEXT,
    oauth_client_id TEXT,
    oauth_client_secret BYTEA,
    oauth_refresh_token BYTEA
);

-- ============================================================================
-- Issuers
-- ============================================================================
--
-- A SWIYU Business Partner with at least one DID covered by a Trust
-- Statement. The three role-keyed `*_key_id` columns reference key
-- pairs in the SigningEngine (see specs/aspect-key-management.md);
-- they are populated by the create_issuer task flow.
--
-- `created_at` drives stable ordering for the cursor-paginated GET
-- /api/v1/issuers endpoint (created_at DESC, id DESC).
--
-- `current_status_list_id` is the issuer's active status list. NULL
-- means no list has been provisioned yet; the create_issuer worker
-- populates it as part of the provision_status_list step. The FK to
-- status_lists(id) is added later in this migration, after that
-- table is created.

CREATE TABLE issuers (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    did TEXT NOT NULL,
    state TEXT,
    description TEXT,
    authorized_key_id UUID,
    authentication_key_id UUID,
    assertion_key_id UUID,
    display_name TEXT,
    logo_uri TEXT,
    locale TEXT,
    current_status_list_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- Credential offers
-- ============================================================================
--
-- The walking-skeleton aggregate. `tenant_id` is denormalised here
-- (technically derivable via `issuer_id`) so scoped queries filter
-- by tenant directly and so future RLS predicates can key on
-- tenant_id without joining.
--
-- `pre_auth_code` lifecycle:
--   - Pending offer:  set to the bare value.
--   - Cancelled:      set to NULL by `cancel`.
--   - Issued:         set to NULL by `mark_issued`.
--   - Expired:        a periodic cleanup sweep NULLs it out.
--
-- `state` is held as TEXT, not a Postgres ENUM, to keep migrations
-- simple.
--
-- `credential_type_id` is the denormalised reference to the
-- `credential_types` row the BA addressed at offer creation.
-- Nullable rather than NOT NULL: legacy offer rows written before
-- the column shipped read as NULL and the issuance handler treats
-- them as "no per-type validity policy available" (the historical
-- `vct` column still drives metadata). No foreign key to
-- `credential_types(id)` per specs/impl-credential-type.md §
-- *Relationship to credential-offer / issued-credential rows*: a FK
-- would couple the offer row's lifetime to the credential type's,
-- which is the wrong contract for a historical record.

CREATE TABLE credential_offers (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    issuer_id TEXT NOT NULL REFERENCES issuers(id),
    vct TEXT NOT NULL,
    credential_type_id TEXT,
    claims JSONB NOT NULL,
    state TEXT NOT NULL,
    pre_auth_code TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    cancelled_at TIMESTAMPTZ,
    issued_at TIMESTAMPTZ
);

CREATE INDEX credential_offers_by_tenant_issuer
    ON credential_offers (tenant_id, issuer_id);

-- ============================================================================
-- API tokens
-- ============================================================================
--
-- Token format and hashing: see specs/impl_auth.md.
--   id            primary key (bare base58, identifies the row).
--   tenant_id     FK to tenants; the token authorises requests for
--                 this tenant.
--   name          operator-supplied label; surfaces in audit logs
--                 once the audit slice lands.
--   token_hash    base58(SHA-256(bare token body)). UNIQUE so a
--                 generation collision (cosmic, given 256 bits) is
--                 rejected at insert time.
--   expires_at    optional; NULL means "never expires".
--   revoked_at    optional; non-NULL means "explicitly revoked".
--   last_used_at  bumped by the auth path on each successful request.
--
-- A token is valid iff revoked_at IS NULL AND (expires_at IS NULL OR
-- expires_at > now()).

CREATE TABLE api_tokens (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ
);

CREATE INDEX api_tokens_by_tenant ON api_tokens (tenant_id);

-- ============================================================================
-- OIDC token endpoint state
-- ============================================================================
--
-- See specs/impl_api_oidc.md.
--
-- `oidc_access_tokens.offer_id` is UNIQUE: the row-level guard
-- against double redemption. A second /token request for the same
-- offer races to this constraint and loses; the handler maps the
-- conflict to an OAuth `invalid_grant` response.
--
-- `oidc_nonces` deliberately does not constrain offer_id to UNIQUE:
-- multiple nonces may coexist for one offer (current spec uses one,
-- future batch credential issuance uses several).
--
-- The expires_at indexes serve the periodic cleanup sweep that the
-- token / credential / sweeper slices wire up.

CREATE TABLE oidc_access_tokens (
    token_hash TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    issuer_id TEXT NOT NULL REFERENCES issuers(id),
    offer_id TEXT NOT NULL UNIQUE REFERENCES credential_offers(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX oidc_access_tokens_by_expiry ON oidc_access_tokens (expires_at);

CREATE TABLE oidc_nonces (
    nonce_hash TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    issuer_id TEXT NOT NULL REFERENCES issuers(id),
    offer_id TEXT NOT NULL REFERENCES credential_offers(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX oidc_nonces_by_offer ON oidc_nonces (offer_id);
CREATE INDEX oidc_nonces_by_expiry ON oidc_nonces (expires_at);

-- ============================================================================
-- DevSigningEngine storage
-- ============================================================================
--
-- Private keys live unencrypted by design — Low maturity tier, only
-- intended for development and integration tests. Do not use in
-- production. See specs/aspect-key-management.md and
-- specs/impl-key-management.md (DevSigningEngine subsection).
--
-- No role/tenant/issuer columns: the engine is ignorant of issuer
-- ownership; the (issuer, role) -> current_id mapping lives one
-- layer up in swiyu-issuer's domain state.

CREATE TABLE signing_engine_dev_keypairs (
    id UUID PRIMARY KEY,
    algorithm TEXT NOT NULL,
    private_key BYTEA NOT NULL,
    public_key BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- Operation tasks (worker queue)
-- ============================================================================
--
-- Asynchronous operation tasks initiated by business applications.
-- Backs the create_issuer / rotate_keys / deactivate_issuer task
-- flows described in specs/aspect-issuer.md (Asynchronous execution)
-- and specs/impl-issuer.md (Worker).

CREATE TABLE operation_tasks (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    task_type TEXT NOT NULL,
    state TEXT NOT NULL,
    step TEXT,
    attempts INT NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ,
    error_code TEXT,
    error_message TEXT,
    input JSONB NOT NULL,
    state_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    result_issuer_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

-- Worker dispatch index: keeps "find next runnable task" fast as
-- completed/failed rows accumulate. Partial index covers only the
-- runnable states.
CREATE INDEX operation_tasks_dispatch
    ON operation_tasks (next_attempt_at NULLS FIRST, created_at)
    WHERE state IN ('pending', 'in_progress');

-- Tenant-scoped polling index: supports the BA's GET task endpoint
-- and any future list-by-tenant query.
CREATE INDEX operation_tasks_tenant
    ON operation_tasks (tenant_id, created_at DESC);

-- ============================================================================
-- Status lists (BitstringStatusList)
-- ============================================================================
--
-- Each issuer owns one or more BitstringStatusList instances. A list
-- carries a 32 KB bitstring at statusSize=2 (LIST_CAPACITY = 131 072
-- credentials, two bits per credential encoding valid/suspended/revoked).
--
-- `allocated_count` is the next free index handed out by issuance;
-- the issuance handler refuses to allocate once it reaches
-- LIST_CAPACITY. List rollover is a worker concern: a fresh list
-- requires a registry round-trip to obtain its public URL, and that
-- does not belong in the issuance hot path. See
-- aspect-credential-management.md (Bit allocation).
--
-- The `committed_version` / `published_version` pair drives the
-- publish worker: when committed > published the list is "dirty"
-- and a publish round is needed.
--
-- `registry_entry_id` is the entry UUID returned by
-- `create_status_list_entry`; the path segment of every subsequent
-- `update_status_list_entry` PUT.
--
-- `registry_url` is the `statusRegistryUrl` returned alongside it;
-- the `uri` value embedded in every issued credential's
-- `status.status_list` claim, and the `sub` of the published
-- `statuslist+jwt`.
--
-- Both registry columns are nullable: a row stays in the
-- *unallocated-on-registry* state from local insert until the
-- create_issuer worker's create_status_list_entry step fills them in.

CREATE TABLE status_lists (
    id TEXT PRIMARY KEY,
    issuer_id TEXT NOT NULL REFERENCES issuers(id),
    bitstring BYTEA NOT NULL,
    allocated_count INT NOT NULL DEFAULT 0,
    committed_version BIGINT NOT NULL DEFAULT 0,
    published_version BIGINT NOT NULL DEFAULT 0,
    last_publish_attempt_at TIMESTAMPTZ,
    last_publish_error TEXT,
    next_publish_attempt_at TIMESTAMPTZ,
    publish_attempts INT NOT NULL DEFAULT 0,
    registry_entry_id TEXT,
    registry_url TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (allocated_count <= 131072),
    CHECK (octet_length(bitstring) = 32768)
);

CREATE INDEX status_lists_issuer ON status_lists (issuer_id);

-- Publish worker's "find next runnable" probe.
CREATE INDEX status_lists_dirty
    ON status_lists (next_publish_attempt_at NULLS FIRST)
    WHERE committed_version > published_version;

-- Now that status_lists exists, attach the FK from issuers
-- back to it.
ALTER TABLE issuers
    ADD CONSTRAINT issuers_current_status_list_id_fkey
    FOREIGN KEY (current_status_list_id) REFERENCES status_lists(id);

-- ============================================================================
-- Issued credentials
-- ============================================================================
--
-- The issuer's record of a credential it has signed. Metadata only;
-- the signed SD-JWT VC bytes are not retained — `integrity_hash`
-- (SHA-256 of the compact serialisation handed to the wallet) is the
-- only trace that survives.
--
-- Cardinality:
--   - `UNIQUE (credential_offer_id)` codifies the 1:{0..1} relation
--     from `credential_offers` to `issued_credentials`: every issued
--     credential originates from exactly one offer; an offer that is
--     cancelled or expires before the wallet picks it up never
--     produces a row here.
--   - `UNIQUE (status_list_id, status_list_index)` codifies "indices
--     are not reused" — a status-list bit is bound to one credential
--     for the row's lifetime.
--
-- `vct` and `holder_key_jkt` are denormalised at issuance:
--   - `vct` is copied from the originating CredentialType so later
--     edits to the type row do not retroactively change what an
--     existing credential reads as.
--   - `holder_key_jkt` is the RFC 7638 thumbprint of the wallet's
--     `cnf` key, base64url-encoded. The full `cnf` key is not
--     retained; the thumbprint is enough to correlate later
--     presentations or audit trails.
--
-- `state` is held as TEXT (matching the rest of the schema's
-- enum-as-text convention). Domain values: 'active', 'suspended',
-- 'revoked'. `expired` is *not* a state — expiry is derived at read
-- time from `expires_at`. See aspect-credential-management.md
-- (Lifecycle states / Expiry is a view, not a state).

CREATE TABLE issued_credentials (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    issuer_id TEXT NOT NULL REFERENCES issuers(id),
    credential_offer_id TEXT NOT NULL REFERENCES credential_offers(id),
    vct TEXT NOT NULL,
    holder_key_jkt TEXT NOT NULL,
    status_list_id TEXT NOT NULL REFERENCES status_lists(id),
    status_list_index INT NOT NULL,
    state TEXT NOT NULL DEFAULT 'active',
    integrity_hash BYTEA NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,

    UNIQUE (status_list_id, status_list_index),
    UNIQUE (credential_offer_id)
);

-- Tenant-scoped listing/pagination support for the management API
-- (`GET /api/v1/issued-credentials`). The trailing `issued_at DESC`
-- matches the default sort order.
CREATE INDEX issued_credentials_tenant_issuer
    ON issued_credentials (tenant_id, issuer_id, issued_at DESC);

-- Holder-keyed lookup support (e.g. "what has this wallet
-- received?"). Tenant + issuer scoped because thumbprints are not
-- globally unique across issuers.
CREATE INDEX issued_credentials_holder
    ON issued_credentials (tenant_id, issuer_id, holder_key_jkt);

-- ============================================================================
-- Credential types
-- ============================================================================
--
-- Per-tenant catalogue of credential types a tenant's issuers can
-- offer. Replaces the compile-time `vct.rs` catalogue (removed in
-- step 12 of the credential-type slice).
--
-- Cardinality and ownership:
--   - Each row belongs to exactly one tenant. Two tenants may carry
--     the same `vct` value on independent rows -- credential types
--     are not globally unique. The `UNIQUE (tenant_id, vct)`
--     constraint codifies "a tenant has at most one credential-type
--     row per vct".
--   - The relationship to `issuers` is many-to-many via the
--     `issuer_credential_types` join table below.
--
-- Column notes:
--   `claim_schema`              JSON Schema validating the
--                               credential's application-level claims.
--                               Required: a credential type without a
--                               schema cannot validate at issuance.
--   `claim_schema_source_url` /
--   `claim_schema_fetched_at`   Provenance for schemas fetched from
--                               an external URL; both nullable.
--   `claims`                    OID4VCI claims metadata; per-claim
--                               display labels surfaced verbatim in
--                               the issuer metadata projection.
--   `default_validity_duration` Required at creation. No
--                               application-level fallback at
--                               issuance -- silently picking a
--                               default would produce credentials
--                               with surprise expiry.
--   `revocation_mode`           TEXT (enum-as-text):
--                               'revocable' / 'suspendable' /
--                               'revocable_and_suspendable' / 'none'.
--                               The credential-lifecycle handlers
--                               reject verbs the mode forbids with
--                               HTTP 409.
--   `retired_at`                Soft-delete marker. Already-issued
--                               credentials may still reference the
--                               row long after retirement, so rows
--                               are never hard-deleted.

CREATE TABLE credential_types (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    vct TEXT NOT NULL,

    display JSONB NOT NULL DEFAULT '[]'::jsonb,
    internal_description TEXT,

    claim_schema JSONB NOT NULL,
    claim_schema_source_url TEXT,
    claim_schema_fetched_at TIMESTAMPTZ,
    claims JSONB NOT NULL DEFAULT '{}'::jsonb,

    default_validity_duration INTERVAL NOT NULL,
    revocation_mode TEXT NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retired_at TIMESTAMPTZ,

    UNIQUE (tenant_id, vct)
);

-- Hot path: "list a tenant's active (non-retired) credential types".
-- Retired rows stay in the table for audit and historical lookup
-- from already-issued credentials.
CREATE INDEX credential_types_tenant_active
    ON credential_types (tenant_id)
    WHERE retired_at IS NULL;

-- ============================================================================
-- Issuer / credential-type assignments
-- ============================================================================
--
-- Many-to-many join between `issuers` and `credential_types`: an
-- issuer offers a credential type only when a row exists here. The
-- OID4VCI metadata projection consumes
-- `credential_types JOIN issuer_credential_types` so wallets see
-- exactly the assigned types in `credential_configurations_supported`.
--
-- Cross-tenant integrity (both the issuer and the credential type
-- must belong to the same tenant) is enforced in application code at
-- the assignment handler, not via a SQL check constraint. A SQL-level
-- enforcement would need either a trigger (heavy) or a composite FK
-- against a denormalised `tenant_id` on every referenced row; the
-- application check is the simplest faithful enforcement and matches
-- how the issuance handler already performs (tenant, issuer,
-- credential type) ownership checks before claim validation.
--
-- Retiring a credential type hard-deletes its rows from this table in
-- the same transaction that stamps `credential_types.retired_at`, so
-- a retired type drops out of every issuer's offer set atomically.
--
-- See specs/impl-credential-type.md for rationale.

CREATE TABLE issuer_credential_types (
    issuer_id TEXT NOT NULL REFERENCES issuers(id),
    credential_type_id TEXT NOT NULL REFERENCES credential_types(id),
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (issuer_id, credential_type_id)
);

-- Tenant-scoped listing support.
CREATE INDEX issuer_credential_types_tenant
    ON issuer_credential_types (tenant_id);

-- Reverse-lookup support: "which issuers carry this credential type?"
-- The retire handler also uses this index path when deleting
-- assignments by credential_type_id.
CREATE INDEX issuer_credential_types_credential_type
    ON issuer_credential_types (credential_type_id);

-- No seed data. Contributors create their own dev tenant via
-- `swiyu-issuer-cli tenant bootstrap-dev-from-env`, sourcing their
-- own SWIYU Business Partner UUID and OAuth2 credentials from `.env`.
-- API tokens are minted on demand (`swiyu-issuer-cli tenant
-- api-token mint`).
