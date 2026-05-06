-- Initial schema for swiyu-issuer.
--
-- This file is the consolidation of the early-development migrations
-- (originally 0001 through 0012) into a single baseline. The project
-- is still pre-production; collapsing was cheaper than carrying the
-- expand/contract history. Subsequent schema changes go in their own
-- numbered migration on top of this one.
--
-- See specs/impl_persistence.md for design rationale (identifier
-- strategy, denormalisation choices, deferred constraints).

-- ============================================================================
-- Tenants
-- ============================================================================
--
-- Organisational entities operating issuers. `partner_id` is the
-- SWIYU business-partner UUID; the worker's allocate_did step reads
-- it when calling the registry. Nullable so non-registry-touching
-- tenants stay possible; the worker fails the task Terminal with
-- 'tenant_missing_partner_id' when this column is NULL.

CREATE TABLE tenants (
    id TEXT PRIMARY KEY,
    partner_id TEXT
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

CREATE TABLE credential_offers (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    issuer_id TEXT NOT NULL REFERENCES issuers(id),
    vct TEXT NOT NULL,
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
-- Seed data
-- ----------------------------------------------------------------------------
-- Walking-skeleton dev fixtures: one tenant, one issuer, one API
-- token. IDs are valid 14-character base58 strings, mirroring what
-- the application's `generate()` will produce, so they look like
-- real generated IDs to dev tooling.
--
-- The tenant's partner_id is the kacon gmbh business entity. Use
-- during development only.
--
-- The seeded API token is alpha/beta-only by policy. The transition
-- to production maturity (prod-1) revokes it explicitly via a
-- follow-up migration; see specs/aspect-persistence.md for maturity
-- rules.
--
--   Wire form:    tok_DevDevDevDevDevDevDevDevDevDevDevDevDevDe
--   Bare body:    DevDevDevDevDevDevDevDevDevDevDevDevDevDe
--   token_hash:   base58(SHA-256(bare body))
--                 = eNmyzEH7r3JEawZtuEkdePoqyEoNSoKG7FJVZPwXHbh
--
-- A unit test in domain::api_token recomputes this hash and asserts
-- it matches the literal below; if the seed body is ever changed the
-- test breaks loudly.
-- ============================================================================

INSERT INTO tenants (id, partner_id) VALUES
    ('4Mk7yK5pQR7sN3', '4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef');

-- The seeded issuer carries no SigningEngine key triple (state,
-- authorized_key_id, assertion_key_id, ...). Use it to exercise the
-- list/fetch endpoints; create a real issuer through the management
-- API's create_issuer task flow before issuing credentials.
INSERT INTO issuers (id, tenant_id, did, display_name, locale) VALUES
    ('9hXq2vRtL8pK7f',
     '4Mk7yK5pQR7sN3',
     'did:tdw:dev.example.com:9hXq2vRtL8pK7f',
     'Dev Issuer (seeded)',
     'en');

INSERT INTO api_tokens (id, tenant_id, name, token_hash) VALUES (
    '9DevDevDevDev1',
    '4Mk7yK5pQR7sN3',
    'seeded-dev-token',
    'eNmyzEH7r3JEawZtuEkdePoqyEoNSoKG7FJVZPwXHbh'
);
