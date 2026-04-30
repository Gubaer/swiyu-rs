-- Initial schema for swiyu-issuer.
-- See specs/impl_persistence.md for design rationale (identifier strategy,
-- denormalisation choices, deferred constraints).

-- Tenants: organisational entities operating issuers. Body intentionally
-- minimal at v0.1.0; columns for name, kind, contact, branding land when the
-- admin UI and onboarding flows require them.
CREATE TABLE tenants (
    id TEXT PRIMARY KEY
);

-- Issuers: SWIYU Business Partners with at least one DID covered by a Trust
-- Statement. Body intentionally minimal at v0.1.0; columns for the Business
-- Partner reference, DIDs, status lists, and branding land with their
-- respective slices.
CREATE TABLE issuers (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id)
);

-- Credential offers: the v0.1.0 aggregate driving the walking-skeleton slice.
-- tenant_id is denormalised here (technically derivable via issuer_id) so
-- scoped queries filter by tenant directly and so future RLS predicates can
-- key on tenant_id without joining.
CREATE TABLE credential_offers (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    issuer_id TEXT NOT NULL REFERENCES issuers(id),
    credential_type TEXT NOT NULL,
    claims JSONB NOT NULL,
    -- state held as TEXT, not a Postgres ENUM, to keep migrations simple.
    state TEXT NOT NULL,
    -- Only the hash of the secret pre-auth code is stored; the secret itself
    -- is returned to the wallet at offer creation and never persisted.
    pre_auth_code_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Supports the (tenant_id, issuer_id) scoping that every query against
-- credential_offers carries.
CREATE INDEX credential_offers_by_tenant_issuer
    ON credential_offers (tenant_id, issuer_id);


-- ============================================================================
-- Seed data
-- ----------------------------------------------------------------------------
-- The v0.1.0 walking-skeleton scope ships with one tenant and one issuer,
-- hand-picked with fixed IDs for predictable dev and test setups. Real
-- tenants and issuers are created via onboarding flows in later releases.
--
-- The IDs are valid 14-character base58 strings, mirroring what the
-- application's generate() will produce, so they look like real generated
-- IDs to dev tooling.
-- ============================================================================

-- Default development tenant. The only tenant the v0.1.0 system knows about;
-- every issuer (currently one) belongs to it.
INSERT INTO tenants (id) VALUES
    ('4Mk7yK5pQR7sN3');

-- Default development issuer, owned by the tenant above. The only issuer the
-- v0.1.0 system knows about; every credential offer references this issuer
-- until tenant and issuer onboarding flows are implemented.
INSERT INTO issuers (id, tenant_id) VALUES
    ('9hXq2vRtL8pK7f', '4Mk7yK5pQR7sN3');
