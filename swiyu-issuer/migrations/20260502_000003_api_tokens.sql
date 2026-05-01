-- v0.1.2: api_tokens for the first real authentication slice.
--
-- See specs/impl_auth.md for design rationale (token format, hashing,
-- dev-token seeding).
--
-- Schema:
--   id            primary key (bare base58, identifies the row).
--   tenant_id     FK to tenants; the token authorises requests for this tenant.
--   name          operator-supplied label; surfaces in audit logs once the
--                 audit slice lands.
--   token_hash    base58-encoded SHA-256 of the bare token body. UNIQUE so a
--                 generation collision (cosmic, given 256 bits) is rejected at
--                 insert time.
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
-- Seeded dev token
-- ----------------------------------------------------------------------------
-- The v0.1.x walking skeleton ships with one well-known API token bound to
-- the seeded tenant 4Mk7yK5pQR7sN3, so dev/test environments and the docker
-- compose setup can authenticate without minting first.
--
--   Wire form:    tok_DevDevDevDevDevDevDevDevDevDevDevDevDevDe
--   Bare body:    DevDevDevDevDevDevDevDevDevDevDevDevDevDe
--   token_hash:   base58(SHA-256(bare body))
--                 = eNmyzEH7r3JEawZtuEkdePoqyEoNSoKG7FJVZPwXHbh
--
-- A unit test in domain::api_token recomputes this hash and asserts it
-- matches the literal below; if the seed body is ever changed the test
-- breaks loudly.
--
-- This row is alpha/beta-only by policy. The transition to production
-- maturity (prod-1) revokes it explicitly via a follow-up migration; see
-- specs/aspect-persistence.md for maturity rules.
-- ============================================================================

INSERT INTO api_tokens (id, tenant_id, name, token_hash) VALUES (
    '9DevDevDevDev1',
    '4Mk7yK5pQR7sN3',
    'seeded-dev-token',
    'eNmyzEH7r3JEawZtuEkdePoqyEoNSoKG7FJVZPwXHbh'
);
