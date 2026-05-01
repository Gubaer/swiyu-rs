-- OIDC token endpoint state.
--
-- See specs/impl_api_oidc.md (Schema additions) for design rationale.
--
-- oidc_access_tokens:
--   token_hash PK     base58(SHA-256(bare-token)). The bare value is
--                     returned to the wallet exactly once.
--   offer_id UNIQUE   the row-level guard against double redemption.
--                     A second /token request for the same offer
--                     races to this constraint and loses; the
--                     handler maps the conflict to an OAuth
--                     `invalid_grant` response.
--   tenant_id, issuer_id are denormalised for the same reasons given
--   on credential_offers (RLS readiness, scoped-query indexing).
--
-- oidc_nonces:
--   nonce_hash PK     base58(SHA-256(bare-nonce)).
--   No UNIQUE on offer_id: multiple nonces may coexist for one
--   offer (current spec uses one, future batch credential issuance
--   uses several).
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
