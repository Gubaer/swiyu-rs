-- The OIDC binary's GET /credential-offer/{offer_id} endpoint must
-- return the bare pre-authorised code in the response body (the
-- OID4VCI by-reference flow requires it). The credential_offers row
-- only stores a hash of that code, so the management binary persists
-- the bare value here at offer creation. The OIDC binary reads it
-- out at first wallet fetch.
--
-- See specs/impl_api_oidc.md (Schema additions) for design rationale
-- and lifecycle (write at create, delete at first terminal-state
-- transition, expire-and-sweep).
--
-- ON DELETE CASCADE is defence in depth — nothing currently deletes
-- a credential_offers row, but if a hard delete is ever introduced
-- the bridge entry must not outlive the parent.

CREATE TABLE oidc_offer_bridge (
    offer_id TEXT PRIMARY KEY REFERENCES credential_offers(id) ON DELETE CASCADE,
    pre_auth_code TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX oidc_offer_bridge_by_expiry ON oidc_offer_bridge (expires_at);
