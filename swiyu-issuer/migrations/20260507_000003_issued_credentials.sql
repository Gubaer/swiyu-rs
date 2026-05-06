-- Issued credentials for credential management.
--
-- See specs/aspect-credential-management.md (What is persisted, what
-- is not) and specs/impl-credential-management.md (Persistence schema).

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
