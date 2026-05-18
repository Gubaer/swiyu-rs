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
