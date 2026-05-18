-- ============================================================================
-- Credential types
-- ============================================================================
--
-- Per-tenant catalogue of credential types a tenant's issuers can
-- offer. Replaces the compile-time `vct.rs` catalogue once the
-- credential-type slice cuts over; see specs/plan-credential-type.md
-- and specs/impl-credential-type.md.
--
-- Cardinality and ownership:
--   - Each row belongs to exactly one tenant. Two tenants may carry
--     the same `vct` value on independent rows -- credential types
--     are not globally unique. The `UNIQUE (tenant_id, vct)`
--     constraint codifies "a tenant has at most one credential-type
--     row per vct".
--   - The relationship to `issuers` is many-to-many via the
--     `issuer_credential_types` join table (next migration).
--
-- Column notes:
--   `claim_schema`              JSON Schema validating the
--                               credential's application-level claims.
--                               Required: a credential type without a
--                               schema cannot validate at issuance.
--   `claim_schema_source_url` /
--   `claim_schema_fetched_at`   Provenance for schemas fetched from
--                               an external URL; both nullable.
--   `claims`                    Sample / default claims payload used
--                               for tenant-facing examples; not
--                               authoritative.
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
