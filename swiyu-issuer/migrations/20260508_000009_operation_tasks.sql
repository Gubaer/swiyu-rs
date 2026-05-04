-- Storage for asynchronous operation tasks initiated by business
-- applications. Backs the create-issuer task flow described in
-- specs/aspect-issuer.md (Asynchronous execution) and
-- specs/impl-issuer.md (Worker).
--
-- Schema is shared across task types: v1 uses only 'create_issuer';
-- 'rotate_keys' and 'deactivate_issuer' land in subsequent slices.

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
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
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
