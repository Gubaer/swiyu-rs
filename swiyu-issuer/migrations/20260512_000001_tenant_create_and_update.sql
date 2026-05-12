-- Tenant management slice: tighten `partner_id`, add metadata columns.
--
-- Three changes to `tenants`, all in one migration so the row reaches
-- its new shape atomically:
--
--   1. `partner_id` becomes native Postgres `UUID`. The column was TEXT
--      to accommodate the alpha period; format validation lived only at
--      the worker boundary. Native UUID matches the rest of the schema
--      (authorized_key_id, authentication_key_id, assertion_key_id are
--      already UUID) and lets Postgres reject malformed inputs at
--      insert time.
--
--   2. `partner_id` becomes NOT NULL. SWIYU Business Partner
--      registration is now a precondition for tenant creation; tenants
--      without a Business Partner UUID cannot be admitted to the
--      system. The previously possible `tenant_missing_partner_id`
--      Terminal worker failure goes away with this column constraint.
--
--   3. Add `display_name` and `description`, both nullable TEXT, for
--      operator-supplied tenant metadata. The UI layer derives a
--      fallback display name from the bare id when `display_name` is
--      NULL.
--
-- The seeded dev tenant (`4Mk7yK5pQR7sN3`) already carries a valid
-- canonical-form UUID partner_id, so the cast and NOT NULL apply
-- cleanly to the fixture. The two new columns default to NULL on the
-- seeded row; no UPDATE is needed here.

ALTER TABLE tenants
    ALTER COLUMN partner_id TYPE UUID USING partner_id::uuid;

ALTER TABLE tenants
    ALTER COLUMN partner_id SET NOT NULL;

ALTER TABLE tenants
    ADD COLUMN display_name TEXT,
    ADD COLUMN description  TEXT;
