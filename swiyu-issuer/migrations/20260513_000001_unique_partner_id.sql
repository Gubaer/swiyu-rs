-- Enforce the `tenant 1:1 SWIYU Business Partner` invariant at the
-- database boundary.
--
-- aspect-multi-tenancy.md declares the 1:1 mapping at the conceptual
-- level; the previous migration tightened `partner_id` to NOT NULL
-- UUID but left the column unconstrained on uniqueness. Without the
-- UNIQUE constraint two tenants could share a Business Partner UUID,
-- and the dev-tenant bootstrap path that wants to do
-- `find_by_partner_id` would need a tie-breaker. Lifting the rule
-- into the schema removes both gaps in one step.
--
-- The seeded dev row (`4Mk7yK5pQR7sN3` -> partner
-- `7355b9bb-d45a-4d42-82ea-0c30b3f2fa25`) is the only existing tenant,
-- so the constraint applies cleanly. A fresh dev DB built from this
-- migration onward refuses any attempt to insert a second tenant with
-- the same partner_id.

ALTER TABLE tenants
    ADD CONSTRAINT tenants_partner_id_key UNIQUE (partner_id);
