-- Adds partner_id to the tenants table.
--
-- The worker's allocate_did step reads partner_id when calling the
-- SWIYU Identifier Registry; a tenant without one cannot have new
-- issuers created. Nullable so non-registry-touching tenants stay
-- possible; the worker fails the task Terminal with
-- 'tenant_missing_partner_id' when this column is NULL.

ALTER TABLE tenants
    ADD COLUMN partner_id TEXT;

-- Backfill the seeded dev tenant from migration 0001 with the
-- business partner id for kacon gmbh. Use during development only.
UPDATE tenants
SET partner_id = '4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef'
WHERE id = '4Mk7yK5pQR7sN3';
