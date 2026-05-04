-- Adds partner_id to the tenants table.
--
-- The worker's allocate_did step reads partner_id when calling the
-- SWIYU Identifier Registry; a tenant without one cannot have new
-- issuers created. Nullable so non-registry-touching tenants stay
-- possible; the worker fails the task Terminal with
-- 'tenant_missing_partner_id' when this column is NULL.

ALTER TABLE tenants
    ADD COLUMN partner_id TEXT;

-- Backfill the seeded dev tenant from migration 0001 with a clearly-
-- fake placeholder. The all-zero ("nil") UUID flags the row as
-- "must be re-onboarded before any real registry call"; real SWIYU
-- partner-ids are v4 UUIDs.
UPDATE tenants
SET partner_id = '00000000-0000-0000-0000-000000000000'
WHERE id = '4Mk7yK5pQR7sN3';
