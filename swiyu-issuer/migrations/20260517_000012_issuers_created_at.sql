-- Adds created_at to the issuers table.
--
-- Drives stable ordering for the cursor-paginated GET /api/v1/issuers
-- endpoint. The list keys off (created_at DESC, id DESC) so a tenant
-- sees newest issuers first; without created_at, ordering would fall
-- back to lexical-by-random-id, which is essentially arbitrary order.
--
-- DEFAULT NOW() backfills the seeded dev row from migration 0001 to
-- migration time. That row carries state = NULL (legacy shape) and is
-- filtered out of the list endpoint anyway, so the backfill timestamp
-- has no observable effect on BAs.

ALTER TABLE issuers
    ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
