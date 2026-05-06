-- Phase-2 schema additions: registry coordinates.
--
-- Per specs/impl-credential-management.md § "Phase-2 schema additions:
-- registry coordinates" and plan-credential-management.md § "2.0 —
-- Phase-2 migration: registry coordinates".
--
-- `registry_entry_id` is the entry UUID returned by
-- `create_status_list_entry`; the path segment of every subsequent
-- `update_status_list_entry` PUT.
--
-- `registry_url` is the `statusRegistryUrl` returned alongside it; the
-- `uri` value embedded in every issued credential's
-- `status.status_list` claim, and the `sub` of the published
-- `statuslist+jwt`.
--
-- Both columns are nullable: a row stays in the
-- *unallocated-on-registry* state from local insert until the
-- issuer-creation operation task fills them in (see
-- plan-credential-management.md § "Eager registry-side provisioning at
-- issuer-creation time").

ALTER TABLE status_lists
    ADD COLUMN registry_entry_id TEXT,
    ADD COLUMN registry_url TEXT;
