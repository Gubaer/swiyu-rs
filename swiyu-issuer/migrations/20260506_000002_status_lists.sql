-- Status lists for credential management.
--
-- See specs/aspect-credential-management.md (Status-list integration)
-- and specs/impl-credential-management.md (Persistence schema).

-- ============================================================================
-- Status lists (BitstringStatusList)
-- ============================================================================
--
-- Each issuer owns one or more BitstringStatusList instances. A list
-- carries a 32 KB bitstring at statusSize=2 (LIST_CAPACITY = 131 072
-- credentials, two bits per credential encoding valid/suspended/revoked).
--
-- `allocated_count` is the next free index handed out by issuance; once
-- it reaches LIST_CAPACITY the issuance path provisions a fresh list
-- and re-points `issuers.current_status_list_id`. Indices are not
-- reused — see aspect-credential-management.md (Bit allocation).
--
-- The `committed_version` / `published_version` pair drives the
-- (phase-2) publish worker: when committed > published the list is
-- "dirty" and a publish round is needed. `next_publish_attempt_at`,
-- `last_publish_*`, and `publish_attempts` are inert in phase 1; they
-- land here so phase 2 ships without another migration.

CREATE TABLE status_lists (
    id TEXT PRIMARY KEY,
    issuer_id TEXT NOT NULL REFERENCES issuers(id),
    bitstring BYTEA NOT NULL,
    allocated_count INT NOT NULL DEFAULT 0,
    committed_version BIGINT NOT NULL DEFAULT 0,
    published_version BIGINT NOT NULL DEFAULT 0,
    last_publish_attempt_at TIMESTAMPTZ,
    last_publish_error TEXT,
    next_publish_attempt_at TIMESTAMPTZ,
    publish_attempts INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (allocated_count <= 131072),
    CHECK (octet_length(bitstring) = 32768)
);

CREATE INDEX status_lists_issuer ON status_lists (issuer_id);

-- Phase-2 publish worker's "find next runnable" probe. Inert in phase
-- 1 (no consumer yet); landed now so phase 2 ships with no new
-- migration of its own.
CREATE INDEX status_lists_dirty
    ON status_lists (next_publish_attempt_at NULLS FIRST)
    WHERE committed_version > published_version;

-- ============================================================================
-- Pointer from issuer to its current "active" status list
-- ============================================================================
--
-- NULL means no list has been provisioned for this issuer yet; the
-- issuance path provisions one lazily on the first credential and
-- re-points this column on capacity overflow. See
-- aspect-credential-management.md (Status-list integration).

ALTER TABLE issuers
    ADD COLUMN current_status_list_id TEXT REFERENCES status_lists(id);
