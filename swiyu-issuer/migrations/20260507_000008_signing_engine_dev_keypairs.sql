-- Storage for the development SigningEngine. Private keys live in
-- this table unencrypted by design — this is the Low maturity tier
-- and is only intended for development and integration tests. Do
-- not use in production.
--
-- See specs/aspect-key-management.md and specs/impl-key-management.md
-- (DevSigningEngine subsection) for design rationale. The schema has
-- no role/tenant/issuer columns: the engine is ignorant of issuer
-- ownership; the (issuer, role) -> current_id mapping lives one
-- layer up in swiyu-issuer's domain state.

CREATE TABLE signing_engine_dev_keypairs (
    id UUID PRIMARY KEY,
    algorithm TEXT NOT NULL,
    private_key BYTEA NOT NULL,
    public_key BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
