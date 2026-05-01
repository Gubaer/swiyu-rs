-- Issuer-metadata columns required by the OIDC binary's
-- /.well-known/openid-credential-issuer handler.
--
-- See specs/impl_api_oidc.md (Schema additions) for design rationale.
-- did and signing_key_id are mandatory once the OIDC binary is in
-- play (without them no credential can be signed); display_*/locale
-- are optional and a future admin slice owns them.
--
-- The oidc_access_tokens and oidc_nonces tables ship with the
-- token / credential endpoints in their own slices.

ALTER TABLE issuers
    ADD COLUMN did TEXT,
    ADD COLUMN signing_key_id TEXT,
    ADD COLUMN display_name TEXT,
    ADD COLUMN logo_uri TEXT,
    ADD COLUMN locale TEXT;

-- Backfill the seeded dev issuer with a fixture DID and key-store
-- handle. The DID and key id are placeholders that match the
-- developer keystore convention; real values land when issuer
-- onboarding flows arrive.
UPDATE issuers
SET did = 'did:tdw:dev.example.com:9hXq2vRtL8pK7f',
    signing_key_id = 'fixture-dev-9hXq2vRtL8pK7f',
    display_name = 'Dev Issuer (seeded)',
    locale = 'en'
WHERE id = '9hXq2vRtL8pK7f';

ALTER TABLE issuers
    ALTER COLUMN did SET NOT NULL,
    ALTER COLUMN signing_key_id SET NOT NULL;
