-- Extends `issuers` with the columns required for the
-- issuer-management slice (per specs/aspect-issuer.md and
-- specs/impl-issuer.md):
--
--   * `state`                     — lifecycle state
--                                   ('active' | 'deactivated')
--   * `description`               — human-readable description
--   * `authorized_key_id`         — current Authorized KeyPairId
--   * `authentication_key_id`     — current Authentication KeyPairId
--   * `assertion_key_id`          — current Assertion KeyPairId
--
-- All five are nullable while expand-contract is in progress: the
-- seeded dev row from migration 0004 carries the legacy
-- `signing_key_id` and leaves the new columns NULL; new issuers
-- created through the issuer-management task flow populate the new
-- columns and leave `signing_key_id` NULL.
--
-- `signing_key_id` is also relaxed from NOT NULL to nullable so new
-- issuers do not need a fictitious legacy keystore handle. The
-- column itself is dropped together with `logo_uri` and `locale`
-- once the OIDC binary migrates from the swiyu-didtool keystore to
-- SigningEngine-based signing.

ALTER TABLE issuers
    ADD COLUMN state TEXT,
    ADD COLUMN description TEXT,
    ADD COLUMN authorized_key_id UUID,
    ADD COLUMN authentication_key_id UUID,
    ADD COLUMN assertion_key_id UUID,
    ALTER COLUMN signing_key_id DROP NOT NULL;
