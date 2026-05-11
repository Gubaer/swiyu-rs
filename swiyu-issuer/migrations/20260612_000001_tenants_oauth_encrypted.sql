-- Re-types the two OAuth2 secret columns as BYTEA so the application
-- can persist self-describing ciphertext blobs produced by the
-- SecretEncryptionEngine. `oauth_client_id` is not a secret and stays
-- TEXT.
--
-- Destructive: any existing values are dropped. The columns are
-- populated by `swiyu-issuer-cli tenant set-oauth-credentials` and
-- `tenant import-oauth-refresh-token` (and by the dev compose
-- bootstrap-dev-tenant service from .env), so dev environments
-- re-seed on the next `docker compose up`.

ALTER TABLE tenants
    DROP COLUMN oauth_client_secret,
    DROP COLUMN oauth_refresh_token,
    ADD COLUMN oauth_client_secret BYTEA,
    ADD COLUMN oauth_refresh_token BYTEA;
