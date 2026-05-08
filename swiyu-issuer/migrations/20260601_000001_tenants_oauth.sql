-- OAuth2 credentials per tenant.
--
-- Adds three columns to the `tenants` table so each tenant can hold
-- its own SWIYU OAuth2 credentials: the client id / client secret
-- (long-lived material from the ePortal) and the refresh token (the
-- recurring secret that the runtime rotates on every successful
-- `refresh_token` grant). Access tokens are session artefacts and
-- not persisted.
--
-- All three columns are NULL-able. Tenants that do not call SWIYU
-- registries (today: none, but the option is preserved) leave them
-- unset; workers requesting a token for such a tenant fail Terminal
-- with `tenant_missing_oauth_credentials`. Operators populate the
-- client id / client secret via direct SQL at onboarding; the
-- refresh token's recurring import path is the
-- `tenant-mgmt import-oidc-refresh-token` subcommand.
--
-- See specs/aspect-oauth2.md and specs/impl-oauth2.md for design
-- rationale.

ALTER TABLE tenants
    ADD COLUMN oauth_client_id     TEXT,
    ADD COLUMN oauth_client_secret TEXT,
    ADD COLUMN oauth_refresh_token TEXT;
