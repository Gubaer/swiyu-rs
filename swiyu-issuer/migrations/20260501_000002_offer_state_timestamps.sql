-- v0.1.1: state-transition timestamps on credential_offers.
--
-- See specs/impl_api_management.md (Schema additions for v0.1.1) for
-- design rationale. cancelled_at is written by the cancel endpoint;
-- issued_at is reserved for the OIDC binary's wallet-redemption flow
-- in a later slice but ships now so the management API contract is
-- stable today.

ALTER TABLE credential_offers
    ADD COLUMN cancelled_at TIMESTAMPTZ,
    ADD COLUMN issued_at TIMESTAMPTZ;
