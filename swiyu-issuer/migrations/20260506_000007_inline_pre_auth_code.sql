-- Replaces the oidc_offer_bridge table + credential_offers.pre_auth_code_hash
-- pair with a single nullable pre_auth_code column directly on
-- credential_offers. See specs/impl_api_oidc.md and
-- specs/aspect-persistence.md for the rationale: the by-reference offer
-- fetch needs the bare value at request time, the hash on the parent row
-- never earned its keep, and the separate bridge table didn't actually
-- isolate a leak surface from the parent row.
--
-- Lifecycle of the new column:
--   - Pending offer:  pre_auth_code is set (NOT NULL effectively).
--   - Cancelled:      pre_auth_code is set to NULL by `cancel`.
--   - Issued:         pre_auth_code is set to NULL by `mark_issued`.
--   - Expired (stored as Pending past expires_at): the column is still
--     populated, but the periodic cleanup sweep (when it lands) is the
--     right place to NULL it.
--
-- Throwaway-data policy (aspect-persistence.md maturity rules) lets us
-- drop the old column rather than rename, since alpha rows with hashes
-- have no semantic mapping to the new bare values.

DROP TABLE oidc_offer_bridge;

ALTER TABLE credential_offers DROP COLUMN pre_auth_code_hash;
ALTER TABLE credential_offers ADD COLUMN pre_auth_code TEXT;
