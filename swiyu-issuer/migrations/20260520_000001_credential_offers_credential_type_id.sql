-- Denormalised reference from `credential_offers` to the
-- `credential_types` row that the BA addressed at offer creation.
--
-- Nullable rather than NOT NULL: the column ships after offers
-- already exist in any non-production environment, and there is no
-- meaningful default to backfill. New offers minted by the
-- management API always set Some(...); legacy rows read as None and
-- the issuance handler treats them as "no per-type validity policy
-- available" (the historical `vct` column still drives metadata).
--
-- No foreign key on `credential_types(id)` per
-- specs/impl-credential-type.md § *Relationship to credential-offer /
-- issued-credential rows*: a FK would couple the offer row's
-- lifetime to the credential type's, which is the wrong contract for
-- a historical record.

ALTER TABLE credential_offers
    ADD COLUMN credential_type_id TEXT;
