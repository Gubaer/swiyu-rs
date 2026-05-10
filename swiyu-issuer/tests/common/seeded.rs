//! Mirrors of the values written by the consolidated baseline
//! migration `swiyu-issuer/migrations/20260430_000001_init.sql` for
//! the dev fixture rows.
//!
//! Tests that assert on a seeded value (round-trip checks against the
//! migration) should reference these constants, so a future seed
//! change touches the migration plus this file rather than hunting
//! through individual `assert_eq!` literals. Test fixtures that
//! happen to use a "real-looking" UUID for an arbitrary partner do
//! NOT need to come from here — they are unrelated to the seed.

#![allow(dead_code)] // not every test module that pulls common/ uses these

/// Partner id (SWIYU business-partner UUID) carried by the seeded
/// dev tenant.
pub const SEEDED_DEV_TENANT_PARTNER_ID: &str = "7355b9bb-d45a-4d42-82ea-0c30b3f2fa25";
