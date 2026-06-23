//! Reusable core of `didtool`: persistent key storage ([`keystore`]) and the
//! low-level key cryptography it builds on ([`crypto`]).
//!
//! The `didtool` binary layers a CLI and registry/HTTP integration on top of
//! this; those parts live only in the binary and are gated behind the `cli`
//! Cargo feature. External consumers that need just the key store can depend on
//! this crate with `default-features = false` to avoid pulling in the CLI and
//! HTTP dependency closure.

pub mod crypto;
pub mod keystore;
