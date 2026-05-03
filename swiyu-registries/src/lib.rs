//! Async HTTP clients for the SWIYU-operated registries.
//!
//! Each registry has its own submodule (`identifier`, `status`,
//! `trust`) gated behind a feature of the same name; consumers opt
//! in to the ones they need. Shared machinery — error types, retry
//! classification, the configured `reqwest::Client` builder — lives
//! in [`common`].

pub mod common;

#[cfg(feature = "identifier")]
pub mod identifier;
