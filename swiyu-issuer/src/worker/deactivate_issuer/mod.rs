//! `DeactivateIssuer` task-type executor and supporting types.
//!
//! Step 9.1 introduces the input and state-data shapes only. Step
//! executors land in 9.3–9.5.

pub mod state;

pub use state::{DeactivateIssuerInput, DeactivateIssuerStateData};
