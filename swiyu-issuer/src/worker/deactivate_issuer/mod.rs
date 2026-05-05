//! `DeactivateIssuer` task-type executor and supporting types.
//!
//! Step 9.1 introduced the input and state-data shapes; step 9.3
//! adds `build_deactivation_log` plus its shared `log_builder`.
//! `publish_log` and `mark_deactivated` land in 9.4 and 9.5.

pub mod build_deactivation_log;
pub mod log_builder;
pub mod state;

pub use state::{DeactivateIssuerInput, DeactivateIssuerStateData};
