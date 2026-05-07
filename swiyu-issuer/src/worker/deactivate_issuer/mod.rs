//! `DeactivateIssuer` task-type executor and supporting types.

pub mod build_deactivation_log;
pub mod log_builder;
pub mod mark_deactivated;
pub mod publish_log;
pub mod state;

pub use state::{DeactivateIssuerInput, DeactivateIssuerStateData};
