//! `DeactivateIssuer` task-type executor and supporting types.

pub mod build_deactivation_didlog;
pub mod didlog_builder;
pub mod mark_deactivated;
pub mod publish_didlog;
pub mod state;

pub use state::{DeactivateIssuerInput, DeactivateIssuerStateData};
