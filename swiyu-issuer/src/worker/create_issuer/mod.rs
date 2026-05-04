//! `CreateIssuer` task-type executor and supporting types.
//!
//! Step executors land in 7.6; this slice introduces the input and
//! state-data shapes the dispatcher and (later) the executors share.

pub mod state;

pub use state::{CreateIssuerInput, CreateIssuerStateData, KeyTriple};
