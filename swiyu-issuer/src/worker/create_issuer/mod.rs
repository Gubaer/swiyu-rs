//! `CreateIssuer` task-type executor and supporting types.

pub mod allocate_did;
pub mod state;

pub use allocate_did::execute_allocate_did;
pub use state::{CreateIssuerInput, CreateIssuerStateData, KeyTriple};
