//! `CreateIssuer` saga: the multi-step task that runs on
//! `POST /api/v1/issuers`.
//!
//! Allocates a DID at the SWIYU Identifier Registry, generates the
//! three keypairs (authorized / authentication / assertion), signs
//! and publishes the genesis DIDLog entry, persists the issuer row,
//! and provisions a status-list entry. Each step is one submodule
//! exporting one `execute_*` function; the dispatch loop in
//! [`crate::worker::runner`] sequences them and persists progress in
//! `operation_tasks` so a crash mid-saga resumes from the same step.

pub mod allocate_did;
pub mod build_initial_didlog;
pub mod create_status_list_entry;
pub mod didlog_builder;
pub mod generate_keys;
pub mod persist_issuer;
pub mod provision_status_list;
pub mod publish_didlog;
pub mod state;

pub use allocate_did::execute_allocate_did;
pub use build_initial_didlog::execute_build_initial_didlog;
pub use create_status_list_entry::execute_create_status_list_entry;
pub use generate_keys::execute_generate_keys;
pub use persist_issuer::execute_persist_issuer;
pub use provision_status_list::execute_provision_status_list;
pub use publish_didlog::execute_publish_didlog;
pub use state::{CreateIssuerInput, CreateIssuerStateData, KeyTriple};
