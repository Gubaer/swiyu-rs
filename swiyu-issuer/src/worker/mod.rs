//! Task-dispatching worker for swiyu-issuer.
//!
//! A single tokio task that picks operation tasks off the queue and
//! drives them to completion through their per-task-type step sequence.
//! See `specs/impl-issuer.md` (Worker section).

pub mod backoff;
pub mod create_issuer;
pub mod deactivate_issuer;
pub mod dispatch;
pub mod registry;
pub mod rotate_keys;
pub mod runner;
pub mod status_list_publisher;

pub use runner::{Worker, WorkerError};
pub use status_list_publisher::{PublisherConfig, StatusListPublisher};

// `test_support` is hand-rolled mocks for `RegistryFacade` and
// `SigningEngine`, used by both inline executor tests and integration
// tests under `tests/`. It is always compiled (rather than gated on
// `cfg(test)`) so integration tests — which see the library without
// `cfg(test)` — can access it. `#[doc(hidden)]` keeps it out of the
// public API surface.
#[doc(hidden)]
pub mod test_support;
