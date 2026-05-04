//! Task-dispatching worker for swiyu-issuer.
//!
//! A single tokio task that picks operation tasks off the queue and
//! drives them to completion through their per-task-type step sequence.
//! See `specs/impl-issuer.md` (Worker section).

pub mod backoff;
pub mod create_issuer;
pub mod dispatch;
pub mod registry;
