//! Shared types used by every registry client in this crate.

mod auth;
mod error;

pub use auth::AccessToken;
pub use error::RegistryError;
