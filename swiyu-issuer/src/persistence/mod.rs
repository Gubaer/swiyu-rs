pub mod api_tokens;
pub mod credential_offers;
pub mod credential_types;
mod errors;
mod helpers;
pub mod issued_credentials;
pub mod issuer_credential_types;
pub mod issuers;
pub mod oidc;
pub mod operation_tasks;
mod pool;
pub mod status_lists;
pub mod tenant_secret_keys;
pub mod tenants;

pub use errors::PersistenceError;
pub use pool::{connect, run_migrations};

/// Paginated result returned by list queries.
///
/// The underlying query fetches `limit + 1` rows; if more than `limit`
/// rows come back, `has_more` is `true` and the extra row is dropped.
#[derive(Debug)]
pub struct ListPage<T> {
    pub items: Vec<T>,
    pub has_more: bool,
}
