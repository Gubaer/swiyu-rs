use std::sync::Arc;

use sqlx::PgPool;

use crate::domain::AnySigningEngine;

pub struct Config {
    /// Public base URL the wallet sees. The metadata document
    /// substitutes this into `credential_issuer`,
    /// `credential_endpoint`, and the like. Both binaries
    /// (`issuer-mgmt` and `issuer-oidc`) must agree on it; a
    /// reverse proxy in front of the two is the canonical layout
    /// (see `impl_api_oidc.md` Deployment topology).
    pub issuer_base_url: String,

    /// Lifetime of an access token minted at `POST /token`. Mirrors
    /// the `c_nonce_ttl` in v0.1.x so the wallet's `expires_in` and
    /// `c_nonce_expires_in` line up.
    pub access_token_ttl: chrono::Duration,

    /// Lifetime of a `c_nonce` minted at `POST /token`. Currently
    /// equal to `access_token_ttl`; rotated independently when batch
    /// credential issuance arrives.
    pub c_nonce_ttl: chrono::Duration,

    /// Template for the `status_list.uri` claim embedded in every
    /// issued credential. The literal `{list_id}` is replaced with
    /// the list's bare base58 id at issuance time. The concrete
    /// template comes from the SWIYU Status Registry contract, which
    /// is not yet finalised — alpha/beta credentials may carry a URL
    /// the verifier cannot resolve until the Registry is wired up
    /// (phase 2). See plan-credential-management.md (Cross-phase open
    /// questions / Status-list well-known URL format).
    pub status_list_url_template: String,
}

impl Config {
    /// Default value for `access_token_ttl` when the binary's
    /// `ACCESS_TOKEN_TTL_SECONDS` env var is unset, in seconds.
    pub const DEFAULT_ACCESS_TOKEN_TTL_SECONDS: i64 = 300;

    /// Default value for `c_nonce_ttl` when the binary's
    /// `C_NONCE_TTL_SECONDS` env var is unset, in seconds.
    pub const DEFAULT_C_NONCE_TTL_SECONDS: i64 = 300;

    /// Placeholder used inside `status_list_url_template`; replaced
    /// at issuance time with the credential's status-list id.
    pub const STATUS_LIST_URL_LIST_ID_PLACEHOLDER: &'static str = "{list_id}";
}

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Arc<Config>,
    pub engine: Arc<AnySigningEngine>,
}

impl AppState {
    pub fn new(pool: PgPool, config: Config, engine: Arc<AnySigningEngine>) -> Self {
        Self {
            pool,
            config: Arc::new(config),
            engine,
        }
    }
}
