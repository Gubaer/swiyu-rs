use std::sync::Arc;

use sqlx::PgPool;

use crate::domain::AnySigningEngine;

use super::signer::Signer;

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
}

impl Config {
    /// Default value for `access_token_ttl` when the binary's
    /// `ACCESS_TOKEN_TTL_SECONDS` env var is unset, in seconds.
    pub const DEFAULT_ACCESS_TOKEN_TTL_SECONDS: i64 = 300;

    /// Default value for `c_nonce_ttl` when the binary's
    /// `C_NONCE_TTL_SECONDS` env var is unset, in seconds.
    pub const DEFAULT_C_NONCE_TTL_SECONDS: i64 = 300;
}

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Arc<Config>,
    // `signer` is the legacy ephemeral fixture path; `engine` is the
    // SigningEngine-backed replacement being phased in. Both fields
    // exist while the credential handler is still on the old path;
    // the eventual cleanup drops `signer` and `Signer` entirely.
    pub signer: Arc<Signer>,
    pub engine: Arc<AnySigningEngine>,
}

impl AppState {
    pub fn new(
        pool: PgPool,
        config: Config,
        signer: Signer,
        engine: Arc<AnySigningEngine>,
    ) -> Self {
        Self {
            pool,
            config: Arc::new(config),
            signer: Arc::new(signer),
            engine,
        }
    }
}
