use std::sync::Arc;

use axum::http::HeaderValue;
use sqlx::PgPool;

use crate::domain::AnySigningEngine;
use crate::state::ValidatorCache;

/// Which browser origins the OIDC endpoints answer CORS requests for.
pub enum CorsAllowedOrigins {
    /// Answer any origin with `Access-Control-Allow-Origin: *`. The
    /// dev default when `OIDC_CORS_ALLOWED_ORIGINS` is unset. Safe
    /// because the OID4VCI pre-authorized-code flow carries its token
    /// in the `Authorization` header, never in cookies, so credentials
    /// are not allowed and the `*`-with-credentials hazard does not
    /// apply.
    Any,
    /// Answer only these exact origins (e.g. `https://wallet.example`).
    List(Vec<HeaderValue>),
}

pub struct Config {
    /// Public base URL the wallet sees. The metadata document
    /// substitutes this into `credential_issuer`,
    /// `credential_endpoint`, and the like. Both binaries
    /// (`swiyu-issuer-mgmtapi` and `swiyu-issuer-oidcapi`) must
    /// agree on it; a reverse proxy in front of the two is the
    /// canonical layout.
    pub issuer_base_url: String,

    /// Lifetime of an access token minted at `POST /token`. Mirrors
    /// the `c_nonce_ttl` in v0.1.x so the wallet's `expires_in` and
    /// `c_nonce_expires_in` line up.
    pub access_token_ttl: chrono::Duration,

    /// Lifetime of a `c_nonce` minted at `POST /token`. Currently
    /// equal to `access_token_ttl`; rotated independently when batch
    /// credential issuance arrives.
    pub c_nonce_ttl: chrono::Duration,

    /// Browser origins the OIDC endpoints serve CORS requests for.
    pub cors_allowed_origins: CorsAllowedOrigins,
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
    pub signing_engine: Arc<AnySigningEngine>,
    pub validators: Arc<ValidatorCache>,
}

impl AppState {
    pub fn new(pool: PgPool, config: Config, signing_engine: Arc<AnySigningEngine>) -> Self {
        Self {
            pool,
            config: Arc::new(config),
            signing_engine,
            validators: Arc::new(ValidatorCache::new()),
        }
    }
}
