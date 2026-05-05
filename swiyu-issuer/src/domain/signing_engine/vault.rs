use std::time::Duration;

use reqwest::Url;
use secrecy::SecretString;

/// Configuration for the Vault Transit signing backend.
///
/// Populated from environment variables in the binary; see `.env.example`
/// for the variables that map to each field.
pub struct VaultSigningEngineConfig {
    /// Base URL of the Vault server (`VAULT_ADDR`), e.g. `http://127.0.0.1:8200`.
    /// The Transit mount point is configured separately via `transit_path`.
    pub address: Url,

    /// Vault auth token (`VAULT_TOKEN`). Held as `SecretString` so accidental
    /// `Debug` / `Display` prints elide the value — tokens leaking into logs
    /// is a recurring real-world failure mode.
    pub token: SecretString,

    /// Mount path of the Transit secrets engine, without surrounding slashes
    /// (e.g. `transit`). Configurable because Vault deployments occasionally
    /// mount Transit under a non-default path; request URLs are built as
    /// `/v1/{transit_path}/...`. Defaults to `DEFAULT_TRANSIT_PATH`.
    pub transit_path: String,

    /// Per-request HTTP timeout applied to every Vault call. Since v1 has no
    /// retry or backoff, this is also the total wall-clock budget for a single
    /// signing-engine call. Defaults to `DEFAULT_REQUEST_TIMEOUT`.
    pub request_timeout: Duration,
}

impl VaultSigningEngineConfig {
    /// Default Transit mount path. Matches Vault's out-of-the-box mount point,
    /// so deployments that haven't relocated Transit can omit the override.
    pub const DEFAULT_TRANSIT_PATH: &'static str = "transit";

    /// Default per-request timeout. Chosen to fail fast on a misconfigured or
    /// unreachable Vault while leaving headroom for a healthy local network.
    pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
}

// Fields are populated by `new` and read by trait methods filled in
// in subsequent commits per `specs/plan-vault-signing-engine.md`
// (steps 3–5). Allowing dead_code keeps the skeleton building under
// `-D warnings` without forcing a half-implemented method.
#[allow(dead_code)]
pub struct VaultSigningEngine {
    client: reqwest::Client,
    address: Url,
    token: SecretString,
    transit_path: String,
}

impl VaultSigningEngine {
    pub fn new(config: VaultSigningEngineConfig) -> Self {
        // reqwest::ClientBuilder::build only fails on TLS init errors;
        // we configure no custom CA, no proxy, no resolver, so failure
        // is unreachable for this code path.
        let client = reqwest::Client::builder()
            .timeout(config.request_timeout)
            .build()
            .expect("reqwest client build with default options");
        Self {
            client,
            address: config.address,
            token: config.token,
            transit_path: config.transit_path,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    fn sample_config() -> VaultSigningEngineConfig {
        VaultSigningEngineConfig {
            address: Url::parse("http://127.0.0.1:8200").unwrap(),
            token: SecretString::from("dev-only-root"),
            transit_path: VaultSigningEngineConfig::DEFAULT_TRANSIT_PATH.to_string(),
            request_timeout: VaultSigningEngineConfig::DEFAULT_REQUEST_TIMEOUT,
        }
    }

    #[test]
    fn defaults_match_plan() {
        assert_eq!(VaultSigningEngineConfig::DEFAULT_TRANSIT_PATH, "transit");
        assert_eq!(
            VaultSigningEngineConfig::DEFAULT_REQUEST_TIMEOUT,
            Duration::from_secs(5)
        );
    }

    #[test]
    fn new_carries_config_through() {
        let engine = VaultSigningEngine::new(sample_config());
        assert_eq!(engine.address.as_str(), "http://127.0.0.1:8200/");
        assert_eq!(engine.transit_path, "transit");
        assert_eq!(engine.token.expose_secret(), "dev-only-root");
    }
}
