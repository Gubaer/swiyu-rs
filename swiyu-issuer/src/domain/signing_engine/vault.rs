use std::collections::HashMap;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use p256::PublicKey as P256PublicKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::DecodePublicKey;
use reqwest::{Client, StatusCode, Url};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::json;

use super::{GeneratedKeyPair, KeyAlgorithm, KeyPairId, KeyRole, RawPublicKey, SigningEngineError};

const VAULT_TYPE_ED25519: &str = "ed25519";
const VAULT_TYPE_ECDSA_P256: &str = "ecdsa-p256";
const VAULT_TOKEN_HEADER: &str = "X-Vault-Token";
// Vault stores every signing key we create at version 1; we never call rotate
// (rotation creates a brand-new Vault key under a new UUID instead).
const VAULT_KEY_VERSION: &str = "1";

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

/// Mid-maturity `SigningEngine` backed by HashiCorp Vault's Transit
/// secrets engine.
///
/// Private keys never leave Vault; signing happens server-side via the
/// Transit API. Suitable for staging and small-scale production where a
/// dedicated HSM is not yet available — production targeting FIPS-validated
/// hardware uses `HsmSigningEngine` instead.
///
/// One `reqwest::Client` is built in `new` and shared across all calls;
/// configuration (address, token, mount path, timeout) comes from
/// `VaultSigningEngineConfig`.
pub struct VaultSigningEngine {
    /// Built once in `new` with the configured timeout; reused across
    /// every request so reqwest can pool connections.
    client: Client,
    /// Base URL of the Vault server. Per-request URLs are assembled by
    /// `key_url`, which appends `/v1/{transit_path}/...` to this base.
    address: Url,
    /// Vault auth token, sent verbatim in the `X-Vault-Token` header on
    /// every request. `SecretString` keeps it from leaking through
    /// `Debug` / `Display`.
    token: SecretString,
    /// Mount path of the Transit secrets engine (e.g. `transit`). Stored
    /// verbatim from the config; `key_url` trims surrounding slashes at
    /// request time.
    transit_path: String,
}

impl VaultSigningEngine {
    pub fn new(config: VaultSigningEngineConfig) -> Self {
        // reqwest::ClientBuilder::build only fails on TLS init errors;
        // we configure no custom CA, no proxy, no resolver, so failure
        // is unreachable for this code path.
        let client = Client::builder()
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

    pub async fn generate_keypair(
        &self,
        role: KeyRole,
    ) -> Result<GeneratedKeyPair, SigningEngineError> {
        let algorithm = KeyAlgorithm::for_role(role);
        let id = KeyPairId::generate();
        self.create_key(&id, algorithm).await?;
        let public_key = self.fetch_public_key(&id).await?;
        if public_key.algorithm != algorithm {
            return Err(SigningEngineError::Backend(
                format!(
                    "vault returned algorithm {:?} for key {id}, expected {:?}",
                    public_key.algorithm, algorithm
                )
                .into(),
            ));
        }
        Ok(GeneratedKeyPair { id, public_key })
    }

    pub async fn get_public_key(&self, id: &KeyPairId) -> Result<RawPublicKey, SigningEngineError> {
        self.fetch_public_key(id).await
    }

    async fn create_key(
        &self,
        id: &KeyPairId,
        algorithm: KeyAlgorithm,
    ) -> Result<(), SigningEngineError> {
        let url = self.key_url(id)?;
        let body = json!({ "type": vault_type_label(algorithm) });
        let response = self
            .client
            .post(url)
            .header(VAULT_TOKEN_HEADER, self.token.expose_secret())
            .json(&body)
            .send()
            .await
            .map_err(reqwest_to_backend)?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let body_text = response.text().await.unwrap_or_default();
        Err(SigningEngineError::Backend(
            format!("vault create-key {status}: {body_text}").into(),
        ))
    }

    async fn fetch_public_key(&self, id: &KeyPairId) -> Result<RawPublicKey, SigningEngineError> {
        let url = self.key_url(id)?;
        let response = self
            .client
            .get(url)
            .header(VAULT_TOKEN_HEADER, self.token.expose_secret())
            .send()
            .await
            .map_err(reqwest_to_backend)?;
        let status = response.status();
        if status == StatusCode::NOT_FOUND {
            return Err(SigningEngineError::KeyNotFound(*id));
        }
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(SigningEngineError::Backend(
                format!("vault get-key {status}: {body}").into(),
            ));
        }
        let response_body: KeyReadResponse = response.json().await.map_err(reqwest_to_backend)?;
        let algorithm = parse_vault_algorithm(&response_body.data.type_)?;
        let version = response_body
            .data
            .keys
            .get(VAULT_KEY_VERSION)
            .ok_or_else(|| {
                SigningEngineError::Backend(
                    format!("vault key {id} missing version `{VAULT_KEY_VERSION}`").into(),
                )
            })?;
        let bytes = match algorithm {
            KeyAlgorithm::Ed25519 => parse_ed25519_public_key(&version.public_key)?,
            KeyAlgorithm::EcdsaP256 => parse_ecdsa_p256_public_key_pem(&version.public_key)?,
        };
        Ok(RawPublicKey { algorithm, bytes })
    }

    fn key_url(&self, id: &KeyPairId) -> Result<Url, SigningEngineError> {
        // `Url::join` re-bases relative paths and would silently drop a
        // configured base prefix (e.g. `http://host/proxy`) when the joined
        // string starts with `/`. Build the full string explicitly.
        let base = self.address.as_str().trim_end_matches('/');
        let mount = self.transit_path.trim_matches('/');
        let url_str = format!("{base}/v1/{mount}/keys/{id}");
        Url::parse(&url_str)
            .map_err(|e| SigningEngineError::Backend(format!("vault url parse: {e}").into()))
    }
}

#[derive(Deserialize)]
struct KeyReadResponse {
    data: KeyReadData,
}

#[derive(Deserialize)]
struct KeyReadData {
    #[serde(rename = "type")]
    type_: String,
    keys: HashMap<String, KeyVersion>,
}

#[derive(Deserialize)]
struct KeyVersion {
    public_key: String,
}

fn reqwest_to_backend(error: reqwest::Error) -> SigningEngineError {
    SigningEngineError::Backend(Box::new(error))
}

fn vault_type_label(algorithm: KeyAlgorithm) -> &'static str {
    match algorithm {
        KeyAlgorithm::Ed25519 => VAULT_TYPE_ED25519,
        KeyAlgorithm::EcdsaP256 => VAULT_TYPE_ECDSA_P256,
    }
}

fn parse_vault_algorithm(label: &str) -> Result<KeyAlgorithm, SigningEngineError> {
    match label {
        VAULT_TYPE_ED25519 => Ok(KeyAlgorithm::Ed25519),
        VAULT_TYPE_ECDSA_P256 => Ok(KeyAlgorithm::EcdsaP256),
        other => Err(SigningEngineError::Backend(
            format!("unknown vault key type: {other}").into(),
        )),
    }
}

fn parse_ed25519_public_key(b64: &str) -> Result<Vec<u8>, SigningEngineError> {
    let bytes = BASE64_STANDARD
        .decode(b64)
        .map_err(|e| SigningEngineError::Backend(format!("ed25519 base64: {e}").into()))?;
    if bytes.len() != 32 {
        return Err(SigningEngineError::Backend(
            format!("ed25519 public key has unexpected length: {}", bytes.len()).into(),
        ));
    }
    Ok(bytes)
}

fn parse_ecdsa_p256_public_key_pem(pem: &str) -> Result<Vec<u8>, SigningEngineError> {
    let public_key = P256PublicKey::from_public_key_pem(pem)
        .map_err(|e| SigningEngineError::Backend(format!("ecdsa-p256 pem: {e}").into()))?;
    Ok(public_key.to_encoded_point(false).as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const ED25519_FIXTURE_B64: &str = "2gc1vkhCCUeNrTVhLA/miCFvEXAFeylMxBdZqwls1HQ=";
    const ECDSA_FIXTURE_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEz1ebD9c8+3CtFrFeBmqdxtiiEUUy\ndAATdauznJBVbj9SDvinYhd50+1MDpAHwbmcm6s2fvfEQxnxkJS8emJCwA==\n-----END PUBLIC KEY-----\n";

    const CREATE_KEY_ED25519_BODY: &str =
        include_str!("../../../tests/fixtures/vault/create_key_ed25519.json");
    const CREATE_KEY_ECDSA_BODY: &str =
        include_str!("../../../tests/fixtures/vault/create_key_ecdsa_p256.json");
    const GET_KEY_ED25519_BODY: &str =
        include_str!("../../../tests/fixtures/vault/get_key_ed25519.json");
    const GET_KEY_ECDSA_BODY: &str =
        include_str!("../../../tests/fixtures/vault/get_key_ecdsa_p256.json");
    const GET_KEY_NOT_FOUND_BODY: &str =
        include_str!("../../../tests/fixtures/vault/get_key_not_found.json");
    const SIGN_UNAUTHORIZED_BODY: &str =
        include_str!("../../../tests/fixtures/vault/sign_unauthorized.json");

    const KEYS_PATH_REGEX: &str = r"^/v1/transit/keys/[^/]+$";

    fn engine_for(server: &MockServer) -> VaultSigningEngine {
        VaultSigningEngine::new(VaultSigningEngineConfig {
            address: Url::parse(&server.uri()).unwrap(),
            token: SecretString::from("dev-only-root"),
            transit_path: VaultSigningEngineConfig::DEFAULT_TRANSIT_PATH.to_string(),
            request_timeout: VaultSigningEngineConfig::DEFAULT_REQUEST_TIMEOUT,
        })
    }

    #[test]
    fn ed25519_public_key_parses_to_32_bytes() {
        let bytes = parse_ed25519_public_key(ED25519_FIXTURE_B64).unwrap();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn ed25519_public_key_rejects_wrong_length() {
        // 5-byte input ("hello"), not 32.
        let err = parse_ed25519_public_key("aGVsbG8=").unwrap_err();
        assert!(matches!(err, SigningEngineError::Backend(_)));
    }

    #[test]
    fn ed25519_public_key_rejects_invalid_base64() {
        let err = parse_ed25519_public_key("not!base64!").unwrap_err();
        assert!(matches!(err, SigningEngineError::Backend(_)));
    }

    #[test]
    fn ecdsa_p256_pem_decodes_to_sec1_uncompressed() {
        let bytes = parse_ecdsa_p256_public_key_pem(ECDSA_FIXTURE_PEM).unwrap();
        assert_eq!(bytes.len(), 65);
        assert_eq!(bytes[0], 0x04);
    }

    #[test]
    fn ecdsa_p256_pem_rejects_garbage() {
        let err = parse_ecdsa_p256_public_key_pem("not a pem").unwrap_err();
        assert!(matches!(err, SigningEngineError::Backend(_)));
    }

    #[test]
    fn vault_algorithm_round_trips() {
        assert_eq!(
            parse_vault_algorithm(vault_type_label(KeyAlgorithm::Ed25519)).unwrap(),
            KeyAlgorithm::Ed25519
        );
        assert_eq!(
            parse_vault_algorithm(vault_type_label(KeyAlgorithm::EcdsaP256)).unwrap(),
            KeyAlgorithm::EcdsaP256
        );
    }

    #[test]
    fn vault_algorithm_rejects_unknown() {
        assert!(parse_vault_algorithm("rsa-2048").is_err());
    }

    #[tokio::test]
    async fn get_public_key_returns_ed25519_bytes() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(KEYS_PATH_REGEX))
            .respond_with(ResponseTemplate::new(200).set_body_string(GET_KEY_ED25519_BODY))
            .mount(&server)
            .await;

        let engine = engine_for(&server);
        let public_key = engine.get_public_key(&KeyPairId::generate()).await.unwrap();
        assert_eq!(public_key.algorithm, KeyAlgorithm::Ed25519);
        assert_eq!(public_key.bytes.len(), 32);
    }

    #[tokio::test]
    async fn get_public_key_returns_ecdsa_sec1_uncompressed() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(KEYS_PATH_REGEX))
            .respond_with(ResponseTemplate::new(200).set_body_string(GET_KEY_ECDSA_BODY))
            .mount(&server)
            .await;

        let engine = engine_for(&server);
        let public_key = engine.get_public_key(&KeyPairId::generate()).await.unwrap();
        assert_eq!(public_key.algorithm, KeyAlgorithm::EcdsaP256);
        assert_eq!(public_key.bytes.len(), 65);
        assert_eq!(public_key.bytes[0], 0x04);
    }

    #[tokio::test]
    async fn get_public_key_404_returns_key_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(KEYS_PATH_REGEX))
            .respond_with(ResponseTemplate::new(404).set_body_string(GET_KEY_NOT_FOUND_BODY))
            .mount(&server)
            .await;

        let engine = engine_for(&server);
        let id = KeyPairId::generate();
        let err = engine.get_public_key(&id).await.unwrap_err();
        match err {
            SigningEngineError::KeyNotFound(returned) => assert_eq!(returned, id),
            other => panic!("expected KeyNotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn get_public_key_403_returns_backend() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(KEYS_PATH_REGEX))
            .respond_with(ResponseTemplate::new(403).set_body_string(SIGN_UNAUTHORIZED_BODY))
            .mount(&server)
            .await;

        let engine = engine_for(&server);
        let err = engine
            .get_public_key(&KeyPairId::generate())
            .await
            .unwrap_err();
        assert!(matches!(err, SigningEngineError::Backend(_)));
    }

    #[tokio::test]
    async fn generate_keypair_for_authorized_role_creates_ed25519() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(KEYS_PATH_REGEX))
            .respond_with(ResponseTemplate::new(200).set_body_string(CREATE_KEY_ED25519_BODY))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(KEYS_PATH_REGEX))
            .respond_with(ResponseTemplate::new(200).set_body_string(GET_KEY_ED25519_BODY))
            .mount(&server)
            .await;

        let engine = engine_for(&server);
        let pair = engine.generate_keypair(KeyRole::Authorized).await.unwrap();
        assert_eq!(pair.public_key.algorithm, KeyAlgorithm::Ed25519);
        assert_eq!(pair.public_key.bytes.len(), 32);
    }

    #[tokio::test]
    async fn generate_keypair_for_assertion_role_creates_ecdsa_p256() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(KEYS_PATH_REGEX))
            .respond_with(ResponseTemplate::new(200).set_body_string(CREATE_KEY_ECDSA_BODY))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(KEYS_PATH_REGEX))
            .respond_with(ResponseTemplate::new(200).set_body_string(GET_KEY_ECDSA_BODY))
            .mount(&server)
            .await;

        let engine = engine_for(&server);
        let pair = engine.generate_keypair(KeyRole::Assertion).await.unwrap();
        assert_eq!(pair.public_key.algorithm, KeyAlgorithm::EcdsaP256);
        assert_eq!(pair.public_key.bytes.len(), 65);
        assert_eq!(pair.public_key.bytes[0], 0x04);
    }

    #[tokio::test]
    async fn generate_keypair_create_failure_returns_backend() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(KEYS_PATH_REGEX))
            .respond_with(ResponseTemplate::new(403).set_body_string(SIGN_UNAUTHORIZED_BODY))
            .mount(&server)
            .await;

        let engine = engine_for(&server);
        let err = engine
            .generate_keypair(KeyRole::Authorized)
            .await
            .unwrap_err();
        assert!(matches!(err, SigningEngineError::Backend(_)));
    }

    #[test]
    fn defaults_match_plan() {
        assert_eq!(VaultSigningEngineConfig::DEFAULT_TRANSIT_PATH, "transit");
        assert_eq!(
            VaultSigningEngineConfig::DEFAULT_REQUEST_TIMEOUT,
            Duration::from_secs(5)
        );
    }
}
