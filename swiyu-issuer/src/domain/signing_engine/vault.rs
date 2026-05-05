use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::{
    STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD,
};
use p256::PublicKey as P256PublicKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::DecodePublicKey;
use reqwest::{Client, StatusCode, Url};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::json;

use super::{
    GeneratedKeyPair, KeyAlgorithm, KeyPairId, KeyRole, RawPublicKey, Signature, SigningEngine,
    SigningEngineError,
};

const VAULT_TYPE_ED25519: &str = "ed25519";
const VAULT_TYPE_ECDSA_P256: &str = "ecdsa-p256";
const VAULT_TOKEN_HEADER: &str = "X-Vault-Token";
// Vault stores every signing key we create at version 1; we never call rotate
// (rotation creates a brand-new Vault key under a new UUID instead).
const VAULT_KEY_VERSION: &str = "1";
const VAULT_SIGNATURE_PREFIX: &str = "vault:v1:";
// Body fragments Vault returns (HTTP 400) for "key missing" cases. Substring
// match is what Vault gives us — there's no machine-readable discriminator;
// the integration tests guard against silent wording changes.
const VAULT_SIGN_KEY_NOT_FOUND: &str = "signing key not found";
// `POST keys/{id}/config` on a missing key.
const VAULT_CONFIG_KEY_NOT_FOUND: &str = "no existing key named";
// `DELETE keys/{id}` on a missing key.
const VAULT_DELETE_KEY_NOT_FOUND: &str = "could not delete key; not found";

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
    /// Base URL of the Vault server. Per-request URLs are built by
    /// appending `/v1/{transit_path}/...` to this base.
    address: Url,
    /// Vault auth token, sent verbatim in the `X-Vault-Token` header on
    /// every request. `SecretString` keeps it from leaking through
    /// `Debug` / `Display`.
    token: SecretString,
    /// Mount path of the Transit secrets engine (e.g. `transit`). Stored
    /// verbatim from the config; URL builders trim surrounding slashes
    /// at request time.
    transit_path: String,
    /// Caches the algorithm of every `KeyPairId` the engine has read or
    /// created, so `sign` can craft the right request shape without an
    /// extra Vault round-trip. Best-effort: `lookup_algorithm` falls
    /// through to a `GET` on miss.
    algorithm_cache: RwLock<HashMap<KeyPairId, KeyAlgorithm>>,
}

impl SigningEngine for VaultSigningEngine {
    async fn generate_keypair(
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

    async fn get_public_key(&self, id: &KeyPairId) -> Result<RawPublicKey, SigningEngineError> {
        self.fetch_public_key(id).await
    }

    async fn sign(&self, id: &KeyPairId, input: &[u8]) -> Result<Signature, SigningEngineError> {
        let algorithm = self.lookup_algorithm(id).await?;
        if algorithm == KeyAlgorithm::EcdsaP256 && input.len() != 32 {
            return Err(SigningEngineError::InvalidInputLength {
                expected: 32,
                actual: input.len(),
            });
        }
        let url = self.sign_url(id)?;
        let body = build_sign_request(input, algorithm);
        let response = self
            .client
            .post(url)
            .header(VAULT_TOKEN_HEADER, self.token.expose_secret())
            .json(&body)
            .send()
            .await
            .map_err(reqwest_to_backend)?;
        let status = response.status();
        if !status.is_success() {
            let body_text = response.text().await.unwrap_or_default();
            return Err(map_error(status, &body_text, *id, Op::Sign));
        }
        let response_body: SignResponse = response.json().await.map_err(reqwest_to_backend)?;
        let bytes = parse_vault_signature(&response_body.data.signature, algorithm)?;
        Ok(Signature { algorithm, bytes })
    }

    // Vault marks new keys as non-deletable by default. The two-step dance
    // (config flag, then DELETE) is required even for a key we just created.
    // Both calls are idempotent: missing-key 400s are swallowed so a second
    // delete returns Ok(()), per the trait contract.
    async fn delete_keypair(&self, id: &KeyPairId) -> Result<(), SigningEngineError> {
        self.allow_deletion(id).await?;
        self.delete_key(id).await?;
        self.cache_remove(id);
        Ok(())
    }
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
            algorithm_cache: RwLock::new(HashMap::new()),
        }
    }

    async fn allow_deletion(&self, id: &KeyPairId) -> Result<(), SigningEngineError> {
        let url = self.key_config_url(id)?;
        let body = json!({ "deletion_allowed": true });
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
        if status == StatusCode::BAD_REQUEST && body_text.contains(VAULT_CONFIG_KEY_NOT_FOUND) {
            return Ok(());
        }
        Err(SigningEngineError::Backend(
            format!("vault keys/{id}/config {status}: {body_text}").into(),
        ))
    }

    async fn delete_key(&self, id: &KeyPairId) -> Result<(), SigningEngineError> {
        let url = self.key_url(id)?;
        let response = self
            .client
            .delete(url)
            .header(VAULT_TOKEN_HEADER, self.token.expose_secret())
            .send()
            .await
            .map_err(reqwest_to_backend)?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let body_text = response.text().await.unwrap_or_default();
        if status == StatusCode::BAD_REQUEST && body_text.contains(VAULT_DELETE_KEY_NOT_FOUND) {
            return Ok(());
        }
        Err(SigningEngineError::Backend(
            format!("vault delete keys/{id} {status}: {body_text}").into(),
        ))
    }

    fn cache_remove(&self, id: &KeyPairId) {
        self.algorithm_cache.write().unwrap().remove(id);
    }

    async fn lookup_algorithm(&self, id: &KeyPairId) -> Result<KeyAlgorithm, SigningEngineError> {
        if let Some(algorithm) = self.cache_get(id) {
            return Ok(algorithm);
        }
        let public_key = self.fetch_public_key(id).await?;
        Ok(public_key.algorithm)
    }

    fn cache_get(&self, id: &KeyPairId) -> Option<KeyAlgorithm> {
        // The lock is poisoned only if a writer panicked while holding it;
        // `cache_set` does nothing but a HashMap insert, so this is unreachable.
        self.algorithm_cache.read().unwrap().get(id).copied()
    }

    fn cache_set(&self, id: KeyPairId, algorithm: KeyAlgorithm) {
        self.algorithm_cache.write().unwrap().insert(id, algorithm);
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
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(map_error(status, &body, *id, Op::Get));
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
        self.cache_set(*id, algorithm);
        Ok(RawPublicKey { algorithm, bytes })
    }

    fn key_url(&self, id: &KeyPairId) -> Result<Url, SigningEngineError> {
        self.transit_url(&format!("keys/{id}"))
    }

    fn sign_url(&self, id: &KeyPairId) -> Result<Url, SigningEngineError> {
        self.transit_url(&format!("sign/{id}"))
    }

    fn key_config_url(&self, id: &KeyPairId) -> Result<Url, SigningEngineError> {
        self.transit_url(&format!("keys/{id}/config"))
    }

    fn transit_url(&self, suffix: &str) -> Result<Url, SigningEngineError> {
        // `Url::join` re-bases relative paths and would silently drop a
        // configured base prefix (e.g. `http://host/proxy`) when the joined
        // string starts with `/`. Build the full string explicitly.
        let base = self.address.as_str().trim_end_matches('/');
        let mount = self.transit_path.trim_matches('/');
        let url_str = format!("{base}/v1/{mount}/{suffix}");
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

#[derive(Deserialize)]
struct SignResponse {
    data: SignData,
}

#[derive(Deserialize)]
struct SignData {
    signature: String,
}

#[derive(Debug, Clone, Copy)]
enum Op {
    Get,
    Sign,
}

// Concentrates the status-to-error mapping for operations that have a
// "key missing" failure mode. The delete path's "already gone" body
// substrings are handled at the call site (see `delete_keypair`), not
// here, since they map to `Ok(())`, not an error.
fn map_error(status: StatusCode, body: &str, id: KeyPairId, op: Op) -> SigningEngineError {
    match (op, status.as_u16()) {
        (Op::Get, 404) => SigningEngineError::KeyNotFound(id),
        (Op::Sign, 400) if body.contains(VAULT_SIGN_KEY_NOT_FOUND) => {
            SigningEngineError::KeyNotFound(id)
        }
        _ => SigningEngineError::Backend(format!("vault {status}: {body}").into()),
    }
}

fn build_sign_request(input: &[u8], algorithm: KeyAlgorithm) -> serde_json::Value {
    let input_b64 = BASE64_STANDARD.encode(input);
    match algorithm {
        KeyAlgorithm::Ed25519 => json!({ "input": input_b64 }),
        KeyAlgorithm::EcdsaP256 => json!({
            "input": input_b64,
            "prehashed": true,
            "hash_algorithm": "sha2-256",
            "marshaling_algorithm": "jws",
        }),
    }
}

// Decodes Vault's `vault:v1:<base64>` signature envelope. Ed25519 uses
// standard base64; ECDSA P-256 with `marshaling_algorithm=jws` uses
// base64url-no-padding. Both algorithms produce 64 raw bytes — Ed25519
// signature, or `r ‖ s` for ECDSA.
fn parse_vault_signature(
    raw: &str,
    algorithm: KeyAlgorithm,
) -> Result<Vec<u8>, SigningEngineError> {
    let body = raw.strip_prefix(VAULT_SIGNATURE_PREFIX).ok_or_else(|| {
        SigningEngineError::Backend(
            format!("vault signature missing `{VAULT_SIGNATURE_PREFIX}` prefix: {raw}").into(),
        )
    })?;
    let bytes = match algorithm {
        KeyAlgorithm::Ed25519 => BASE64_STANDARD.decode(body),
        KeyAlgorithm::EcdsaP256 => BASE64_URL_SAFE_NO_PAD.decode(body),
    }
    .map_err(|e| SigningEngineError::Backend(format!("vault signature base64: {e}").into()))?;
    if bytes.len() != 64 {
        return Err(SigningEngineError::Backend(
            format!("vault signature has unexpected length: {}", bytes.len()).into(),
        ));
    }
    Ok(bytes)
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
    const SIGN_ED25519_BODY: &str = include_str!("../../../tests/fixtures/vault/sign_ed25519.json");
    const SIGN_ECDSA_BODY: &str =
        include_str!("../../../tests/fixtures/vault/sign_ecdsa_p256.json");
    const SIGN_KEY_NOT_FOUND_BODY: &str =
        include_str!("../../../tests/fixtures/vault/sign_key_not_found.json");
    const SIGN_UNAUTHORIZED_BODY: &str =
        include_str!("../../../tests/fixtures/vault/sign_unauthorized.json");
    const CONFIG_DELETION_ALLOWED_BODY: &str =
        include_str!("../../../tests/fixtures/vault/config_deletion_allowed.json");
    const CONFIG_KEY_NOT_FOUND_BODY: &str =
        include_str!("../../../tests/fixtures/vault/config_key_not_found.json");
    const DELETE_KEY_NOT_FOUND_BODY: &str =
        include_str!("../../../tests/fixtures/vault/delete_key_not_found.json");

    // Signature strings extracted from the fixtures above; used by the
    // pure-helper tests to avoid re-parsing the JSON envelopes.
    const ED25519_SIGNATURE: &str = "vault:v1:IlKcyf5fLJ19yCrtmtUebOjeM4w+XTzkYP/LasXe2kxy1o08kqR8w/scCS/sEbhX+/h94OHgMwkqII734rRbBA==";
    const ECDSA_SIGNATURE: &str = "vault:v1:nswySSQhbnd95shhno23D43A4zvz9g14fyrC3n-5rRLEe44AtFKkQA1T8jMh9ivZEIl48h_YrORix1w_PEHhWA";

    const KEYS_PATH_REGEX: &str = r"^/v1/transit/keys/[^/]+$";
    const SIGN_PATH_REGEX: &str = r"^/v1/transit/sign/[^/]+$";
    const KEYS_CONFIG_PATH_REGEX: &str = r"^/v1/transit/keys/[^/]+/config$";

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

    #[test]
    fn parse_vault_signature_decodes_ed25519_to_64_bytes() {
        let bytes = parse_vault_signature(ED25519_SIGNATURE, KeyAlgorithm::Ed25519).unwrap();
        assert_eq!(bytes.len(), 64);
    }

    #[test]
    fn parse_vault_signature_decodes_ecdsa_p256_to_64_bytes() {
        let bytes = parse_vault_signature(ECDSA_SIGNATURE, KeyAlgorithm::EcdsaP256).unwrap();
        assert_eq!(bytes.len(), 64);
    }

    #[test]
    fn parse_vault_signature_rejects_missing_prefix() {
        let raw = ED25519_SIGNATURE
            .strip_prefix(VAULT_SIGNATURE_PREFIX)
            .unwrap();
        let err = parse_vault_signature(raw, KeyAlgorithm::Ed25519).unwrap_err();
        assert!(matches!(err, SigningEngineError::Backend(_)));
    }

    #[test]
    fn parse_vault_signature_rejects_wrong_length() {
        // 5-byte payload, not 64.
        let err = parse_vault_signature("vault:v1:aGVsbG8=", KeyAlgorithm::Ed25519).unwrap_err();
        assert!(matches!(err, SigningEngineError::Backend(_)));
    }

    #[test]
    fn parse_vault_signature_rejects_wrong_base64_flavor_for_ecdsa() {
        // Standard base64 (with `+`/`/`/`=`) for an ECDSA signature should
        // fail under base64url-no-pad decoding.
        let err = parse_vault_signature(ED25519_SIGNATURE, KeyAlgorithm::EcdsaP256).unwrap_err();
        assert!(matches!(err, SigningEngineError::Backend(_)));
    }

    #[test]
    fn build_sign_request_for_ed25519_only_has_input() {
        let request = build_sign_request(b"hello", KeyAlgorithm::Ed25519);
        assert_eq!(request["input"], BASE64_STANDARD.encode(b"hello"));
        assert!(request.get("prehashed").is_none());
        assert!(request.get("hash_algorithm").is_none());
        assert!(request.get("marshaling_algorithm").is_none());
    }

    #[test]
    fn build_sign_request_for_ecdsa_p256_has_jws_marshaling() {
        let digest = [0xa5_u8; 32];
        let request = build_sign_request(&digest, KeyAlgorithm::EcdsaP256);
        assert_eq!(request["input"], BASE64_STANDARD.encode(digest));
        assert_eq!(request["prehashed"], true);
        assert_eq!(request["hash_algorithm"], "sha2-256");
        assert_eq!(request["marshaling_algorithm"], "jws");
    }

    #[test]
    fn map_error_get_404_returns_key_not_found() {
        let id = KeyPairId::generate();
        let err = map_error(StatusCode::NOT_FOUND, r#"{"errors":[]}"#, id, Op::Get);
        match err {
            SigningEngineError::KeyNotFound(returned) => assert_eq!(returned, id),
            other => panic!("expected KeyNotFound, got {other:?}"),
        }
    }

    #[test]
    fn map_error_sign_400_signing_key_not_found_returns_key_not_found() {
        let id = KeyPairId::generate();
        let err = map_error(
            StatusCode::BAD_REQUEST,
            SIGN_KEY_NOT_FOUND_BODY,
            id,
            Op::Sign,
        );
        match err {
            SigningEngineError::KeyNotFound(returned) => assert_eq!(returned, id),
            other => panic!("expected KeyNotFound, got {other:?}"),
        }
    }

    #[test]
    fn map_error_sign_400_unrelated_body_returns_backend() {
        let id = KeyPairId::generate();
        let err = map_error(
            StatusCode::BAD_REQUEST,
            r#"{"errors":["something else"]}"#,
            id,
            Op::Sign,
        );
        assert!(matches!(err, SigningEngineError::Backend(_)));
    }

    #[test]
    fn map_error_403_returns_backend() {
        let id = KeyPairId::generate();
        let err = map_error(StatusCode::FORBIDDEN, "perm denied", id, Op::Get);
        assert!(matches!(err, SigningEngineError::Backend(_)));
    }

    #[tokio::test]
    async fn sign_ed25519_after_warmup_returns_64_bytes() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(KEYS_PATH_REGEX))
            .respond_with(ResponseTemplate::new(200).set_body_string(GET_KEY_ED25519_BODY))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path_regex(SIGN_PATH_REGEX))
            .respond_with(ResponseTemplate::new(200).set_body_string(SIGN_ED25519_BODY))
            .mount(&server)
            .await;

        let engine = engine_for(&server);
        let id = KeyPairId::generate();
        // Warm the cache so `sign` doesn't have to fetch.
        let _ = engine.get_public_key(&id).await.unwrap();
        let signature = engine.sign(&id, b"hello swiyu").await.unwrap();
        assert_eq!(signature.algorithm, KeyAlgorithm::Ed25519);
        assert_eq!(signature.bytes.len(), 64);
    }

    #[tokio::test]
    async fn sign_ecdsa_p256_with_32_byte_digest_returns_64_bytes() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(KEYS_PATH_REGEX))
            .respond_with(ResponseTemplate::new(200).set_body_string(GET_KEY_ECDSA_BODY))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path_regex(SIGN_PATH_REGEX))
            .respond_with(ResponseTemplate::new(200).set_body_string(SIGN_ECDSA_BODY))
            .mount(&server)
            .await;

        let engine = engine_for(&server);
        let id = KeyPairId::generate();
        let _ = engine.get_public_key(&id).await.unwrap();
        let digest = [0xa5_u8; 32];
        let signature = engine.sign(&id, &digest).await.unwrap();
        assert_eq!(signature.algorithm, KeyAlgorithm::EcdsaP256);
        assert_eq!(signature.bytes.len(), 64);
    }

    #[tokio::test]
    async fn sign_ecdsa_p256_rejects_31_byte_input() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(KEYS_PATH_REGEX))
            .respond_with(ResponseTemplate::new(200).set_body_string(GET_KEY_ECDSA_BODY))
            .mount(&server)
            .await;
        // Sign endpoint should never be hit — the length check fires first.

        let engine = engine_for(&server);
        let id = KeyPairId::generate();
        let _ = engine.get_public_key(&id).await.unwrap();
        let err = engine.sign(&id, &[0x5a_u8; 31]).await.unwrap_err();
        match err {
            SigningEngineError::InvalidInputLength { expected, actual } => {
                assert_eq!(expected, 32);
                assert_eq!(actual, 31);
            }
            other => panic!("expected InvalidInputLength, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn sign_ecdsa_p256_rejects_64_byte_input() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(KEYS_PATH_REGEX))
            .respond_with(ResponseTemplate::new(200).set_body_string(GET_KEY_ECDSA_BODY))
            .mount(&server)
            .await;

        let engine = engine_for(&server);
        let id = KeyPairId::generate();
        let _ = engine.get_public_key(&id).await.unwrap();
        let err = engine.sign(&id, &[0x3c_u8; 64]).await.unwrap_err();
        assert!(matches!(
            err,
            SigningEngineError::InvalidInputLength {
                expected: 32,
                actual: 64,
            }
        ));
    }

    #[tokio::test]
    async fn sign_unknown_id_via_get_returns_key_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(KEYS_PATH_REGEX))
            .respond_with(ResponseTemplate::new(404).set_body_string(GET_KEY_NOT_FOUND_BODY))
            .mount(&server)
            .await;

        let engine = engine_for(&server);
        let id = KeyPairId::generate();
        let err = engine.sign(&id, b"any").await.unwrap_err();
        match err {
            SigningEngineError::KeyNotFound(returned) => assert_eq!(returned, id),
            other => panic!("expected KeyNotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn sign_400_signing_key_not_found_returns_key_not_found() {
        // Cache is warm with Ed25519 (vault deletes the key behind our back),
        // sign POST returns 400 with the discriminating body string.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(KEYS_PATH_REGEX))
            .respond_with(ResponseTemplate::new(200).set_body_string(GET_KEY_ED25519_BODY))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path_regex(SIGN_PATH_REGEX))
            .respond_with(ResponseTemplate::new(400).set_body_string(SIGN_KEY_NOT_FOUND_BODY))
            .mount(&server)
            .await;

        let engine = engine_for(&server);
        let id = KeyPairId::generate();
        let _ = engine.get_public_key(&id).await.unwrap();
        let err = engine.sign(&id, b"any").await.unwrap_err();
        match err {
            SigningEngineError::KeyNotFound(returned) => assert_eq!(returned, id),
            other => panic!("expected KeyNotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn sign_unauthorized_returns_backend() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(KEYS_PATH_REGEX))
            .respond_with(ResponseTemplate::new(200).set_body_string(GET_KEY_ED25519_BODY))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path_regex(SIGN_PATH_REGEX))
            .respond_with(ResponseTemplate::new(403).set_body_string(SIGN_UNAUTHORIZED_BODY))
            .mount(&server)
            .await;

        let engine = engine_for(&server);
        let id = KeyPairId::generate();
        let _ = engine.get_public_key(&id).await.unwrap();
        let err = engine.sign(&id, b"any").await.unwrap_err();
        assert!(matches!(err, SigningEngineError::Backend(_)));
    }

    #[tokio::test]
    async fn sign_caches_algorithm_after_first_lookup() {
        let server = MockServer::start().await;
        // Exactly one GET should fire across two signs — the second reuses
        // the cached algorithm. `MockServer::drop` panics on expectation
        // mismatch, so the assertion is implicit.
        Mock::given(method("GET"))
            .and(path_regex(KEYS_PATH_REGEX))
            .respond_with(ResponseTemplate::new(200).set_body_string(GET_KEY_ED25519_BODY))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path_regex(SIGN_PATH_REGEX))
            .respond_with(ResponseTemplate::new(200).set_body_string(SIGN_ED25519_BODY))
            .expect(2)
            .mount(&server)
            .await;

        let engine = engine_for(&server);
        let id = KeyPairId::generate();
        let _ = engine.sign(&id, b"first").await.unwrap();
        let _ = engine.sign(&id, b"second").await.unwrap();
    }

    #[tokio::test]
    async fn delete_keypair_succeeds_with_known_key() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(KEYS_CONFIG_PATH_REGEX))
            .respond_with(ResponseTemplate::new(200).set_body_string(CONFIG_DELETION_ALLOWED_BODY))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path_regex(KEYS_PATH_REGEX))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;

        let engine = engine_for(&server);
        engine.delete_keypair(&KeyPairId::generate()).await.unwrap();
    }

    #[tokio::test]
    async fn delete_keypair_idempotent_when_key_already_gone() {
        // Both endpoints report the key is missing — both 400s are swallowed.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(KEYS_CONFIG_PATH_REGEX))
            .respond_with(ResponseTemplate::new(400).set_body_string(CONFIG_KEY_NOT_FOUND_BODY))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path_regex(KEYS_PATH_REGEX))
            .respond_with(ResponseTemplate::new(400).set_body_string(DELETE_KEY_NOT_FOUND_BODY))
            .mount(&server)
            .await;

        let engine = engine_for(&server);
        engine.delete_keypair(&KeyPairId::generate()).await.unwrap();
    }

    #[tokio::test]
    async fn delete_keypair_idempotent_when_only_delete_reports_key_gone() {
        // Race scenario: config succeeds, then the key is removed before DELETE.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(KEYS_CONFIG_PATH_REGEX))
            .respond_with(ResponseTemplate::new(200).set_body_string(CONFIG_DELETION_ALLOWED_BODY))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path_regex(KEYS_PATH_REGEX))
            .respond_with(ResponseTemplate::new(400).set_body_string(DELETE_KEY_NOT_FOUND_BODY))
            .mount(&server)
            .await;

        let engine = engine_for(&server);
        engine.delete_keypair(&KeyPairId::generate()).await.unwrap();
    }

    #[tokio::test]
    async fn delete_keypair_returns_backend_on_unrelated_config_400() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(KEYS_CONFIG_PATH_REGEX))
            .respond_with(
                ResponseTemplate::new(400).set_body_string(r#"{"errors":["some other problem"]}"#),
            )
            .mount(&server)
            .await;

        let engine = engine_for(&server);
        let err = engine
            .delete_keypair(&KeyPairId::generate())
            .await
            .unwrap_err();
        assert!(matches!(err, SigningEngineError::Backend(_)));
    }

    #[tokio::test]
    async fn delete_keypair_returns_backend_on_unrelated_delete_400() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(KEYS_CONFIG_PATH_REGEX))
            .respond_with(ResponseTemplate::new(200).set_body_string(CONFIG_DELETION_ALLOWED_BODY))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path_regex(KEYS_PATH_REGEX))
            .respond_with(
                ResponseTemplate::new(400).set_body_string(r#"{"errors":["unexpected"]}"#),
            )
            .mount(&server)
            .await;

        let engine = engine_for(&server);
        let err = engine
            .delete_keypair(&KeyPairId::generate())
            .await
            .unwrap_err();
        assert!(matches!(err, SigningEngineError::Backend(_)));
    }

    #[tokio::test]
    async fn delete_keypair_returns_backend_on_unauthorized() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(KEYS_CONFIG_PATH_REGEX))
            .respond_with(ResponseTemplate::new(403).set_body_string(SIGN_UNAUTHORIZED_BODY))
            .mount(&server)
            .await;

        let engine = engine_for(&server);
        let err = engine
            .delete_keypair(&KeyPairId::generate())
            .await
            .unwrap_err();
        assert!(matches!(err, SigningEngineError::Backend(_)));
    }

    #[tokio::test]
    async fn delete_keypair_evicts_from_algorithm_cache() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(KEYS_PATH_REGEX))
            .respond_with(ResponseTemplate::new(200).set_body_string(GET_KEY_ED25519_BODY))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path_regex(KEYS_CONFIG_PATH_REGEX))
            .respond_with(ResponseTemplate::new(200).set_body_string(CONFIG_DELETION_ALLOWED_BODY))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path_regex(KEYS_PATH_REGEX))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let engine = engine_for(&server);
        let id = KeyPairId::generate();
        let _ = engine.get_public_key(&id).await.unwrap();
        assert!(engine.cache_get(&id).is_some(), "cache should be warmed");
        engine.delete_keypair(&id).await.unwrap();
        assert!(
            engine.cache_get(&id).is_none(),
            "cache should be evicted after delete_keypair"
        );
    }

    #[tokio::test]
    async fn generate_keypair_warms_algorithm_cache() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(KEYS_PATH_REGEX))
            .respond_with(ResponseTemplate::new(200).set_body_string(CREATE_KEY_ED25519_BODY))
            .expect(1)
            .mount(&server)
            .await;
        // generate_keypair already triggered one GET; sign should hit cache.
        Mock::given(method("GET"))
            .and(path_regex(KEYS_PATH_REGEX))
            .respond_with(ResponseTemplate::new(200).set_body_string(GET_KEY_ED25519_BODY))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path_regex(SIGN_PATH_REGEX))
            .respond_with(ResponseTemplate::new(200).set_body_string(SIGN_ED25519_BODY))
            .expect(1)
            .mount(&server)
            .await;

        let engine = engine_for(&server);
        let pair = engine.generate_keypair(KeyRole::Authorized).await.unwrap();
        let _ = engine.sign(&pair.id, b"hello swiyu").await.unwrap();
    }
}
