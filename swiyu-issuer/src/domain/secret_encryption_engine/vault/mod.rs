mod envelope;

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use reqwest::{Client, StatusCode, Url};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::json;

use super::{Ciphertext, SecretEncryptionEngine, SecretEncryptionError};
use envelope::Envelope;

const VAULT_TOKEN_HEADER: &str = "X-Vault-Token";
const VAULT_CIPHERTEXT_PREFIX: &str = "vault:v";
// Body substrings Vault's Transit endpoint returns (HTTP 400) for the
// failure modes we map to typed variants. Substring match is what Vault
// gives us; the integration tests guard against silent wording changes.
const VAULT_ENCRYPTION_KEY_NOT_FOUND: &str = "encryption key not found";
const VAULT_MESSAGE_AUTHENTICATION_FAILED: &str = "cipher: message authentication failed";

/// Configuration for the Vault Transit secret-encryption backend.
///
/// Populated from environment variables in the binary; see `.env.example`
/// for the variables that map to each field. Shares `VAULT_ADDR`,
/// `VAULT_TOKEN`, and `VAULT_TRANSIT_PATH` with
/// [`VaultSigningEngine`][crate::domain::signing_engine::VaultSigningEngine] —
/// operators wanting to isolate signing keys from secret-encryption keys
/// must configure a different Vault mount point out of band.
pub struct VaultSecretEncryptionEngineConfig {
    pub address: Url,
    pub token: SecretString,
    pub transit_path: String,
    pub request_timeout: Duration,
}

impl VaultSecretEncryptionEngineConfig {
    pub const DEFAULT_TRANSIT_PATH: &'static str = "transit";
    pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
}

/// Middle-maturity [`SecretEncryptionEngine`] backed by Vault Transit.
///
/// Symmetric keys never leave Vault; encryption and decryption happen
/// server-side. The engine itself is stateless beyond the HTTP client
/// and never provisions keys — operators create per-tenant Transit keys
/// out of band. A request against a missing key surfaces as
/// [`KeyNotFound`][super::SecretEncryptionError::KeyNotFound] at first use.
pub struct VaultSecretEncryptionEngine {
    client: Client,
    address: Url,
    token: SecretString,
    transit_path: String,
}

impl VaultSecretEncryptionEngine {
    pub fn new(config: VaultSecretEncryptionEngineConfig) -> Self {
        // reqwest::ClientBuilder::build only fails on TLS init errors; we
        // configure no custom CA, no proxy, no resolver, so failure is
        // unreachable for this code path.
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

    fn encrypt_url(&self, key_name: &str) -> Result<Url, SecretEncryptionError> {
        self.transit_url(&format!("encrypt/{key_name}"))
    }

    fn decrypt_url(&self, key_name: &str) -> Result<Url, SecretEncryptionError> {
        self.transit_url(&format!("decrypt/{key_name}"))
    }

    fn transit_url(&self, suffix: &str) -> Result<Url, SecretEncryptionError> {
        // `Url::join` re-bases relative paths and would silently drop a
        // configured base prefix (e.g. `http://host/proxy`) when the joined
        // string starts with `/`. Build the full string explicitly.
        let base = self.address.as_str().trim_end_matches('/');
        let mount = self.transit_path.trim_matches('/');
        let url_str = format!("{base}/v1/{mount}/{suffix}");
        Url::parse(&url_str)
            .map_err(|e| SecretEncryptionError::Backend(format!("vault url parse: {e}").into()))
    }
}

impl SecretEncryptionEngine for VaultSecretEncryptionEngine {
    async fn encrypt(
        &self,
        key_name: &str,
        plaintext: &[u8],
    ) -> Result<Ciphertext, SecretEncryptionError> {
        let url = self.encrypt_url(key_name)?;
        let body = json!({ "plaintext": BASE64_STANDARD.encode(plaintext) });
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
            return Err(map_error(status, &body_text, key_name, Op::Encrypt));
        }
        let response_body: EncryptResponse = response.json().await.map_err(reqwest_to_backend)?;
        let (key_version, vault_payload) = parse_vault_ciphertext(&response_body.data.ciphertext)?;
        let env = Envelope {
            key_name,
            key_version,
            vault_payload: &vault_payload,
        };
        let bytes = env.encode()?;
        Ok(Ciphertext::from(bytes))
    }

    async fn decrypt(
        &self,
        key_name: &str,
        ciphertext: &Ciphertext,
    ) -> Result<Vec<u8>, SecretEncryptionError> {
        let env = Envelope::decode(ciphertext.as_bytes())?;
        if env.key_name != key_name {
            return Err(SecretEncryptionError::KeyNameMismatch {
                envelope: env.key_name.to_string(),
                argument: key_name.to_string(),
            });
        }
        let vault_ciphertext = format!(
            "{VAULT_CIPHERTEXT_PREFIX}{}:{}",
            env.key_version,
            BASE64_STANDARD.encode(env.vault_payload),
        );
        let url = self.decrypt_url(key_name)?;
        let body = json!({ "ciphertext": vault_ciphertext });
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
            return Err(map_error(status, &body_text, key_name, Op::Decrypt));
        }
        let response_body: DecryptResponse = response.json().await.map_err(reqwest_to_backend)?;
        BASE64_STANDARD
            .decode(&response_body.data.plaintext)
            .map_err(|e| {
                SecretEncryptionError::Backend(format!("vault plaintext base64: {e}").into())
            })
    }
}

#[derive(Deserialize)]
struct EncryptResponse {
    data: EncryptData,
}

#[derive(Deserialize)]
struct EncryptData {
    ciphertext: String,
}

#[derive(Deserialize)]
struct DecryptResponse {
    data: DecryptData,
}

#[derive(Deserialize)]
struct DecryptData {
    plaintext: String,
}

#[derive(Debug, Clone, Copy)]
enum Op {
    Encrypt,
    Decrypt,
}

// Status-to-error mapping for Vault Transit failures. `KeyNotFound` is
// recognised on both endpoints; `Tampered` only on decrypt (encrypt has
// no authentication-tag failure mode). Anything else falls through to
// `Backend` with the verbatim body for debugging.
fn map_error(status: StatusCode, body: &str, key_name: &str, op: Op) -> SecretEncryptionError {
    if status == StatusCode::BAD_REQUEST {
        if body.contains(VAULT_ENCRYPTION_KEY_NOT_FOUND) {
            return SecretEncryptionError::KeyNotFound(key_name.to_string());
        }
        if matches!(op, Op::Decrypt) && body.contains(VAULT_MESSAGE_AUTHENTICATION_FAILED) {
            return SecretEncryptionError::Tampered;
        }
    }
    SecretEncryptionError::Backend(format!("vault {status}: {body}").into())
}

fn reqwest_to_backend(error: reqwest::Error) -> SecretEncryptionError {
    SecretEncryptionError::Backend(Box::new(error))
}

// Vault Transit returns standard base64 (with padding) inside the
// `vault:v<N>:<base64>` envelope; the integration tests guard against
// silent backend wording changes.
fn parse_vault_ciphertext(raw: &str) -> Result<(u32, Vec<u8>), SecretEncryptionError> {
    let after_prefix = raw.strip_prefix(VAULT_CIPHERTEXT_PREFIX).ok_or_else(|| {
        SecretEncryptionError::Backend(
            format!("vault ciphertext missing `{VAULT_CIPHERTEXT_PREFIX}` prefix: {raw}").into(),
        )
    })?;
    let (version_str, payload_b64) = after_prefix.split_once(':').ok_or_else(|| {
        SecretEncryptionError::Backend(
            format!("vault ciphertext missing version/payload separator: {raw}").into(),
        )
    })?;
    let key_version = version_str.parse::<u32>().map_err(|e| {
        SecretEncryptionError::Backend(format!("vault ciphertext version parse: {e}").into())
    })?;
    let payload = BASE64_STANDARD.decode(payload_b64).map_err(|e| {
        SecretEncryptionError::Backend(format!("vault ciphertext payload base64: {e}").into())
    })?;
    Ok((key_version, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    use wiremock::matchers::{header, method, path_regex};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    const ENCRYPT_PATH_REGEX: &str = r"^/v1/transit/encrypt/[^/]+$";
    const DECRYPT_PATH_REGEX: &str = r"^/v1/transit/decrypt/[^/]+$";

    fn engine_for(server: &MockServer) -> VaultSecretEncryptionEngine {
        VaultSecretEncryptionEngine::new(VaultSecretEncryptionEngineConfig {
            address: Url::parse(&server.uri()).unwrap(),
            token: SecretString::from("dev-only-root"),
            transit_path: VaultSecretEncryptionEngineConfig::DEFAULT_TRANSIT_PATH.to_string(),
            request_timeout: VaultSecretEncryptionEngineConfig::DEFAULT_REQUEST_TIMEOUT,
        })
    }

    fn vault_ciphertext_string(version: u32, payload: &[u8]) -> String {
        format!(
            "{VAULT_CIPHERTEXT_PREFIX}{version}:{}",
            BASE64_STANDARD.encode(payload)
        )
    }

    #[test]
    fn parse_vault_ciphertext_round_trips_version_and_payload() {
        let payload = [0x11_u8, 0x22, 0x33, 0x44];
        let raw = vault_ciphertext_string(3, &payload);
        let (version, decoded) = parse_vault_ciphertext(&raw).unwrap();
        assert_eq!(version, 3);
        assert_eq!(decoded, payload);
    }

    #[test]
    fn parse_vault_ciphertext_rejects_missing_prefix() {
        let err = parse_vault_ciphertext("not-a-vault-ciphertext").unwrap_err();
        assert!(matches!(err, SecretEncryptionError::Backend(_)));
    }

    #[test]
    fn parse_vault_ciphertext_rejects_missing_separator() {
        let err = parse_vault_ciphertext("vault:v1payload").unwrap_err();
        assert!(matches!(err, SecretEncryptionError::Backend(_)));
    }

    #[test]
    fn parse_vault_ciphertext_rejects_non_numeric_version() {
        let err = parse_vault_ciphertext("vault:vX:abcdef==").unwrap_err();
        assert!(matches!(err, SecretEncryptionError::Backend(_)));
    }

    #[test]
    fn map_error_encrypt_400_key_not_found_returns_key_not_found() {
        let err = map_error(
            StatusCode::BAD_REQUEST,
            r#"{"errors":["encryption key not found"]}"#,
            "my-key",
            Op::Encrypt,
        );
        match err {
            SecretEncryptionError::KeyNotFound(name) => assert_eq!(name, "my-key"),
            other => panic!("expected KeyNotFound, got {other:?}"),
        }
    }

    #[test]
    fn map_error_decrypt_400_key_not_found_returns_key_not_found() {
        let err = map_error(
            StatusCode::BAD_REQUEST,
            r#"{"errors":["encryption key not found"]}"#,
            "my-key",
            Op::Decrypt,
        );
        assert!(matches!(err, SecretEncryptionError::KeyNotFound(_)));
    }

    #[test]
    fn map_error_decrypt_400_auth_failed_returns_tampered() {
        let err = map_error(
            StatusCode::BAD_REQUEST,
            r#"{"errors":["cipher: message authentication failed"]}"#,
            "my-key",
            Op::Decrypt,
        );
        assert!(matches!(err, SecretEncryptionError::Tampered));
    }

    #[test]
    fn map_error_encrypt_400_auth_failed_returns_backend() {
        // Encrypt has no auth-failed mode; the substring should not be
        // recognised there. Defensive: ensure we don't accidentally map it.
        let err = map_error(
            StatusCode::BAD_REQUEST,
            r#"{"errors":["cipher: message authentication failed"]}"#,
            "my-key",
            Op::Encrypt,
        );
        assert!(matches!(err, SecretEncryptionError::Backend(_)));
    }

    #[test]
    fn map_error_5xx_returns_backend() {
        let err = map_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "boom",
            "my-key",
            Op::Encrypt,
        );
        assert!(matches!(err, SecretEncryptionError::Backend(_)));
    }

    #[test]
    fn map_error_decrypt_400_unrelated_body_returns_backend() {
        let err = map_error(
            StatusCode::BAD_REQUEST,
            r#"{"errors":["something else entirely"]}"#,
            "my-key",
            Op::Decrypt,
        );
        assert!(matches!(err, SecretEncryptionError::Backend(_)));
    }

    #[tokio::test]
    async fn encrypt_emits_format_0x02_envelope_carrying_parsed_version_and_payload() {
        let server = MockServer::start().await;
        let payload = [0xde_u8, 0xad, 0xbe, 0xef];
        let response_body = json!({
            "data": { "ciphertext": vault_ciphertext_string(2, &payload) }
        })
        .to_string();
        Mock::given(method("POST"))
            .and(path_regex(ENCRYPT_PATH_REGEX))
            .and(header(VAULT_TOKEN_HEADER, "dev-only-root"))
            .respond_with(ResponseTemplate::new(200).set_body_string(response_body))
            .mount(&server)
            .await;

        let engine = engine_for(&server);
        let ct = engine.encrypt("k-name", b"hello").await.unwrap();
        let env = Envelope::decode(ct.as_bytes()).unwrap();
        assert_eq!(env.key_name, "k-name");
        assert_eq!(env.key_version, 2);
        assert_eq!(env.vault_payload, &payload);
    }

    #[tokio::test]
    async fn encrypt_sends_base64_plaintext_in_request_body() {
        let server = MockServer::start().await;
        let payload = [0x01_u8, 0x02, 0x03];
        let response_body = json!({
            "data": { "ciphertext": vault_ciphertext_string(1, &payload) }
        })
        .to_string();
        Mock::given(method("POST"))
            .and(path_regex(ENCRYPT_PATH_REGEX))
            .and(verify_request_plaintext("aGVsbG8gc3dpeXU="))
            .respond_with(ResponseTemplate::new(200).set_body_string(response_body))
            .expect(1)
            .mount(&server)
            .await;

        let engine = engine_for(&server);
        let _ = engine.encrypt("k", b"hello swiyu").await.unwrap();
    }

    #[tokio::test]
    async fn encrypt_400_key_not_found_returns_key_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(ENCRYPT_PATH_REGEX))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_string(r#"{"errors":["encryption key not found"]}"#),
            )
            .mount(&server)
            .await;

        let engine = engine_for(&server);
        let err = engine.encrypt("missing", b"x").await.unwrap_err();
        match err {
            SecretEncryptionError::KeyNotFound(name) => assert_eq!(name, "missing"),
            other => panic!("expected KeyNotFound, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn decrypt_sends_reconstructed_vault_ciphertext_and_returns_plaintext() {
        let server = MockServer::start().await;
        let payload = [0x10_u8, 0x20, 0x30, 0x40];
        // Decrypt must send vault:v5:<base64(payload)> verbatim.
        let expected_ciphertext = vault_ciphertext_string(5, &payload);
        let response_body = json!({
            "data": { "plaintext": BASE64_STANDARD.encode(b"plain text out") }
        })
        .to_string();
        Mock::given(method("POST"))
            .and(path_regex(DECRYPT_PATH_REGEX))
            .and(verify_request_ciphertext(expected_ciphertext))
            .respond_with(ResponseTemplate::new(200).set_body_string(response_body))
            .expect(1)
            .mount(&server)
            .await;

        let engine = engine_for(&server);
        let env = Envelope {
            key_name: "k",
            key_version: 5,
            vault_payload: &payload,
        };
        let ct = Ciphertext::from(env.encode().unwrap());
        let pt = engine.decrypt("k", &ct).await.unwrap();
        assert_eq!(pt, b"plain text out");
    }

    #[tokio::test]
    async fn decrypt_400_auth_failed_returns_tampered() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(DECRYPT_PATH_REGEX))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_string(r#"{"errors":["cipher: message authentication failed"]}"#),
            )
            .mount(&server)
            .await;

        let engine = engine_for(&server);
        let env = Envelope {
            key_name: "k",
            key_version: 1,
            vault_payload: b"abc",
        };
        let ct = Ciphertext::from(env.encode().unwrap());
        let err = engine.decrypt("k", &ct).await.unwrap_err();
        assert!(matches!(err, SecretEncryptionError::Tampered));
    }

    #[tokio::test]
    async fn decrypt_rejects_key_name_mismatch_before_calling_vault() {
        let server = MockServer::start().await;
        // No mock is mounted on the decrypt endpoint — the mismatch must
        // be detected before any network call is made.
        let engine = engine_for(&server);
        let env = Envelope {
            key_name: "name-a",
            key_version: 1,
            vault_payload: b"x",
        };
        let ct = Ciphertext::from(env.encode().unwrap());
        let err = engine.decrypt("name-b", &ct).await.unwrap_err();
        match err {
            SecretEncryptionError::KeyNameMismatch { envelope, argument } => {
                assert_eq!(envelope, "name-a");
                assert_eq!(argument, "name-b");
            }
            other => panic!("expected KeyNameMismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn decrypt_rejects_dev_format_envelope_as_malformed() {
        // Cross-backend isolation: a 0x01-format envelope (produced by the
        // Dev backend) cannot be decrypted by the Vault backend. The check
        // happens before any network call.
        let server = MockServer::start().await;
        let engine = engine_for(&server);
        let key_name = "k";
        let mut bytes = vec![0x01_u8, key_name.len() as u8];
        bytes.extend_from_slice(key_name.as_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 12]); // dummy nonce
        bytes.extend_from_slice(&[0u8; 16]); // dummy ct+tag
        let ct = Ciphertext::from(bytes);
        let err = engine.decrypt(key_name, &ct).await.unwrap_err();
        assert!(matches!(err, SecretEncryptionError::MalformedCiphertext));
    }

    #[tokio::test]
    async fn encrypt_5xx_returns_backend() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(ENCRYPT_PATH_REGEX))
            .respond_with(ResponseTemplate::new(503).set_body_string("upstream down"))
            .mount(&server)
            .await;

        let engine = engine_for(&server);
        let err = engine.encrypt("k", b"x").await.unwrap_err();
        assert!(matches!(err, SecretEncryptionError::Backend(_)));
    }

    // wiremock body-matcher helpers: extract the JSON field, compare verbatim.

    fn verify_request_plaintext(expected_b64: &'static str) -> impl wiremock::Match {
        FieldEquals {
            field: "plaintext",
            expected: expected_b64.to_string(),
        }
    }

    fn verify_request_ciphertext(expected: String) -> impl wiremock::Match {
        FieldEquals {
            field: "ciphertext",
            expected,
        }
    }

    struct FieldEquals {
        field: &'static str,
        expected: String,
    }

    impl wiremock::Match for FieldEquals {
        fn matches(&self, request: &Request) -> bool {
            let body: serde_json::Value = match serde_json::from_slice(&request.body) {
                Ok(v) => v,
                Err(_) => return false,
            };
            body.get(self.field).and_then(|v| v.as_str()) == Some(self.expected.as_str())
        }
    }
}
