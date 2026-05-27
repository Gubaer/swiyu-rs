use tracing::Instrument;

use swiyu_core::did::DID;

use crate::common::RegistryError;
use crate::trust::TrustRegistryClient;

impl TrustRegistryClient {
    /// Fetches the trust statements the registry holds for `did`, as
    /// the raw JWT strings. They are returned unparsed because callers
    /// need the original string: to print it as-is, and to verify the
    /// signature over its exact signing input.
    ///
    /// A 404 means the registry knows of no statements for the
    /// identifier; this is reported as an empty `Vec`, not an error,
    /// so callers need not special-case the status code.
    ///
    /// Idempotent and **unauthenticated**: any verifier may read this
    /// endpoint, and the client deliberately sends no `Authorization`
    /// header. Safe to retry.
    ///
    /// Errors:
    /// - [`RegistryError::Transport`] for network failures or
    ///   body-read failures.
    /// - [`RegistryError::HttpStatus`] for any non-2xx response other
    ///   than 404; 429 and 5xx are retryable per
    ///   [`RegistryError::is_retryable`].
    /// - [`RegistryError::Decode`] when the body is not a JSON array
    ///   of strings.
    pub async fn fetch_trust_statements(&self, did: &DID) -> Result<Vec<String>, RegistryError> {
        let url = build_endpoint(&self.base_url, did);
        let span = tracing::debug_span!(
            "fetch_trust_statements",
            url = url,
            status = tracing::field::Empty,
        );
        async move {
            let response = self
                .http
                .get(&url)
                .send()
                .await
                .map_err(RegistryError::Transport)?;

            let status = response.status();
            tracing::Span::current().record("status", status.as_u16());

            if status.as_u16() == 404 {
                return Ok(Vec::new());
            }
            if !status.is_success() {
                let body = response.text().await.unwrap_or_default();
                return Err(RegistryError::HttpStatus {
                    status: status.as_u16(),
                    body,
                });
            }

            let body = response.text().await.map_err(RegistryError::Transport)?;
            serde_json::from_str::<Vec<String>>(&body).map_err(|_| {
                RegistryError::Decode(
                    "trust registry response is not a JSON array of JWT strings".to_string(),
                )
            })
        }
        .instrument(span)
        .await
    }
}

fn build_endpoint(base_url: &str, did: &DID) -> String {
    let trimmed = base_url.trim_end_matches('/');
    format!(
        "{trimmed}/api/v1/truststatements/identity/{}",
        did.url_path_segment()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn client(server: &MockServer) -> TrustRegistryClient {
        TrustRegistryClient::with_http(server.uri(), reqwest::Client::new())
    }

    fn test_did() -> DID {
        "did:tdw:Q123:host.example.com:api:v1:did:abc"
            .parse()
            .unwrap()
    }

    const ENDPOINT: &str = "/api/v1/truststatements/identity/did%3Atdw%3AQ123%3Ahost.example.com%3Aapi%3Av1%3Adid%3Aabc";

    #[test]
    fn build_endpoint_percent_encodes_did() {
        let url = build_endpoint("https://trust-reg.example.com/", &test_did());
        assert_eq!(url, format!("https://trust-reg.example.com{ENDPOINT}"));
    }

    #[test]
    fn build_endpoint_handles_trailing_slash() {
        let did: DID = "did:tdw:abc:example.com".parse().unwrap();
        let with_slash = build_endpoint("https://x/", &did);
        let without = build_endpoint("https://x", &did);
        assert_eq!(with_slash, without);
    }

    #[tokio::test]
    async fn happy_path_returns_jwt_array() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(ENDPOINT))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"["jwt-one","jwt-two"]"#))
            .expect(1)
            .mount(&server)
            .await;

        let statements = client(&server)
            .fetch_trust_statements(&test_did())
            .await
            .unwrap();
        assert_eq!(statements, vec!["jwt-one", "jwt-two"]);
    }

    #[tokio::test]
    async fn not_found_yields_empty_vec() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(ENDPOINT))
            .respond_with(ResponseTemplate::new(404).set_body_string("unknown identifier"))
            .mount(&server)
            .await;

        let statements = client(&server)
            .fetch_trust_statements(&test_did())
            .await
            .unwrap();
        assert!(statements.is_empty());
    }

    #[tokio::test]
    async fn non_array_body_is_decode_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(ENDPOINT))
            .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
            .mount(&server)
            .await;

        let err = client(&server)
            .fetch_trust_statements(&test_did())
            .await
            .unwrap_err();
        assert!(matches!(err, RegistryError::Decode(_)));
        assert!(!err.is_retryable());
    }

    #[tokio::test]
    async fn server_error_yields_http_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(ENDPOINT))
            .respond_with(ResponseTemplate::new(503).set_body_string("upstream down"))
            .mount(&server)
            .await;

        let err = client(&server)
            .fetch_trust_statements(&test_did())
            .await
            .unwrap_err();
        match &err {
            RegistryError::HttpStatus { status, .. } => assert_eq!(*status, 503),
            other => panic!("expected HttpStatus(503), got {other:?}"),
        }
        assert!(err.is_retryable());
    }

    #[tokio::test]
    async fn no_authorization_header_sent() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(ENDPOINT))
            .respond_with(ResponseTemplate::new(200).set_body_string("[]"))
            .mount(&server)
            .await;

        client(&server)
            .fetch_trust_statements(&test_did())
            .await
            .unwrap();

        let received = server
            .received_requests()
            .await
            .expect("request recording enabled");
        assert_eq!(received.len(), 1, "expected exactly one request");
        assert!(
            received[0].headers.get("authorization").is_none(),
            "fetch_trust_statements must not send an Authorization header",
        );
    }
}
