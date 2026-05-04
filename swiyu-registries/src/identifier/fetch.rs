use tracing::Instrument;

use crate::common::RegistryError;
use crate::identifier::IdentifierRegistryClient;

impl IdentifierRegistryClient {
    /// Fetches the DIDLog for `identifier` from the registry's
    /// public resolver path and returns the body verbatim.
    ///
    /// Idempotent and **unauthenticated**: this endpoint is what
    /// any DID verifier reads from, and the client deliberately
    /// does not send the `Authorization` header here even when an
    /// [`AccessToken`](crate::common::AccessToken) was supplied at
    /// construction. Safe to retry.
    ///
    /// The body is read into memory in full as a `String`. DIDLogs
    /// are kilobytes-scale in practice; streaming is out of scope
    /// for this crate.
    ///
    /// Errors:
    /// - [`RegistryError::Transport`] for network failures or
    ///   body-read failures.
    /// - [`RegistryError::HttpStatus`] for any non-2xx response;
    ///   404 (unknown identifier) is non-retryable, 429 and 5xx
    ///   are retryable per [`RegistryError::is_retryable`].
    pub async fn fetch_log(&self, identifier: &str) -> Result<String, RegistryError> {
        let span = tracing::debug_span!(
            "fetch_log",
            identifier = identifier,
            status = tracing::field::Empty,
        );
        async move {
            let endpoint = format!(
                "{}/api/v1/did/{}/did.jsonl",
                self.base_url().trim_end_matches('/'),
                identifier,
            );

            let response = self
                .http
                .get(&endpoint)
                .send()
                .await
                .map_err(RegistryError::Transport)?;

            let status = response.status();
            tracing::Span::current().record("status", status.as_u16());

            if !status.is_success() {
                let body = response.text().await.unwrap_or_default();
                return Err(RegistryError::HttpStatus {
                    status: status.as_u16(),
                    body,
                });
            }

            response.text().await.map_err(RegistryError::Transport)
        }
        .instrument(span)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::AccessToken;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const IDENTIFIER: &str = "fce949f2-32c4-4915-8b60-0ee2f705231d";

    fn endpoint() -> String {
        format!("/api/v1/did/{IDENTIFIER}/did.jsonl")
    }

    fn client(server: &MockServer) -> IdentifierRegistryClient {
        IdentifierRegistryClient::with_http(
            server.uri(),
            AccessToken::new("test-token".to_string()),
            reqwest::Client::new(),
        )
    }

    #[tokio::test]
    async fn happy_path_returns_body_verbatim() {
        let server = MockServer::start().await;
        let body = "did:tdw log line 1\ndid:tdw log line 2";
        Mock::given(method("GET"))
            .and(path(endpoint()))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .expect(1)
            .mount(&server)
            .await;

        let result = client(&server).fetch_log(IDENTIFIER).await.unwrap();
        assert_eq!(result, body);
    }

    #[tokio::test]
    async fn not_found_yields_http_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(endpoint()))
            .respond_with(ResponseTemplate::new(404).set_body_string("unknown identifier"))
            .mount(&server)
            .await;

        let err = client(&server).fetch_log(IDENTIFIER).await.unwrap_err();
        match &err {
            RegistryError::HttpStatus { status, body } => {
                assert_eq!(*status, 404);
                assert_eq!(body, "unknown identifier");
            }
            other => panic!("expected HttpStatus(404), got {other:?}"),
        }
        assert!(!err.is_retryable());
    }

    #[tokio::test]
    async fn no_authorization_header_sent() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(endpoint()))
            .respond_with(ResponseTemplate::new(200).set_body_string(""))
            .mount(&server)
            .await;

        client(&server).fetch_log(IDENTIFIER).await.unwrap();

        let received = server
            .received_requests()
            .await
            .expect("request recording enabled");
        assert_eq!(received.len(), 1, "expected exactly one request");
        assert!(
            received[0].headers.get("authorization").is_none(),
            "fetch_log must not send an Authorization header",
        );
    }
}
