use tracing::Instrument;

use swiyu_core::did::DID;

use crate::common::RegistryError;
use crate::identifier::IdentifierRegistryClient;

impl IdentifierRegistryClient {
    /// Fetches the DIDLog from the resolver URL the DID itself
    /// encodes (via [`DID::log_url`]) and returns the body verbatim.
    ///
    /// We resolve through the DID rather than the configured
    /// `base_url` because the SWIYU integration registry serves the
    /// partner-write API and the public DID-log resolver from
    /// different hosts (`identifier-reg-api.*` vs `identifier-reg.*`).
    /// The DID method spec already encodes the resolver location in
    /// the DID, so the DID is the safest source of truth — and it
    /// matches what a third-party verifier would do, which has only
    /// the DID to work from.
    ///
    /// Idempotent and **unauthenticated**: this endpoint is what any
    /// DID verifier reads from, and the client deliberately does not
    /// send an `Authorization` header here. Safe to retry.
    ///
    /// Errors:
    /// - [`RegistryError::Transport`] for network failures or
    ///   body-read failures.
    /// - [`RegistryError::HttpStatus`] for any non-2xx response;
    ///   404 (unknown identifier) is non-retryable, 429 and 5xx are
    ///   retryable per [`RegistryError::is_retryable`].
    pub async fn fetch_log(&self, did: &DID) -> Result<String, RegistryError> {
        self.fetch_log_at_url(&did.log_url()).await
    }

    async fn fetch_log_at_url(&self, url: &str) -> Result<String, RegistryError> {
        let span = tracing::debug_span!("fetch_log", url = url, status = tracing::field::Empty,);
        async move {
            let response = self
                .http
                .get(url)
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
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const ENDPOINT: &str = "/api/v1/did/fce949f2-32c4-4915-8b60-0ee2f705231d/did.jsonl";

    fn client(server: &MockServer) -> IdentifierRegistryClient {
        IdentifierRegistryClient::with_http(server.uri(), reqwest::Client::new())
    }

    // The wiremock-driven tests target `fetch_log_at_url` directly
    // because `fetch_log(&DID)` builds an `https://` URL out of the
    // DID's encoded host, which wiremock 0.6 cannot serve. Coverage of
    // the DID → URL derivation lives with `DID::log_url` in
    // `swiyu-core`; coverage of the GET-side behaviour lives here.

    #[tokio::test]
    async fn happy_path_returns_body_verbatim() {
        let server = MockServer::start().await;
        let body = "did:tdw log line 1\ndid:tdw log line 2";
        Mock::given(method("GET"))
            .and(path(ENDPOINT))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .expect(1)
            .mount(&server)
            .await;

        let url = format!("{}{}", server.uri(), ENDPOINT);
        let result = client(&server).fetch_log_at_url(&url).await.unwrap();
        assert_eq!(result, body);
    }

    #[tokio::test]
    async fn not_found_yields_http_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(ENDPOINT))
            .respond_with(ResponseTemplate::new(404).set_body_string("unknown identifier"))
            .mount(&server)
            .await;

        let url = format!("{}{}", server.uri(), ENDPOINT);
        let err = client(&server).fetch_log_at_url(&url).await.unwrap_err();
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
            .and(path(ENDPOINT))
            .respond_with(ResponseTemplate::new(200).set_body_string(""))
            .mount(&server)
            .await;

        let url = format!("{}{}", server.uri(), ENDPOINT);
        client(&server).fetch_log_at_url(&url).await.unwrap();

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
