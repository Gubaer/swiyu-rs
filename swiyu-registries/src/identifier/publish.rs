use tracing::Instrument;

use crate::common::{AccessToken, RegistryError};
use crate::identifier::IdentifierRegistryClient;

impl IdentifierRegistryClient {
    /// PUTs `entry` (a single DIDLog line, no trailing newline) to
    /// the registry under the previously allocated `identifier`.
    ///
    /// Idempotent. Per HTTP semantics and the SWIYU registry
    /// contract, retrying with the same bytes is safe; callers
    /// driving an at-least-once retry loop can call this until it
    /// returns `Ok` (or a non-retryable error) without server-side
    /// duplication.
    ///
    /// `entry` is sent verbatim with `Content-Type:
    /// application/jsonl+json`. The caller owns the line format —
    /// no newline is appended.
    ///
    /// Sends `Authorization: Bearer <token>` from the supplied
    /// [`AccessToken`](crate::common::AccessToken).
    ///
    /// Errors:
    /// - [`RegistryError::Transport`] for network failures before a
    ///   response is received.
    /// - [`RegistryError::HttpStatus`] for any non-2xx response;
    ///   4xx is non-retryable, 429 and 5xx are retryable per
    ///   [`RegistryError::is_retryable`].
    pub async fn publish_log_entry(
        &self,
        token: &AccessToken,
        partner_id: &str,
        identifier: &str,
        entry: &str,
    ) -> Result<(), RegistryError> {
        let span = tracing::debug_span!(
            "publish_log_entry",
            partner_id = partner_id,
            identifier = identifier,
            status = tracing::field::Empty,
        );
        async move {
            let endpoint = format!(
                "{}/api/v1/identifier/business-entities/{}/identifier-entries/{}",
                self.base_url().trim_end_matches('/'),
                partner_id,
                identifier,
            );

            let response = self
                .http
                .put(&endpoint)
                .bearer_auth(token.as_str())
                .header("Content-Type", "application/jsonl+json")
                .body(entry.to_string())
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

            Ok(())
        }
        .instrument(span)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const PARTNER: &str = "4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef";
    const IDENTIFIER: &str = "fce949f2-32c4-4915-8b60-0ee2f705231d";
    const ENDPOINT: &str = "/api/v1/identifier/business-entities/4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef/identifier-entries/fce949f2-32c4-4915-8b60-0ee2f705231d";
    const ENTRY: &str =
        r#"["1-abc","2026-05-04T00:00:00Z",{"method":"did:tdw:0.3"},{"value":"did:tdw:abc"}]"#;

    fn client(server: &MockServer) -> IdentifierRegistryClient {
        IdentifierRegistryClient::with_http(server.uri(), reqwest::Client::new())
    }

    fn token() -> AccessToken {
        AccessToken::new("test-token".to_string())
    }

    #[tokio::test]
    async fn happy_path_sends_put_with_body_and_headers() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path(ENDPOINT))
            .and(header("Authorization", "Bearer test-token"))
            .and(header("Content-Type", "application/jsonl+json"))
            .and(body_string(ENTRY))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;

        client(&server)
            .publish_log_entry(&token(), PARTNER, IDENTIFIER, ENTRY)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn client_error_is_terminal() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path(ENDPOINT))
            .respond_with(ResponseTemplate::new(400).set_body_string("bad entry"))
            .mount(&server)
            .await;

        let err = client(&server)
            .publish_log_entry(&token(), PARTNER, IDENTIFIER, ENTRY)
            .await
            .unwrap_err();
        match &err {
            RegistryError::HttpStatus { status, body } => {
                assert_eq!(*status, 400);
                assert_eq!(body, "bad entry");
            }
            other => panic!("expected HttpStatus(400), got {other:?}"),
        }
        assert!(!err.is_retryable());
    }

    #[tokio::test]
    async fn server_error_is_retryable() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path(ENDPOINT))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let err = client(&server)
            .publish_log_entry(&token(), PARTNER, IDENTIFIER, ENTRY)
            .await
            .unwrap_err();
        assert!(matches!(err, RegistryError::HttpStatus { status: 503, .. }));
        assert!(err.is_retryable());
    }
}
