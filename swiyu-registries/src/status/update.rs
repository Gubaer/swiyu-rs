use tracing::Instrument;

use crate::common::RegistryError;
use crate::status::StatusRegistryClient;

impl StatusRegistryClient {
    /// PUTs `status_list_jwt` (a `statuslist+jwt` token, no
    /// surrounding envelope) to the registry under the previously
    /// allocated `entry_id`.
    ///
    /// Idempotent. Per HTTP semantics and the SWIYU registry
    /// contract, retrying with the same bytes is safe; callers
    /// driving an at-least-once retry loop can call this until it
    /// returns `Ok` (or a non-retryable error) without server-side
    /// duplication.
    ///
    /// `status_list_jwt` is sent verbatim with `Content-Type:
    /// application/statuslist+jwt`. The caller owns producing and
    /// signing the JWT; this client treats it as opaque bytes.
    ///
    /// Sends `Authorization: Bearer <token>` from the
    /// [`AccessToken`](crate::common::AccessToken) supplied at
    /// construction.
    ///
    /// Errors:
    /// - [`RegistryError::Transport`] for network failures before a
    ///   response is received.
    /// - [`RegistryError::HttpStatus`] for any non-2xx response;
    ///   401/403/404 are non-retryable, 429 and 5xx are retryable per
    ///   [`RegistryError::is_retryable`].
    pub async fn update_status_list_entry(
        &self,
        partner_id: &str,
        entry_id: &str,
        status_list_jwt: &str,
    ) -> Result<(), RegistryError> {
        let span = tracing::debug_span!(
            "update_status_list_entry",
            partner_id = partner_id,
            entry_id = entry_id,
            status = tracing::field::Empty,
        );
        async move {
            let endpoint = format!(
                "{}/api/v1/status/business-entities/{}/status-list-entries/{}",
                self.base_url().trim_end_matches('/'),
                partner_id,
                entry_id,
            );

            let response = self
                .http
                .put(&endpoint)
                .bearer_auth(self.access_token.as_str())
                .header("Content-Type", "application/statuslist+jwt")
                .body(status_list_jwt.to_string())
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
    use crate::common::AccessToken;
    use wiremock::matchers::{body_string, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const PARTNER: &str = "8432e1f3-8119-4fb9-a879-190ab2cb9deb";
    const ENTRY_ID: &str = "18fa7c77-9dd1-4e20-a147-fb1bec146085";
    const ENDPOINT: &str = "/api/v1/status/business-entities/8432e1f3-8119-4fb9-a879-190ab2cb9deb/status-list-entries/18fa7c77-9dd1-4e20-a147-fb1bec146085";
    const JWT: &str = "eyJhbGciOiJFUzI1NiJ9.eyJzdGF0dXNfbGlzdCI6e319.signature";

    fn client(server: &MockServer) -> StatusRegistryClient {
        StatusRegistryClient::with_http(
            server.uri(),
            AccessToken::new("test-token".to_string()),
            reqwest::Client::new(),
        )
    }

    #[tokio::test]
    async fn happy_path_sends_put_with_body_and_headers() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path(ENDPOINT))
            .and(header("Authorization", "Bearer test-token"))
            .and(header("Content-Type", "application/statuslist+jwt"))
            .and(body_string(JWT))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        client(&server)
            .update_status_list_entry(PARTNER, ENTRY_ID, JWT)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn not_found_is_terminal() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path(ENDPOINT))
            .respond_with(ResponseTemplate::new(404).set_body_string("unknown entry"))
            .mount(&server)
            .await;

        let err = client(&server)
            .update_status_list_entry(PARTNER, ENTRY_ID, JWT)
            .await
            .unwrap_err();
        match &err {
            RegistryError::HttpStatus { status, body } => {
                assert_eq!(*status, 404);
                assert_eq!(body, "unknown entry");
            }
            other => panic!("expected HttpStatus(404), got {other:?}"),
        }
        assert!(!err.is_retryable());
    }

    #[tokio::test]
    async fn forbidden_is_terminal() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path(ENDPOINT))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;

        let err = client(&server)
            .update_status_list_entry(PARTNER, ENTRY_ID, JWT)
            .await
            .unwrap_err();
        assert!(matches!(err, RegistryError::HttpStatus { status: 403, .. }));
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
            .update_status_list_entry(PARTNER, ENTRY_ID, JWT)
            .await
            .unwrap_err();
        assert!(matches!(err, RegistryError::HttpStatus { status: 503, .. }));
        assert!(err.is_retryable());
    }
}
