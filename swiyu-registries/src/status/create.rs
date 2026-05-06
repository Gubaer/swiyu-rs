use tracing::Instrument;

use crate::common::RegistryError;
use crate::status::StatusRegistryClient;

/// Result of a successful status-list-entry creation.
///
/// `id` is the entry UUID returned by the registry; it is used as
/// the path segment for subsequent
/// [`update_status_list_entry`](StatusRegistryClient::update_status_list_entry)
/// calls. `registry_url` is the public URL where the published
/// status-list JWT will be served — a verifier dereferences it to
/// fetch the JWT before decoding it via
/// [`swiyu_core::statuslist::StatusList`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusListEntry {
    pub id: String,
    pub registry_url: String,
}

impl StatusRegistryClient {
    /// Allocates a new status-list entry under `partner_id` and
    /// returns its `id` (used as the entry path segment in subsequent
    /// updates) and `registry_url` (the public URL where the JWT will
    /// be published).
    ///
    /// **Not idempotent.** The registry mints a fresh entry on every
    /// successful POST. If the response is lost — request future
    /// cancelled, or transport failure after the server has
    /// committed — the entry exists at the registry but the caller
    /// does not learn its `id`. Retrying issues a second allocation.
    /// Callers that need at-least-once semantics across retries must
    /// persist their intent before the call and check it before
    /// retrying; the client does not deduplicate.
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
    /// - [`RegistryError::Decode`] if the response body is not JSON
    ///   or is missing `id` / `statusRegistryUrl`.
    pub async fn create_status_list_entry(
        &self,
        partner_id: &str,
    ) -> Result<StatusListEntry, RegistryError> {
        let span = tracing::debug_span!(
            "create_status_list_entry",
            partner_id = partner_id,
            status = tracing::field::Empty,
        );
        async move {
            let endpoint = format!(
                "{}/api/v1/status/business-entities/{}/status-list-entries/",
                self.base_url().trim_end_matches('/'),
                partner_id,
            );

            let response = self
                .http
                .post(&endpoint)
                .bearer_auth(self.access_token.as_str())
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

            let body: serde_json::Value = response
                .json()
                .await
                .map_err(|e| RegistryError::Decode(format!("response is not valid JSON: {e}")))?;

            let id = read_string(&body, "id")?;
            let registry_url = read_string(&body, "statusRegistryUrl")?;

            Ok(StatusListEntry { id, registry_url })
        }
        .instrument(span)
        .await
    }
}

fn read_string(body: &serde_json::Value, field: &'static str) -> Result<String, RegistryError> {
    match body.get(field) {
        None => Err(RegistryError::Decode(format!("missing {field}"))),
        Some(value) => value
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| RegistryError::Decode(format!("{field} is not a string"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::AccessToken;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const PARTNER: &str = "8432e1f3-8119-4fb9-a879-190ab2cb9deb";
    const ENDPOINT: &str = "/api/v1/status/business-entities/8432e1f3-8119-4fb9-a879-190ab2cb9deb/status-list-entries/";
    const ENTRY_ID: &str = "18fa7c77-9dd1-4e20-a147-fb1bec146085";
    const REGISTRY_URL: &str = "https://status-registry.admin.ch/api/v1/statuslist/18fa7c77-9dd1-4e20-a147-fb1bec146085.jwt";

    fn client(server: &MockServer) -> StatusRegistryClient {
        StatusRegistryClient::with_http(
            server.uri(),
            AccessToken::new("test-token".to_string()),
            reqwest::Client::new(),
        )
    }

    #[tokio::test]
    async fn happy_path_returns_entry() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(ENDPOINT))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": ENTRY_ID,
                "statusRegistryUrl": REGISTRY_URL,
            })))
            .expect(1)
            .mount(&server)
            .await;

        let entry = client(&server)
            .create_status_list_entry(PARTNER)
            .await
            .unwrap();
        assert_eq!(entry.id, ENTRY_ID);
        assert_eq!(entry.registry_url, REGISTRY_URL);
    }

    #[tokio::test]
    async fn missing_id_yields_decode_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(ENDPOINT))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "statusRegistryUrl": REGISTRY_URL,
            })))
            .mount(&server)
            .await;

        let err = client(&server)
            .create_status_list_entry(PARTNER)
            .await
            .unwrap_err();
        match err {
            RegistryError::Decode(message) => assert!(message.contains("missing id"), "{message}"),
            other => panic!("expected Decode, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn missing_status_registry_url_yields_decode_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(ENDPOINT))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": ENTRY_ID,
            })))
            .mount(&server)
            .await;

        let err = client(&server)
            .create_status_list_entry(PARTNER)
            .await
            .unwrap_err();
        match err {
            RegistryError::Decode(message) => {
                assert!(message.contains("missing statusRegistryUrl"), "{message}")
            }
            other => panic!("expected Decode, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn non_string_id_yields_decode_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(ENDPOINT))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 42,
                "statusRegistryUrl": REGISTRY_URL,
            })))
            .mount(&server)
            .await;

        let err = client(&server)
            .create_status_list_entry(PARTNER)
            .await
            .unwrap_err();
        match err {
            RegistryError::Decode(message) => {
                assert!(message.contains("id is not a string"), "{message}")
            }
            other => panic!("expected Decode, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unauthorized_is_terminal() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(ENDPOINT))
            .respond_with(ResponseTemplate::new(401).set_body_string("unauthorized"))
            .mount(&server)
            .await;

        let err = client(&server)
            .create_status_list_entry(PARTNER)
            .await
            .unwrap_err();
        match &err {
            RegistryError::HttpStatus { status, body } => {
                assert_eq!(*status, 401);
                assert_eq!(body, "unauthorized");
            }
            other => panic!("expected HttpStatus(401), got {other:?}"),
        }
        assert!(!err.is_retryable());
    }

    #[tokio::test]
    async fn forbidden_is_terminal() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(ENDPOINT))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;

        let err = client(&server)
            .create_status_list_entry(PARTNER)
            .await
            .unwrap_err();
        assert!(matches!(err, RegistryError::HttpStatus { status: 403, .. }));
        assert!(!err.is_retryable());
    }

    #[tokio::test]
    async fn server_error_is_retryable() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(ENDPOINT))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let err = client(&server)
            .create_status_list_entry(PARTNER)
            .await
            .unwrap_err();
        assert!(matches!(err, RegistryError::HttpStatus { status: 503, .. }));
        assert!(err.is_retryable());
    }
}
