use tracing::Instrument;

use crate::common::{AccessToken, RegistryError};
use crate::identifier::IdentifierRegistryClient;

/// Result of a successful identifier-entry allocation.
///
/// `url` is the registry-published URL where the DIDLog will be
/// served. `identifier` is the UUID extracted from that URL and is
/// used as the path segment for subsequent `publish_log_entry` and
/// `fetch_log` calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allocation {
    pub url: String,
    pub identifier: String,
}

impl IdentifierRegistryClient {
    /// Allocates a new identifier entry for `partner_id` and
    /// returns the registry-published DIDLog URL together with the
    /// UUID extracted from it.
    ///
    /// **Not idempotent.** The registry mints a fresh identifier on
    /// every successful POST. If the response is lost — request
    /// future cancelled, or transport failure after the server has
    /// committed — the allocation exists at the registry but the
    /// caller does not learn its identifier. Retrying issues a
    /// second allocation. Callers that need at-least-once
    /// semantics across retries must persist their intent before
    /// the call and check it before retrying; the client does not
    /// deduplicate.
    ///
    /// Sends `Authorization: Bearer <token>` from the supplied
    /// [`AccessToken`](crate::common::AccessToken).
    ///
    /// Errors:
    /// - [`RegistryError::Transport`] for network failures before a
    ///   response is received.
    /// - [`RegistryError::HttpStatus`] for any non-2xx response;
    ///   401 is non-retryable, 429 and 5xx are retryable per
    ///   [`RegistryError::is_retryable`].
    /// - [`RegistryError::Decode`] if the response body is not
    ///   JSON, is missing `identifierRegistryUrl`, or the URL does
    ///   not contain an extractable identifier segment.
    pub async fn allocate_did(
        &self,
        token: &AccessToken,
        partner_id: &str,
    ) -> Result<Allocation, RegistryError> {
        let span = tracing::debug_span!(
            "allocate_did",
            partner_id = partner_id,
            status = tracing::field::Empty,
        );
        async move {
            let endpoint = format!(
                "{}/api/v1/identifier/business-entities/{}/identifier-entries",
                self.base_url().trim_end_matches('/'),
                partner_id,
            );

            let response = self
                .http
                .post(&endpoint)
                .bearer_auth(token.as_str())
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

            let registry_url = match body.get("identifierRegistryUrl") {
                None => {
                    return Err(RegistryError::Decode(
                        "missing identifierRegistryUrl".to_string(),
                    ));
                }
                Some(value) => value.as_str().ok_or_else(|| {
                    RegistryError::Decode("identifierRegistryUrl is not a string".to_string())
                })?,
            };

            let identifier = extract_identifier(registry_url).ok_or_else(|| {
                RegistryError::Decode(format!(
                    "cannot extract identifier from identifierRegistryUrl '{registry_url}'"
                ))
            })?;

            Ok(Allocation {
                url: registry_url.to_string(),
                identifier,
            })
        }
        .instrument(span)
        .await
    }
}

fn extract_identifier(url: &str) -> Option<String> {
    let trimmed = url
        .strip_suffix("/did.jsonl")
        .unwrap_or(url)
        .trim_end_matches('/');
    let last = trimmed.rsplit('/').next()?;
    if last.is_empty() {
        None
    } else {
        Some(last.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const PARTNER: &str = "4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef";
    const ENDPOINT: &str = "/api/v1/identifier/business-entities/4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef/identifier-entries";
    const UUID: &str = "fce949f2-32c4-4915-8b60-0ee2f705231d";

    fn client(server: &MockServer) -> IdentifierRegistryClient {
        IdentifierRegistryClient::with_http(server.uri(), reqwest::Client::new())
    }

    fn token() -> AccessToken {
        AccessToken::new("test-token".to_string())
    }

    #[tokio::test]
    async fn happy_path_returns_allocation() {
        let server = MockServer::start().await;
        let url = format!("https://identifier-reg.swiyu.admin.ch/api/v1/did/{UUID}/did.jsonl");
        Mock::given(method("POST"))
            .and(path(ENDPOINT))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "identifierRegistryUrl": url,
            })))
            .expect(1)
            .mount(&server)
            .await;

        let allocation = client(&server)
            .allocate_did(&token(), PARTNER)
            .await
            .unwrap();
        assert_eq!(allocation.url, url);
        assert_eq!(allocation.identifier, UUID);
    }

    #[tokio::test]
    async fn missing_field_yields_decode_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(ENDPOINT))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;

        let err = client(&server)
            .allocate_did(&token(), PARTNER)
            .await
            .unwrap_err();
        match err {
            RegistryError::Decode(message) => {
                assert!(
                    message.contains("missing identifierRegistryUrl"),
                    "{message}"
                )
            }
            other => panic!("expected Decode, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn malformed_url_yields_decode_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(ENDPOINT))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "identifierRegistryUrl": "/",
            })))
            .mount(&server)
            .await;

        let err = client(&server)
            .allocate_did(&token(), PARTNER)
            .await
            .unwrap_err();
        match err {
            RegistryError::Decode(message) => {
                assert!(message.contains("cannot extract identifier"), "{message}")
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
            .allocate_did(&token(), PARTNER)
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
    async fn rate_limited_is_retryable() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(ENDPOINT))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;

        let err = client(&server)
            .allocate_did(&token(), PARTNER)
            .await
            .unwrap_err();
        assert!(matches!(err, RegistryError::HttpStatus { status: 429, .. }));
        assert!(err.is_retryable());
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
            .allocate_did(&token(), PARTNER)
            .await
            .unwrap_err();
        assert!(matches!(err, RegistryError::HttpStatus { status: 503, .. }));
        assert!(err.is_retryable());
    }

    #[test]
    fn extract_identifier_with_did_jsonl_suffix() {
        let url = "https://identifier-reg.swiyu.admin.ch/api/v1/did/fce949f2-32c4-4915-8b60-0ee2f705231d/did.jsonl";
        assert_eq!(
            extract_identifier(url).as_deref(),
            Some("fce949f2-32c4-4915-8b60-0ee2f705231d"),
        );
    }

    #[test]
    fn extract_identifier_without_did_jsonl_suffix() {
        let url =
            "https://identifier-reg.swiyu.admin.ch/api/v1/did/aff8f4ae-7fa7-4df2-ab0a-361174ce6ba9";
        assert_eq!(
            extract_identifier(url).as_deref(),
            Some("aff8f4ae-7fa7-4df2-ab0a-361174ce6ba9"),
        );
    }

    #[test]
    fn extract_identifier_returns_none_for_empty_url() {
        assert!(extract_identifier("").is_none());
    }
}
