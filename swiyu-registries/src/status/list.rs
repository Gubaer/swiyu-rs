use tracing::Instrument;

use crate::common::{AccessToken, RegistryError};
use crate::status::StatusRegistryClient;

/// Pagination and sort parameters for
/// [`list_status_list_entries`](StatusRegistryClient::list_status_list_entries).
///
/// Defaults match the registry's defaults: `page = 0` (zero-based)
/// and `size = 20`. `sort` is a free-form list of
/// `"property,(asc|desc)"` strings; the client passes them through
/// without validation because the spec leaves the property names
/// open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListParams {
    pub page: u32,
    pub size: u32,
    pub sort: Vec<String>,
}

impl Default for ListParams {
    fn default() -> Self {
        Self {
            page: 0,
            size: 20,
            sort: Vec::new(),
        }
    }
}

/// One page of status-list entries returned by
/// [`list_status_list_entries`](StatusRegistryClient::list_status_list_entries).
///
/// Surfaces only the fields callers actually use: the entry slice and
/// the four pagination counters. The Spring `Page<T>` envelope's
/// other fields (`pageable`, `sort`, `first`, `last`, `empty`,
/// `numberOfElements`) are intentionally dropped — none of them carry
/// information beyond what `entries`, `page`, `size`, `total_elements`
/// and `total_pages` already convey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusListEntriesPage {
    pub entries: Vec<StatusListEntrySummary>,
    pub page: u32,
    pub size: u32,
    pub total_elements: u64,
    pub total_pages: u32,
}

/// A single status-list entry as returned by the listing endpoint.
///
/// `created_at` and `updated_at` are surfaced as the raw RFC 3339
/// strings the registry returns; this crate does not depend on a
/// timestamp library, and consumers parse them only if they need a
/// typed value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusListEntrySummary {
    pub id: String,
    pub created_at: String,
    pub updated_at: String,
}

impl StatusRegistryClient {
    /// Fetches one page of status-list entries owned by `partner_id`.
    ///
    /// Idempotent and safe to retry.
    ///
    /// Sends `Authorization: Bearer <token>` from the supplied
    /// [`AccessToken`](crate::common::AccessToken). Pagination is
    /// encoded as the `page`, `size` and (zero or more) `sort` query
    /// parameters, matching the Spring conventions of the upstream
    /// service.
    ///
    /// Errors:
    /// - [`RegistryError::Transport`] for network failures before a
    ///   response is received.
    /// - [`RegistryError::HttpStatus`] for any non-2xx response;
    ///   401/403/404 are non-retryable, 429 and 5xx are retryable per
    ///   [`RegistryError::is_retryable`].
    /// - [`RegistryError::Decode`] if the response body is not JSON,
    ///   if `content` is missing or not an array, or if any required
    ///   pagination/entry field has the wrong type.
    pub async fn list_status_list_entries(
        &self,
        token: &AccessToken,
        partner_id: &str,
        params: ListParams,
    ) -> Result<StatusListEntriesPage, RegistryError> {
        let span = tracing::debug_span!(
            "list_status_list_entries",
            partner_id = partner_id,
            page = params.page,
            size = params.size,
            status = tracing::field::Empty,
        );
        async move {
            let endpoint = format!(
                "{}/api/v1/status/business-entities/{}/status-list-entries/",
                self.base_url().trim_end_matches('/'),
                partner_id,
            );

            let mut query: Vec<(&str, String)> = vec![
                ("page", params.page.to_string()),
                ("size", params.size.to_string()),
            ];
            for criterion in &params.sort {
                query.push(("sort", criterion.clone()));
            }

            let response = self
                .http
                .get(&endpoint)
                .bearer_auth(token.as_str())
                .query(&query)
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

            decode_page(&body)
        }
        .instrument(span)
        .await
    }
}

fn decode_page(body: &serde_json::Value) -> Result<StatusListEntriesPage, RegistryError> {
    let content = body
        .get("content")
        .ok_or_else(|| RegistryError::Decode("missing content".to_string()))?
        .as_array()
        .ok_or_else(|| RegistryError::Decode("content is not an array".to_string()))?;

    let mut entries = Vec::with_capacity(content.len());
    for (index, item) in content.iter().enumerate() {
        entries.push(decode_entry(item).map_err(|err| {
            if let RegistryError::Decode(message) = err {
                RegistryError::Decode(format!("content[{index}]: {message}"))
            } else {
                err
            }
        })?);
    }

    Ok(StatusListEntriesPage {
        entries,
        page: read_u32(body, "number")?,
        size: read_u32(body, "size")?,
        total_elements: read_u64(body, "totalElements")?,
        total_pages: read_u32(body, "totalPages")?,
    })
}

fn decode_entry(value: &serde_json::Value) -> Result<StatusListEntrySummary, RegistryError> {
    Ok(StatusListEntrySummary {
        id: read_string(value, "id")?,
        created_at: read_string(value, "createdAt")?,
        updated_at: read_string(value, "updatedAt")?,
    })
}

fn read_string(value: &serde_json::Value, field: &'static str) -> Result<String, RegistryError> {
    match value.get(field) {
        None => Err(RegistryError::Decode(format!("missing {field}"))),
        Some(v) => v
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| RegistryError::Decode(format!("{field} is not a string"))),
    }
}

fn read_u32(value: &serde_json::Value, field: &'static str) -> Result<u32, RegistryError> {
    let n = read_u64(value, field)?;
    u32::try_from(n).map_err(|_| RegistryError::Decode(format!("{field} does not fit in u32: {n}")))
}

fn read_u64(value: &serde_json::Value, field: &'static str) -> Result<u64, RegistryError> {
    match value.get(field) {
        None => Err(RegistryError::Decode(format!("missing {field}"))),
        Some(v) => v
            .as_u64()
            .ok_or_else(|| RegistryError::Decode(format!("{field} is not a non-negative integer"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const PARTNER: &str = "8432e1f3-8119-4fb9-a879-190ab2cb9deb";
    const ENDPOINT: &str = "/api/v1/status/business-entities/8432e1f3-8119-4fb9-a879-190ab2cb9deb/status-list-entries/";
    const ENTRY_ID: &str = "18fa7c77-9dd1-4e20-a147-fb1bec146085";

    fn client(server: &MockServer) -> StatusRegistryClient {
        StatusRegistryClient::with_http(server.uri(), reqwest::Client::new())
    }

    fn token() -> AccessToken {
        AccessToken::new("test-token".to_string())
    }

    fn page_body(content: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "totalElements": 1,
            "totalPages": 1,
            "first": true,
            "last": true,
            "size": 20,
            "content": content,
            "number": 0,
            "numberOfElements": 1,
            "empty": false,
        })
    }

    #[tokio::test]
    async fn happy_path_returns_page_with_defaults() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(ENDPOINT))
            .and(header("Authorization", "Bearer test-token"))
            .and(query_param("page", "0"))
            .and(query_param("size", "20"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(page_body(serde_json::json!([
                    {
                        "id": ENTRY_ID,
                        "createdAt": "2024-10-29T09:35:16.809924Z",
                        "updatedAt": "2024-10-29T09:35:16.809924Z",
                    }
                ]))),
            )
            .expect(1)
            .mount(&server)
            .await;

        let page = client(&server)
            .list_status_list_entries(&token(), PARTNER, ListParams::default())
            .await
            .unwrap();
        assert_eq!(page.entries.len(), 1);
        assert_eq!(page.entries[0].id, ENTRY_ID);
        assert_eq!(page.entries[0].created_at, "2024-10-29T09:35:16.809924Z");
        assert_eq!(page.entries[0].updated_at, "2024-10-29T09:35:16.809924Z");
        assert_eq!(page.page, 0);
        assert_eq!(page.size, 20);
        assert_eq!(page.total_elements, 1);
        assert_eq!(page.total_pages, 1);
    }

    #[tokio::test]
    async fn sort_criteria_are_passed_through_as_repeated_query_params() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(ENDPOINT))
            .and(query_param("page", "2"))
            .and(query_param("size", "5"))
            .and(query_param("sort", "createdAt,desc"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(page_body(serde_json::json!([]))),
            )
            .expect(1)
            .mount(&server)
            .await;

        let params = ListParams {
            page: 2,
            size: 5,
            sort: vec!["createdAt,desc".to_string()],
        };
        client(&server)
            .list_status_list_entries(&token(), PARTNER, params)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn missing_content_yields_decode_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(ENDPOINT))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "totalElements": 0,
                "totalPages": 0,
                "size": 20,
                "number": 0,
            })))
            .mount(&server)
            .await;

        let err = client(&server)
            .list_status_list_entries(&token(), PARTNER, ListParams::default())
            .await
            .unwrap_err();
        match err {
            RegistryError::Decode(message) => {
                assert!(message.contains("missing content"), "{message}")
            }
            other => panic!("expected Decode, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn entry_with_missing_field_localises_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(ENDPOINT))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(page_body(serde_json::json!([
                    {
                        "id": ENTRY_ID,
                        "createdAt": "2024-10-29T09:35:16.809924Z",
                    }
                ]))),
            )
            .mount(&server)
            .await;

        let err = client(&server)
            .list_status_list_entries(&token(), PARTNER, ListParams::default())
            .await
            .unwrap_err();
        match err {
            RegistryError::Decode(message) => {
                assert!(message.contains("content[0]"), "{message}");
                assert!(message.contains("missing updatedAt"), "{message}");
            }
            other => panic!("expected Decode, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unauthorized_is_terminal() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(ENDPOINT))
            .respond_with(ResponseTemplate::new(401).set_body_string("unauthorized"))
            .mount(&server)
            .await;

        let err = client(&server)
            .list_status_list_entries(&token(), PARTNER, ListParams::default())
            .await
            .unwrap_err();
        assert!(matches!(err, RegistryError::HttpStatus { status: 401, .. }));
        assert!(!err.is_retryable());
    }

    #[tokio::test]
    async fn server_error_is_retryable() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(ENDPOINT))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let err = client(&server)
            .list_status_list_entries(&token(), PARTNER, ListParams::default())
            .await
            .unwrap_err();
        assert!(matches!(err, RegistryError::HttpStatus { status: 503, .. }));
        assert!(err.is_retryable());
    }
}
