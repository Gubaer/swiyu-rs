use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use serde_json::Value;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("invalid bearer token (cannot be encoded as a header value): {0}")]
    InvalidToken(#[from] reqwest::header::InvalidHeaderValue),
    #[error("http client build failed: {0}")]
    Build(#[from] reqwest::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum CallError {
    #[error("transport error: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("upstream returned {status}: {body}")]
    Status { status: u16, body: String },
}

#[derive(Clone)]
pub struct MgmtApiClient {
    http: reqwest::Client,
    base_url: String,
}

impl MgmtApiClient {
    pub fn new(base_url: &str, bearer_token: &str) -> Result<Self, ClientError> {
        let mut auth = HeaderValue::from_str(&format!("Bearer {bearer_token}"))?;
        auth.set_sensitive(true);
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, auth);
        let http = reqwest::Client::builder()
            .default_headers(headers)
            .build()?;
        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
        })
    }

    pub async fn list_issuers(&self) -> Result<Value, CallError> {
        let url = format!("{}/api/v1/issuers", self.base_url);
        let response = self.http.get(&url).send().await?;
        let status = response.status();
        if status.is_success() {
            Ok(response.json::<Value>().await?)
        } else {
            let body = response.text().await.unwrap_or_default();
            Err(CallError::Status {
                status: status.as_u16(),
                body,
            })
        }
    }
}
