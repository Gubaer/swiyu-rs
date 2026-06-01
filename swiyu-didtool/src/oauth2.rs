//! OAuth2 `refresh_token` grant against the SWIYU token endpoint.
//!
//! SWIYU partner applications cannot use the `client_credentials` grant (the API
//! gateway forbids it), so the only way to obtain a registry access token is to
//! exchange a refresh token seeded from the ePortal. This module performs that
//! one exchange and returns the resulting [`AccessToken`].
//!
//! It is deliberately stateless: the rotated refresh token the endpoint returns
//! is discarded, not persisted. didtool reads the seed from `SWIYU_REFRESH_TOKEN`
//! on every run.

use std::time::Duration;

use serde_json::Value;
use zeroize::Zeroizing;

use swiyu_registries::common::AccessToken;

#[derive(Debug, thiserror::Error)]
pub enum OAuth2Error {
    #[error("{0} is not set")]
    MissingCredential(&'static str),
    #[error("SWIYU_TOKEN_URL is not an https URL: {0}")]
    InvalidTokenUrl(String),
    #[error("refresh token rejected: {0}")]
    RefreshRejected(String),
    #[error("token endpoint transport: {0}")]
    Transport(String),
    #[error("token endpoint decode: {0}")]
    Decode(String),
}

/// The four OAuth2 inputs the `refresh_token` grant needs, read from the environment.
pub(crate) struct OAuthCredentials {
    token_url: String,
    client_id: String,
    client_secret: Zeroizing<String>,
    refresh_token: Zeroizing<String>,
}

impl OAuthCredentials {
    pub(crate) fn from_env() -> Result<Self, OAuth2Error> {
        let token_url = env_var("SWIYU_TOKEN_URL")?;
        if !crate::is_https_url(&token_url) {
            return Err(OAuth2Error::InvalidTokenUrl(token_url));
        }
        Ok(Self {
            token_url,
            client_id: env_var("SWIYU_CLIENT_ID")?,
            client_secret: Zeroizing::new(env_var("SWIYU_CLIENT_SECRET")?),
            refresh_token: Zeroizing::new(env_var("SWIYU_REFRESH_TOKEN")?),
        })
    }
}

/// Performs one `refresh_token` grant and returns the fresh access token. The
/// rotated refresh token in the response is intentionally discarded — didtool
/// does not persist it.
pub(crate) async fn refresh_token_grant(
    creds: &OAuthCredentials,
) -> Result<AccessToken, OAuth2Error> {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| OAuth2Error::Transport(e.to_string()))?;

    let params = [
        ("grant_type", "refresh_token"),
        ("refresh_token", creds.refresh_token.as_str()),
        ("client_id", creds.client_id.as_str()),
        ("client_secret", creds.client_secret.as_str()),
    ];

    let response = http
        .post(&creds.token_url)
        .form(&params)
        .send()
        .await
        .map_err(|e| OAuth2Error::Transport(e.to_string()))?;

    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| OAuth2Error::Transport(e.to_string()))?;

    if status.is_success() {
        return parse_access_token(&body);
    }
    if status.is_client_error() {
        return Err(OAuth2Error::RefreshRejected(format_oauth_error(
            status.as_u16(),
            &body,
        )));
    }
    Err(OAuth2Error::Transport(format!(
        "token endpoint returned HTTP {}: {}",
        status.as_u16(),
        body
    )))
}

fn env_var(name: &'static str) -> Result<String, OAuth2Error> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(value),
        _ => Err(OAuth2Error::MissingCredential(name)),
    }
}

fn parse_access_token(body: &str) -> Result<AccessToken, OAuth2Error> {
    let value: Value = serde_json::from_str(body)
        .map_err(|e| OAuth2Error::Decode(format!("token endpoint body is not JSON: {e}")))?;
    let token = value
        .get("access_token")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            OAuth2Error::Decode("token endpoint response missing access_token".into())
        })?;
    Ok(AccessToken::new(token.to_string()))
}

fn format_oauth_error(status: u16, body: &str) -> String {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return format!("HTTP {status}: {body}");
    };
    let kind = value
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or("(no error code)");
    let detail = value
        .get("error_description")
        .and_then(Value::as_str)
        .unwrap_or("");
    if detail.is_empty() {
        format!("HTTP {status}: {kind}")
    } else {
        format!("HTTP {status}: {kind}: {detail}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn creds(token_url: String) -> OAuthCredentials {
        OAuthCredentials {
            token_url,
            client_id: "client-A".to_string(),
            client_secret: Zeroizing::new("secret-A".to_string()),
            refresh_token: Zeroizing::new("seed-refresh".to_string()),
        }
    }

    #[tokio::test]
    async fn happy_path_returns_access_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("grant_type=refresh_token"))
            .and(body_string_contains("refresh_token=seed-refresh"))
            .and(body_string_contains("client_id=client-A"))
            .and(body_string_contains("client_secret=secret-A"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "access-A",
                "refresh_token": "rotated-refresh",
                "expires_in": 90000,
                "token_type": "Bearer",
            })))
            .expect(1)
            .mount(&server)
            .await;

        let token = refresh_token_grant(&creds(server.uri())).await.unwrap();
        // AccessToken's payload is opaque; Debug masks it, so assert on the mask.
        assert_eq!(format!("{token:?}"), "AccessToken(***)");
    }

    #[tokio::test]
    async fn client_error_is_refresh_rejected() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "Token is not active",
            })))
            .mount(&server)
            .await;

        let err = refresh_token_grant(&creds(server.uri())).await.unwrap_err();
        match err {
            OAuth2Error::RefreshRejected(msg) => {
                assert!(msg.contains("invalid_grant"), "{msg}");
                assert!(msg.contains("Token is not active"), "{msg}");
            }
            other => panic!("expected RefreshRejected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn server_error_is_transport() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let err = refresh_token_grant(&creds(server.uri())).await.unwrap_err();
        assert!(matches!(err, OAuth2Error::Transport(_)));
    }

    #[tokio::test]
    async fn non_json_success_body_is_decode_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&server)
            .await;

        let err = refresh_token_grant(&creds(server.uri())).await.unwrap_err();
        assert!(matches!(err, OAuth2Error::Decode(_)));
    }

    #[test]
    fn format_oauth_error_without_description() {
        let msg = format_oauth_error(400, r#"{"error":"invalid_grant"}"#);
        assert_eq!(msg, "HTTP 400: invalid_grant");
    }

    #[test]
    fn format_oauth_error_falls_back_to_raw_body() {
        let msg = format_oauth_error(403, "not json at all");
        assert_eq!(msg, "HTTP 403: not json at all");
    }
}
