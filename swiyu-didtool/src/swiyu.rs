#[derive(Debug, thiserror::Error)]
pub enum SwiyuError {
    #[error("SWIYU_ACCESS_TOKEN is not set")]
    AccessTokenMissing,
    #[error("registry API error: {0} {1}")]
    ApiError(u16, String),
    #[error("registry response did not contain identifierRegistryUrl")]
    ResponseInvalid,
    #[error("registry request failed: {0}")]
    Http(#[from] reqwest::Error),
}

/// Calls the SWIYU identifier registry to allocate a new DID space and returns the
/// `identifierRegistryUrl` from the response, which is then used as the DID URL.
///
/// # Arguments
///
/// * `partner_id` — business partner UUID (e.g. `4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef`).
/// * `registry_url` — base URL of the identifier registry API (must use `https://`).
///
/// `SWIYU_ACCESS_TOKEN` must be set in the environment; the function returns
/// [`SwiyuError::AccessTokenMissing`] if it is absent.
pub fn allocate_did_url(partner_id: String, registry_url: String) -> Result<String, SwiyuError> {
    let access_token =
        std::env::var("SWIYU_ACCESS_TOKEN").map_err(|_| SwiyuError::AccessTokenMissing)?;

    let endpoint = format!(
        "{}/api/v1/identifier/business-entities/{}/identifier-entries",
        registry_url.trim_end_matches('/'),
        partner_id,
    );

    let client = reqwest::blocking::Client::new();
    tracing::debug!("POST {}", endpoint);
    let response = client.post(&endpoint).bearer_auth(&access_token).send()?;

    let status = response.status();
    tracing::debug!("registry responded with HTTP {}", status);
    if !status.is_success() {
        let body = response.text().unwrap_or_default();
        return Err(SwiyuError::ApiError(status.as_u16(), body));
    }

    let body: serde_json::Value = response.json()?;
    let url = body["identifierRegistryUrl"]
        .as_str()
        .map(str::to_string)
        .ok_or(SwiyuError::ResponseInvalid)?;
    tracing::debug!("registry allocated URL: {}", url);
    Ok(url)
}
