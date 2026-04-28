#[derive(Debug, thiserror::Error)]
pub enum SwiyuError {
    #[error("SWIYU_ACCESS_TOKEN is not set")]
    AccessTokenMissing,
    #[error("registry API error: HTTP {0}")]
    ApiError(u16),
    #[error("registry response is invalid: {0}")]
    ResponseInvalid(String),
    #[error("registry request failed: {0}")]
    Http(#[from] reqwest::Error),
}

/// Result of a successful identifier-entry allocation against the SWIYU registry.
pub struct Allocation {
    /// Public URL from which the DID log will be served.
    pub url: String,
    /// UUID assigned by the registry, used to address the entry in subsequent calls.
    pub identifier: String,
}

/// Calls the SWIYU identifier registry to allocate a new DID space.
///
/// # Arguments
///
/// * `partner_id` — business partner UUID (e.g. `4e1a7d46-b6dc-48fe-a2fd-56cbb68e7eef`).
/// * `registry_url` — base URL of the identifier registry API (must use `https://`).
///
/// `SWIYU_ACCESS_TOKEN` must be set in the environment; the function returns
/// [`SwiyuError::AccessTokenMissing`] if it is absent.
pub fn allocate_did_url(
    partner_id: String,
    registry_url: String,
) -> Result<Allocation, SwiyuError> {
    let access_token: zeroize::Zeroizing<String> = std::env::var("SWIYU_ACCESS_TOKEN")
        .map(zeroize::Zeroizing::new)
        .map_err(|_| SwiyuError::AccessTokenMissing)?;

    let endpoint = format!(
        "{}/api/v1/identifier/business-entities/{}/identifier-entries",
        registry_url.trim_end_matches('/'),
        partner_id,
    );

    let client = reqwest::blocking::Client::new();
    tracing::debug!("POST {}", endpoint);
    let response = client.post(&endpoint).bearer_auth(&*access_token).send()?;

    let status = response.status();
    tracing::debug!("registry responded with HTTP {}", status);
    if !status.is_success() {
        tracing::debug!(
            "registry error body: {}",
            response.text().unwrap_or_default()
        );
        return Err(SwiyuError::ApiError(status.as_u16()));
    }

    let body: serde_json::Value = response.json()?;
    let url = body["identifierRegistryUrl"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| SwiyuError::ResponseInvalid("missing identifierRegistryUrl".into()))?;
    let identifier = extract_identifier(&url).ok_or_else(|| {
        SwiyuError::ResponseInvalid(format!(
            "cannot extract identifier from identifierRegistryUrl '{url}'"
        ))
    })?;
    tracing::debug!("registry allocated URL: {}", url);
    tracing::debug!("registry allocated identifier: {}", identifier);
    Ok(Allocation { url, identifier })
}

/// Uploads `entry_body` (a single line of JSON, no trailing newline) to the SWIYU registry,
/// completing the registration started by [`allocate_did_url`].
pub fn publish_entry(
    registry_url: &str,
    partner_id: &str,
    identifier: &str,
    entry_body: &str,
) -> Result<(), SwiyuError> {
    let access_token: zeroize::Zeroizing<String> = std::env::var("SWIYU_ACCESS_TOKEN")
        .map(zeroize::Zeroizing::new)
        .map_err(|_| SwiyuError::AccessTokenMissing)?;

    let endpoint = format!(
        "{}/api/v1/identifier/business-entities/{}/identifier-entries/{}",
        registry_url.trim_end_matches('/'),
        partner_id,
        identifier,
    );

    let client = reqwest::blocking::Client::new();
    tracing::debug!("PUT {}", endpoint);
    let response = client
        .put(&endpoint)
        .bearer_auth(&*access_token)
        .header("Content-Type", "application/jsonl+json")
        .body(entry_body.to_string())
        .send()?;

    let status = response.status();
    tracing::debug!("registry responded with HTTP {}", status);
    if !status.is_success() {
        tracing::debug!(
            "registry error body: {}",
            response.text().unwrap_or_default()
        );
        return Err(SwiyuError::ApiError(status.as_u16()));
    }
    Ok(())
}

/// Extracts the identifier (UUID) from an `identifierRegistryUrl` of the form
/// `https://<host>/api/v1/did/<UUID>` (with or without a trailing `/did.jsonl` filename).
/// Returns the last non-empty path segment.
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
