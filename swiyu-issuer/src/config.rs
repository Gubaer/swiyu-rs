/// Resolves the public base URL of the wallet-facing OIDC endpoints.
///
/// Both binaries build wallet-facing URLs from this single value, so
/// they have to agree on it: the management API puts it in each
/// credential-offer deeplink (`credential_offer_uri`), and the OIDC API
/// puts it in the offer body's `credential_issuer` and in the issuer
/// metadata endpoints the wallet follows next. If they disagree, the
/// wallet leaves the deeplink and is sent back to the wrong host.
///
/// `ISSUER_OIDC_HTTP_URL` wins when set. A split-port dev stack runs
/// the OIDC server on a different port than the management API and has
/// no reverse proxy, so the deeplink must name the OIDC port explicitly
/// — that is what this var carries. It falls back to `ISSUER_BASE_URL`,
/// the single externally reachable URL a reverse-proxied production
/// deployment exposes for both binaries, and finally to the dev OIDC
/// default.
pub fn resolve_oidc_public_url(
    oidc_http_url: Option<String>,
    issuer_base_url: Option<String>,
) -> String {
    let non_empty = |value: String| {
        if value.trim().is_empty() {
            None
        } else {
            Some(value)
        }
    };
    oidc_http_url
        .and_then(non_empty)
        .or_else(|| issuer_base_url.and_then(non_empty))
        .unwrap_or_else(|| "http://localhost:8081".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefers_oidc_http_url_when_set() {
        let resolved = resolve_oidc_public_url(
            Some("http://localhost:8081".to_string()),
            Some("http://localhost:8080".to_string()),
        );
        assert_eq!(resolved, "http://localhost:8081");
    }

    #[test]
    fn falls_back_to_issuer_base_url_when_oidc_unset() {
        let resolved =
            resolve_oidc_public_url(None, Some("https://issuer.example.com".to_string()));
        assert_eq!(resolved, "https://issuer.example.com");
    }

    #[test]
    fn treats_empty_oidc_http_url_as_unset() {
        let resolved = resolve_oidc_public_url(
            Some("   ".to_string()),
            Some("https://issuer.example.com".to_string()),
        );
        assert_eq!(resolved, "https://issuer.example.com");
    }

    #[test]
    fn defaults_to_dev_oidc_port_when_nothing_set() {
        assert_eq!(resolve_oidc_public_url(None, None), "http://localhost:8081");
    }
}
