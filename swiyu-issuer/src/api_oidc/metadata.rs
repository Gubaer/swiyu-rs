use axum::Json;
use axum::extract::{Path, State};
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::domain::vct::CATALOGUE;
use crate::persistence;

use super::AppState;
use super::error::OidcError;

/// Hardcoded signing algorithm. `impl_api_oidc.md` notes that real
/// per-issuer algorithm advertising lands when a second algorithm
/// appears (key rotation, dual-signing). Until then `ES256` is what
/// `swiyu-didtool`'s assertion key emits.
const SIGNING_ALG: &str = "ES256";

/// Wallet-facing OID4VCI credential-issuer metadata document.
#[derive(Debug, Serialize)]
pub struct CredentialIssuerMetadata {
    pub credential_issuer: String,
    pub credential_endpoint: String,
    pub authorization_servers: Vec<String>,
    pub credential_configurations_supported: Value,
    /// Localised display names for the issuer. Sourced from the issuer row's
    /// `(display_name, logo_uri, locale)` triple; omitted entirely when
    /// `display_name` is absent.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub display: Vec<DisplayEntry>,
}

/// One locale-keyed display entry for the issuer's human-readable identity.
#[derive(Debug, Serialize)]
pub struct DisplayEntry {
    /// Human-readable issuer name.
    pub name: String,
    /// BCP 47 language tag (e.g. `"en-US"`). Omitted when not set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    /// Optional issuer logo. Omitted when not set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo: Option<DisplayLogo>,
}

#[derive(Debug, Serialize)]
pub struct DisplayLogo {
    pub uri: String,
}

pub async fn credential_issuer_metadata(
    State(state): State<AppState>,
    Path(issuer_id_str): Path<String>,
) -> Result<Json<CredentialIssuerMetadata>, OidcError> {
    tracing::debug!(
        issuer_id = %issuer_id_str,
        "issuer metadata requested",
    );

    let issuer_id = super::parse_issuer_id(&issuer_id_str)?;

    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| OidcError::Internal(Box::new(err)))?;

    let issuer = persistence::issuers::find_by_id(&mut conn, &issuer_id)
        .await?
        .ok_or(OidcError::NotFound)?;

    let base = state.config.issuer_base_url.trim_end_matches('/');
    let issuer_url = format!("{base}/i/{}", issuer.id.bare());
    let credential_endpoint = format!("{issuer_url}/credential");

    let display = match issuer.display_name {
        Some(name) => vec![DisplayEntry {
            name,
            locale: issuer.locale,
            logo: issuer.logo_uri.map(|uri| DisplayLogo { uri }),
        }],
        None => Vec::new(),
    };

    Ok(Json(CredentialIssuerMetadata {
        credential_issuer: issuer_url.clone(),
        credential_endpoint,
        authorization_servers: vec![issuer_url],
        credential_configurations_supported: build_credential_configurations(),
        display,
    }))
}

/// OAuth authorization server metadata document (RFC 8414 + OID4VCI extensions).
#[derive(Debug, Serialize)]
pub struct OauthAuthorizationServerMetadata {
    /// Issuer identifier URL of this authorization server.
    pub issuer: String,
    pub token_endpoint: String,
    pub grant_types_supported: Vec<&'static str>,
    pub token_endpoint_auth_methods_supported: Vec<&'static str>,
    /// Serialised with a hyphen per the OID4VCI metadata registration:
    /// `pre-authorized_grant_anonymous_access_supported`.
    #[serde(rename = "pre-authorized_grant_anonymous_access_supported")]
    pub pre_authorized_grant_anonymous_access_supported: bool,
}

pub async fn oauth_authorization_server_metadata(
    State(state): State<AppState>,
    Path(issuer_id_str): Path<String>,
) -> Result<Json<OauthAuthorizationServerMetadata>, OidcError> {
    tracing::debug!(
        issuer_id = %issuer_id_str,
        "oauth authorization-server metadata requested",
    );

    let issuer_id = super::parse_issuer_id(&issuer_id_str)?;

    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| OidcError::Internal(Box::new(err)))?;

    // Verify the issuer exists. The response body is a function of
    // the URL alone, but a wallet asking metadata for a non-existent
    // issuer should get the same 404 every other unknown-issuer path
    // returns — no probing for issuer existence.
    persistence::issuers::find_by_id(&mut conn, &issuer_id)
        .await?
        .ok_or(OidcError::NotFound)?;

    let base = state.config.issuer_base_url.trim_end_matches('/');
    let issuer_url = format!("{base}/i/{}", issuer_id.bare());
    let token_endpoint = format!("{issuer_url}/token");

    Ok(Json(OauthAuthorizationServerMetadata {
        issuer: issuer_url,
        token_endpoint,
        grant_types_supported: vec![super::PRE_AUTHORIZED_GRANT_TYPE],
        // Pre-auth flow does not authenticate the client at the token
        // endpoint; the pre-authorised code itself is the credential.
        token_endpoint_auth_methods_supported: vec!["none"],
        pre_authorized_grant_anonymous_access_supported: true,
    }))
}

fn build_credential_configurations() -> Value {
    let mut map = Map::with_capacity(CATALOGUE.len());
    for entry in CATALOGUE {
        map.insert(
            entry.vct.to_string(),
            json!({
                "format": "vc+sd-jwt",
                "vct": entry.vct,
                "cryptographic_binding_methods_supported": ["jwk"],
                "credential_signing_alg_values_supported": [SIGNING_ALG],
                "proof_types_supported": {
                    "jwt": {
                        "proof_signing_alg_values_supported": [SIGNING_ALG]
                    }
                }
            }),
        );
    }
    Value::Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oauth_metadata_serializes_with_hyphenated_field_name() {
        // Round-trip the struct to make sure the OID4VCI-specific
        // hyphenated field name is honoured by serde's rename, not
        // silently emitted as snake_case.
        let m = OauthAuthorizationServerMetadata {
            issuer: "https://example.com/i/abc".to_string(),
            token_endpoint: "https://example.com/i/abc/token".to_string(),
            grant_types_supported: vec![super::super::PRE_AUTHORIZED_GRANT_TYPE],
            token_endpoint_auth_methods_supported: vec!["none"],
            pre_authorized_grant_anonymous_access_supported: true,
        };
        let json = serde_json::to_value(&m).unwrap();
        assert_eq!(json["issuer"], "https://example.com/i/abc");
        assert_eq!(json["token_endpoint"], "https://example.com/i/abc/token");
        assert_eq!(
            json["grant_types_supported"][0],
            "urn:ietf:params:oauth:grant-type:pre-authorized_code"
        );
        assert_eq!(
            json["pre-authorized_grant_anonymous_access_supported"],
            true
        );
        assert!(
            json.get("pre_authorized_grant_anonymous_access_supported")
                .is_none()
        );
    }

    #[test]
    fn build_credential_configurations_advertises_every_catalogue_entry() {
        let v = build_credential_configurations();
        let obj = v.as_object().unwrap();
        assert_eq!(obj.len(), CATALOGUE.len());
        for entry in CATALOGUE {
            let cfg = obj
                .get(entry.vct)
                .unwrap_or_else(|| panic!("missing entry for {}", entry.vct));
            assert_eq!(cfg["format"], "vc+sd-jwt");
            assert_eq!(cfg["vct"], entry.vct);
            assert_eq!(
                cfg["cryptographic_binding_methods_supported"]
                    .as_array()
                    .unwrap()[0],
                "jwk"
            );
            assert_eq!(
                cfg["credential_signing_alg_values_supported"]
                    .as_array()
                    .unwrap()[0],
                SIGNING_ALG
            );
        }
    }
}
