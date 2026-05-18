use axum::Json;
use axum::extract::{Path, State};
use serde::Serialize;
use serde_json::{Map, Value, json};
use swiyu_core::oid4vci;

use crate::domain::CredentialType;
use crate::persistence;

use super::AppState;
use super::error::OidcError;

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

    let credential_types = persistence::credential_types::list_assigned_to_issuer(
        &mut conn,
        &issuer.tenant_id,
        &issuer.id,
    )
    .await?;

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
        credential_configurations_supported: build_credential_configurations(&credential_types),
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

// Each entry is keyed by the credential type's prefixed
// `CredentialTypeId` (the `Display` form, e.g. `ctype_…`) and carries
// the SWIYU profile constants inlined per OID4VCI, which has no
// "applies to all configurations" carve-out. Retired rows are
// filtered out; the retire handler also hard-deletes the assignment
// rows in the same transaction, so this predicate is defence in
// depth.
fn build_credential_configurations(types: &[CredentialType]) -> Value {
    let mut map = Map::with_capacity(types.len());
    for ct in types {
        if ct.retired_at.is_some() {
            continue;
        }
        map.insert(
            ct.id.to_string(),
            json!({
                "format": oid4vci::FORMAT,
                "vct": ct.vct,
                "cryptographic_binding_methods_supported": oid4vci::cryptographic_binding_methods_supported(),
                "credential_signing_alg_values_supported": oid4vci::credential_signing_alg_values_supported(),
                "proof_types_supported": oid4vci::proof_types_supported(),
                "display": ct.display.clone(),
                "claims": ct.claims.clone(),
            }),
        );
    }
    Value::Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::Utc;

    use crate::domain::TenantId;
    use crate::test_support::persistence::credential_types as ct_fixture;

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
    fn build_credential_configurations_keys_by_credential_type_id() {
        let ct = ct_fixture::sample(&TenantId::generate());
        let key = ct.id.to_string();
        let expected_vct = ct.vct.clone();
        let v = build_credential_configurations(&[ct]);
        let obj = v.as_object().unwrap();
        assert_eq!(obj.len(), 1);
        let cfg = obj.get(&key).expect("entry keyed by prefixed id");
        assert_eq!(cfg["format"], oid4vci::FORMAT);
        assert_eq!(cfg["vct"], expected_vct);
        assert_eq!(
            cfg["cryptographic_binding_methods_supported"],
            oid4vci::cryptographic_binding_methods_supported()
        );
        assert_eq!(
            cfg["credential_signing_alg_values_supported"],
            oid4vci::credential_signing_alg_values_supported()
        );
        assert_eq!(
            cfg["proof_types_supported"],
            oid4vci::proof_types_supported()
        );
    }

    #[test]
    fn build_credential_configurations_skips_retired_rows() {
        let tenant_id = TenantId::generate();
        let live = ct_fixture::sample(&tenant_id);
        let mut retired = ct_fixture::sample(&tenant_id);
        retired.try_retire(Utc::now()).unwrap();
        let live_key = live.id.to_string();
        let retired_key = retired.id.to_string();
        let v = build_credential_configurations(&[live, retired]);
        let obj = v.as_object().unwrap();
        assert!(obj.contains_key(&live_key));
        assert!(!obj.contains_key(&retired_key));
    }

    #[test]
    fn build_credential_configurations_empty_for_no_assignments() {
        let v = build_credential_configurations(&[]);
        assert_eq!(v.as_object().unwrap().len(), 0);
    }
}
