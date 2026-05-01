use axum::Json;
use axum::extract::{Path, State};
use serde::Serialize;
use serde_json::{Value, json};

use crate::domain::IssuerId;
use crate::persistence;

use super::AppState;
use super::error::OidcError;

/// The single credential configuration this binary advertises.
/// Hardcoded here because the issuers table only holds DID + key-id
/// at this stage; per-issuer credential-config catalogues are a
/// later slice.
const RESIDENCE_ID_VCT: &str = "urn:communal:local-residence-id";

/// Hardcoded signing algorithm. `impl_api_oidc.md` notes that real
/// per-issuer algorithm advertising lands when a second algorithm
/// appears (key rotation, dual-signing). Until then `ES256` is what
/// `swiyu-didtool`'s assertion key emits.
const SIGNING_ALG: &str = "ES256";

/// Wallet-facing OID4VCI metadata document.
///
/// Field order and naming follow the OID4VCI draft we target — see
/// `impl_api_oidc.md` *Open* for the draft-version pinning question.
/// `display` is an array of locale-keyed entries so the wallet can
/// pick a localised name; the issuers table carries one optional
/// `(display_name, logo_uri, locale)` triple, which maps to a
/// single-element array (or omitted entirely if `display_name` is
/// absent).
#[derive(Debug, Serialize)]
pub struct CredentialIssuerMetadata {
    pub credential_issuer: String,
    pub credential_endpoint: String,
    pub authorization_servers: Vec<String>,
    pub credential_configurations_supported: Value,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub display: Vec<DisplayEntry>,
}

#[derive(Debug, Serialize)]
pub struct DisplayEntry {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
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

    let issuer_id = parse_issuer_id(&issuer_id_str)?;

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

fn parse_issuer_id(raw: &str) -> Result<IssuerId, OidcError> {
    IssuerId::from_bare(raw).map_err(|err| OidcError::InvalidInput {
        details: format!("issuer_id path parameter: {err}"),
    })
}

fn build_credential_configurations() -> Value {
    json!({
        RESIDENCE_ID_VCT: {
            "format": "vc+sd-jwt",
            "vct": RESIDENCE_ID_VCT,
            "cryptographic_binding_methods_supported": ["jwk"],
            "credential_signing_alg_values_supported": [SIGNING_ALG],
            "proof_types_supported": {
                "jwt": {
                    "proof_signing_alg_values_supported": [SIGNING_ALG]
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_issuer_id_accepts_valid_base58() {
        assert!(parse_issuer_id("9hXq2vRtL8pK7f").is_ok());
    }

    #[test]
    fn parse_issuer_id_rejects_invalid_character() {
        let err = parse_issuer_id("notValid0").unwrap_err();
        assert!(matches!(err, OidcError::InvalidInput { .. }));
    }

    #[test]
    fn build_credential_configurations_advertises_residence_id() {
        let v = build_credential_configurations();
        let obj = v.as_object().unwrap();
        assert!(obj.contains_key(RESIDENCE_ID_VCT));
        let cfg = &obj[RESIDENCE_ID_VCT];
        assert_eq!(cfg["format"], "vc+sd-jwt");
        assert_eq!(cfg["vct"], RESIDENCE_ID_VCT);
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
