use axum::Json;
use axum::extract::{Form, Path, State};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::domain::{AccessTokenSecret, CredentialOfferState, IssuerId, NonceSecret, PreAuthCode};
use crate::persistence;

use super::AppState;
use super::oauth_error::OAuthError;

/// Form-encoded request body for `POST /token`.
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    /// Wire name is `pre-authorized_code` (hyphen, not underscore) per OID4VCI.
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
}

/// Response body for `POST /token`.
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    /// Always `"Bearer"`.
    pub token_type: &'static str,
    /// Access-token lifetime in seconds.
    pub expires_in: i64,
    /// Nonce the wallet must include in its credential-request proof JWT.
    pub c_nonce: String,
    /// Nonce lifetime in seconds.
    pub c_nonce_expires_in: i64,
}

/// `POST /i/{issuer_id}/token`
///
/// Exchanges a pre-authorised code for a bearer access token and a `c_nonce`
/// for use in the subsequent credential-request proof JWT.
pub async fn token(
    State(state): State<AppState>,
    Path(issuer_id_str): Path<String>,
    Form(payload): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, OAuthError> {
    tracing::debug!(
        issuer_id = %issuer_id_str,
        grant_type = %payload.grant_type,
        "token request",
    );

    if payload.grant_type != super::PRE_AUTHORIZED_GRANT_TYPE {
        return Err(OAuthError::UnsupportedGrantType {
            grant_type: payload.grant_type,
        });
    }

    let issuer_id = parse_issuer_id(&issuer_id_str)?;
    let pre_auth_code = PreAuthCode::from_stored(payload.pre_authorized_code);

    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| OAuthError::Internal(Box::new(err)))?;

    // Resolve the tenant from the issuer row. A wallet asking for a
    // token under a non-existent issuer gets the same `invalid_grant`
    // as a bad pre-auth code — no probing for issuer existence.
    let issuer = persistence::issuers::find_by_id(&mut conn, &issuer_id)
        .await
        .map_err(OAuthError::from)?
        .ok_or_else(|| OAuthError::InvalidGrant {
            description: "no offer matches the presented pre-authorised code".to_string(),
        })?;

    let offer = persistence::oidc::credential_offers::find_by_pre_auth_code(
        &mut conn,
        &issuer.tenant_id,
        &issuer_id,
        &pre_auth_code,
    )
    .await
    .map_err(OAuthError::from)?
    .ok_or_else(|| OAuthError::InvalidGrant {
        description: "no offer matches the presented pre-authorised code".to_string(),
    })?;

    // Observed-state rule: only `pending` and unexpired offers may
    // be redeemed. Issued / cancelled / expired all surface as
    // `invalid_grant` — same generic body so the wallet cannot tell
    // which terminal state the offer is in.
    let now = Utc::now();
    if offer.observed_state(now) != CredentialOfferState::Pending {
        return Err(OAuthError::InvalidGrant {
            description: "the offer is no longer redeemable".to_string(),
        });
    }

    let access_token = AccessTokenSecret::generate();
    let access_token_hash = access_token.hash();
    let access_token_expires_at = now + state.config.access_token_ttl;

    let nonce = NonceSecret::generate();
    let nonce_hash = nonce.hash();
    let nonce_expires_at = now + state.config.c_nonce_ttl;

    // Insert the access token first. The unique constraint on
    // `offer_id` is the spec-mandated double-redemption guard: if a
    // second /token for the same offer races to the insert, this
    // call returns UniqueViolation and the From impl maps it to
    // `invalid_grant`.
    persistence::oidc::access_tokens::insert(
        &mut conn,
        &issuer.tenant_id,
        &issuer_id,
        &offer.id,
        &access_token_hash,
        access_token_expires_at,
    )
    .await?;

    persistence::oidc::nonces::insert(
        &mut conn,
        &issuer.tenant_id,
        &issuer_id,
        &offer.id,
        &nonce_hash,
        nonce_expires_at,
    )
    .await?;

    Ok(Json(TokenResponse {
        access_token: access_token.into(),
        token_type: "Bearer",
        expires_in: state.config.access_token_ttl.num_seconds(),
        c_nonce: nonce.into(),
        c_nonce_expires_in: state.config.c_nonce_ttl.num_seconds(),
    }))
}

fn parse_issuer_id(raw: &str) -> Result<IssuerId, OAuthError> {
    IssuerId::from_bare(raw).map_err(|err| OAuthError::InvalidRequest {
        description: format!("issuer_id path parameter: {err}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_request_round_trips_with_hyphenated_field_name() {
        // serde_urlencoded mirrors the form decoder axum's Form
        // extractor uses. Round-trip through it to verify the
        // hyphenated field name is honoured.
        let body = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code\
                    &pre-authorized_code=DevDevDevDev";
        let req: TokenRequest = serde_urlencoded::from_str(body).unwrap();
        assert_eq!(req.grant_type, super::super::PRE_AUTHORIZED_GRANT_TYPE);
        assert_eq!(req.pre_authorized_code, "DevDevDevDev");
    }

    #[test]
    fn token_request_rejects_underscored_field_name() {
        // A wallet that wrote `pre_authorized_code` (snake-case) in
        // place of the hyphenated OID4VCI spelling must not parse.
        let body = "grant_type=foo&pre_authorized_code=bar";
        assert!(serde_urlencoded::from_str::<TokenRequest>(body).is_err());
    }

    #[test]
    fn parse_issuer_id_rejects_invalid_character() {
        assert!(matches!(
            parse_issuer_id("notValid0").unwrap_err(),
            OAuthError::InvalidRequest { .. }
        ));
    }
}
