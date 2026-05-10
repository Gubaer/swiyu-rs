use axum::Json;
use axum::extract::{Path, State};
use chrono::Utc;
use serde::Serialize;
use serde_json::{Value, json};

use crate::domain::{CredentialOfferId, CredentialOfferState};
use crate::persistence;

use super::AppState;
use super::error::OidcError;

/// OID4VCI `CredentialOffer` body returned behind the `credential_offer_uri` deeplink.
#[derive(Debug, Serialize)]
pub struct CredentialOfferBody {
    pub credential_issuer: String,
    pub credential_configuration_ids: Vec<String>,
    /// JSON object keyed by grant-type URI; we emit a single pre-authorised-code entry
    /// carrying the bare code (single-use bearer secret). The code lives in
    /// `credential_offers.pre_auth_code` until
    /// [`cancel`][persistence::credential_offers::cancel] or
    /// [`set_issued_state`][persistence::oidc::credential_offers::set_issued_state]
    /// NULLs it.
    pub grants: Value,
}

/// `GET /i/{issuer_id}/credential-offer/{offer_id}`
///
/// Returns the OID4VCI credential-offer body that wallets fetch via the `credential_offer_uri`
/// deeplink. Responds with `410 Gone` when the offer has expired and `404 Not Found` when it
/// has already been issued or cancelled.
pub async fn credential_offer(
    State(state): State<AppState>,
    Path((issuer_id_str, offer_id_str)): Path<(String, String)>,
) -> Result<Json<CredentialOfferBody>, OidcError> {
    tracing::debug!(
        issuer_id = %issuer_id_str,
        offer_id = %offer_id_str,
        "credential offer fetch (wallet) requested",
    );

    let issuer_id = super::parse_issuer_id(&issuer_id_str)?;
    let offer_id = parse_offer_id(&offer_id_str)?;

    let mut conn = state
        .pool
        .acquire()
        .await
        .map_err(|err| OidcError::Internal(Box::new(err)))?;

    // Resolve the tenant from the issuer row (the wallet path has
    // none). Same 404 for unknown issuer as for unknown offer — the
    // wallet must not be able to probe issuer existence.
    let issuer = persistence::issuers::find_by_id(&mut conn, &issuer_id)
        .await?
        .ok_or(OidcError::NotFound)?;

    let offer = persistence::credential_offers::find_by_id(
        &mut conn,
        &issuer.tenant_id,
        &issuer_id,
        &offer_id,
    )
    // find_by_id collapses "wrong issuer" and "wrong offer" to NotFound —
    // the wallet must not be able to probe offer existence across issuers.
    .await
    .map_err(OidcError::from)?;

    // Map the observed state to the response code per spec:
    //   pending+unexpired -> 200 with the body
    //   pending+expired   -> 410 (the row is still pending in storage,
    //                       but the wallet sees Gone)
    //   issued/cancelled  -> 404 (the offer is no longer redeemable)
    match offer.observed_state(Utc::now()) {
        CredentialOfferState::Pending => { /* fall through to body */ }
        CredentialOfferState::Expired => return Err(OidcError::Expired),
        CredentialOfferState::Issued | CredentialOfferState::Cancelled => {
            return Err(OidcError::NotFound);
        }
    }

    let bare_code = offer.pre_auth_code.as_ref().ok_or_else(|| {
        // The offer is pending+unexpired but the column is NULL.
        // This is an inconsistency (a pending offer should always
        // carry the bare code); 404 from the wallet's point of view
        // since we cannot honour the request.
        tracing::warn!(
            %offer_id,
            "pending offer has no pre_auth_code; treating as not found",
        );
        OidcError::NotFound
    })?;

    let base = state.config.issuer_base_url.trim_end_matches('/');
    let issuer_url = format!("{base}/i/{}", issuer_id.bare());

    let grants = json!({
        super::PRE_AUTHORIZED_GRANT_TYPE: {
            "pre-authorized_code": bare_code.as_str()
        }
    });

    Ok(Json(CredentialOfferBody {
        credential_issuer: issuer_url,
        credential_configuration_ids: vec![offer.vct],
        grants,
    }))
}

fn parse_offer_id(raw: &str) -> Result<CredentialOfferId, OidcError> {
    CredentialOfferId::from_bare(raw).map_err(|err| OidcError::InvalidInput {
        details: format!("offer_id path parameter: {err}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_offer_id_rejects_invalid_character() {
        assert!(matches!(
            parse_offer_id("notValid0").unwrap_err(),
            OidcError::InvalidInput { .. }
        ));
    }
}
