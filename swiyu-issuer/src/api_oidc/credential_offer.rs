use axum::Json;
use axum::extract::{Path, State};
use chrono::Utc;
use serde::Serialize;
use serde_json::{Value, json};

use crate::domain::{CredentialOfferId, CredentialOfferState, IssuerId};
use crate::persistence;

use super::AppState;
use super::error::OidcError;

const PRE_AUTHORIZED_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

/// OID4VCI `CredentialOffer` body returned behind the
/// `credential_offer_uri` from the deeplink.
///
/// `grants` is a JSON object whose keys are grant-type URIs; we
/// emit a single entry for the pre-authorised-code grant. The body
/// carries the bare pre-auth code (single-use bearer secret) — see
/// `specs/impl_api_oidc.md` for the exposure window and the bridge
/// table that holds the secret server-side until first delivery.
#[derive(Debug, Serialize)]
pub struct CredentialOfferBody {
    pub credential_issuer: String,
    pub credential_configuration_ids: Vec<String>,
    pub grants: Value,
}

pub async fn credential_offer(
    State(state): State<AppState>,
    Path((issuer_id_str, offer_id_str)): Path<(String, String)>,
) -> Result<Json<CredentialOfferBody>, OidcError> {
    tracing::debug!(
        issuer_id = %issuer_id_str,
        offer_id = %offer_id_str,
        "credential offer fetch (wallet) requested",
    );

    let issuer_id = parse_issuer_id(&issuer_id_str)?;
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
    .await
    .map_err(map_credential_offer_lookup)?;

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

    let bare_code = persistence::oidc::offer_bridge::find_by_offer_id(&mut conn, &offer_id)
        .await?
        .ok_or_else(|| {
            // The offer is pending+unexpired but the bridge is gone.
            // This is an inconsistency (a pending offer should always
            // have a live bridge); 404 from the wallet's point of view
            // since we cannot honour the request.
            tracing::warn!(
                %offer_id,
                "pending offer has no bridge entry; treating as not found",
            );
            OidcError::NotFound
        })?;

    let base = state.config.issuer_base_url.trim_end_matches('/');
    let issuer_url = format!("{base}/i/{}", issuer_id.bare());

    let grants = json!({
        PRE_AUTHORIZED_GRANT_TYPE: {
            "pre-authorized_code": bare_code.as_str()
        }
    });

    Ok(Json(CredentialOfferBody {
        credential_issuer: issuer_url,
        credential_configuration_ids: vec![offer.vct],
        grants,
    }))
}

fn parse_issuer_id(raw: &str) -> Result<IssuerId, OidcError> {
    IssuerId::from_bare(raw).map_err(|err| OidcError::InvalidInput {
        details: format!("issuer_id path parameter: {err}"),
    })
}

fn parse_offer_id(raw: &str) -> Result<CredentialOfferId, OidcError> {
    CredentialOfferId::from_bare(raw).map_err(|err| OidcError::InvalidInput {
        details: format!("offer_id path parameter: {err}"),
    })
}

/// `find_by_id` on `credential_offers` returns
/// `PersistenceError::NotFound`; the default `From<PersistenceError>`
/// for `OidcError` already maps that to `NotFound`. This helper
/// exists to centralise the conversion in case the wallet path ever
/// needs to distinguish "wrong issuer" from "wrong offer" — today
/// it doesn't.
fn map_credential_offer_lookup(err: persistence::PersistenceError) -> OidcError {
    OidcError::from(err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_issuer_id_rejects_invalid_character() {
        assert!(matches!(
            parse_issuer_id("notValid0").unwrap_err(),
            OidcError::InvalidInput { .. }
        ));
    }

    #[test]
    fn parse_offer_id_rejects_invalid_character() {
        assert!(matches!(
            parse_offer_id("notValid0").unwrap_err(),
            OidcError::InvalidInput { .. }
        ));
    }
}
