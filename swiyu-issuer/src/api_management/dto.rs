use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Request body for creating a credential offer.
///
/// Submitted by a business application to
/// `POST /api/v1/issuers/{issuer_id}/credential-offers`. The `vct`
/// selects which JSON Schema validates `claims`; unknown values
/// return HTTP 400. `expires_in_seconds` is optional; the handler
/// applies a default and rejects values outside the configured
/// bounds. See `specs/impl_api_management.md` for the full
/// contract.
#[derive(Debug, Deserialize)]
pub struct CreateCredentialOfferRequest {
    pub vct: String,
    pub claims: Value,
    pub expires_in_seconds: Option<u32>,
}

/// Response body returned by `POST .../credential-offers` on
/// success (HTTP 201).
///
/// `pre_auth_code` is the **bare** OID4VCI secret returned to the
/// caller exactly once; only its hash is persisted, so this is the
/// only opportunity to capture it. `offer_deeplink` is an
/// `openid-credential-offer://` URI suitable for rendering as a
/// QR code or handing to the holder's wallet.
#[derive(Debug, Serialize)]
pub struct CreateCredentialOfferResponse {
    pub id: String,
    pub pre_auth_code: String,
    pub offer_deeplink: String,
    pub expires_at: DateTime<Utc>,
}

/// Response body returned by
/// `GET .../credential-offers/{offer_id}` on success (HTTP 200).
///
/// `state` is the offer's *observed* state: when an offer is
/// still stored as `Pending` past its `expires_at`, this field is
/// `"expired"` even though the database row has not been updated.
/// Deliberately omits any pre-auth-code field — the bare secret
/// was returned only at creation, and the stored hash is not
/// surfaced.
#[derive(Debug, Serialize)]
pub struct GetCredentialOfferResponse {
    pub id: String,
    pub issuer_id: String,
    pub vct: String,
    pub claims: Value,
    pub state: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub issued_at: Option<DateTime<Utc>>,
    pub cancelled_at: Option<DateTime<Utc>>,
}

/// Query parameters for `GET .../credential-offers`.
///
/// All fields are optional. `limit` is bounded at the handler; out-of-range
/// values yield `invalid_input`. `cursor` is opaque to clients — the handler
/// rejects anything it did not itself emit. `state` filters on the
/// *observed* projection: `expired` matches stored-`pending` rows past their
/// `expires_at`, and `pending` matches stored-`pending` rows still within it.
#[derive(Debug, Deserialize)]
pub struct ListCredentialOffersQuery {
    pub limit: Option<u32>,
    pub cursor: Option<String>,
    pub state: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ListCredentialOffersResponse {
    pub items: Vec<GetCredentialOfferResponse>,
    pub next_cursor: Option<String>,
}
