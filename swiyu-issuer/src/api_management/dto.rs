use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Deserialize)]
pub struct CreateCredentialOfferRequest {
    pub vct: String,
    pub claims: Value,
    pub expires_in_seconds: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct CreateCredentialOfferResponse {
    pub id: String,
    pub pre_auth_code: String,
    pub offer_deeplink: String,
    pub expires_at: DateTime<Utc>,
}
