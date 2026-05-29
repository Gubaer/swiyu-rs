use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::Value;

use super::AppState;
use crate::error::AppError;

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub limit: Option<u32>,
    pub cursor: Option<String>,
}

pub async fn list_credential_offers(
    State(state): State<AppState>,
    Path(issuer_id): Path<String>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, AppError> {
    let mut payload = state
        .mgmt_api
        .list_credential_offers(&issuer_id, query.limit, query.cursor.as_deref())
        .await?;
    strip_claims_from_items(&mut payload);
    Ok(Json(payload))
}

pub async fn get_credential_offer(
    State(state): State<AppState>,
    Path((issuer_id, offer_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    let payload = state
        .mgmt_api
        .get_credential_offer(&issuer_id, &offer_id)
        .await?;
    Ok(Json(payload))
}

// Forward the create response verbatim: it carries the one-time pre-auth code
// and deeplink, which the SPA can never re-fetch. Unlike the list endpoint, we
// strip nothing here.
pub async fn create_credential_offer(
    State(state): State<AppState>,
    Path(issuer_id): Path<String>,
    Json(body): Json<Value>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let payload = state
        .mgmt_api
        .create_credential_offer(&issuer_id, body)
        .await?;
    Ok((StatusCode::CREATED, Json(payload)))
}

// Drop the per-item `claims` blob from a list response so the SPA's table view
// is not paying for a field it does not display. A malformed upstream body
// (missing `items`, wrong shape) is left alone here — the existing gateway
// error mapping handles the contract violation upstream.
fn strip_claims_from_items(payload: &mut Value) {
    let Some(items) = payload.get_mut("items").and_then(Value::as_array_mut) else {
        return;
    };
    for item in items {
        if let Some(obj) = item.as_object_mut() {
            obj.remove("claims");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn strip_claims_removes_claims_from_each_item() {
        let mut payload = json!({
            "items": [
                {
                    "id": "offer_1",
                    "vct": "urn:demo",
                    "claims": { "name": "Alice", "age": 30 },
                    "state": "pending"
                },
                {
                    "id": "offer_2",
                    "vct": "urn:demo",
                    "claims": { "name": "Bob" },
                    "state": "issued"
                }
            ],
            "next_cursor": "abc"
        });

        strip_claims_from_items(&mut payload);

        assert_eq!(
            payload,
            json!({
                "items": [
                    { "id": "offer_1", "vct": "urn:demo", "state": "pending" },
                    { "id": "offer_2", "vct": "urn:demo", "state": "issued" }
                ],
                "next_cursor": "abc"
            })
        );
    }

    #[test]
    fn strip_claims_handles_empty_items() {
        let mut payload = json!({ "items": [], "next_cursor": null });
        strip_claims_from_items(&mut payload);
        assert_eq!(payload, json!({ "items": [], "next_cursor": null }));
    }

    #[test]
    fn strip_claims_is_noop_when_items_have_no_claims() {
        let mut payload = json!({
            "items": [ { "id": "offer_1", "state": "pending" } ],
            "next_cursor": null
        });
        let before = payload.clone();
        strip_claims_from_items(&mut payload);
        assert_eq!(payload, before);
    }

    #[test]
    fn strip_claims_is_noop_when_items_missing() {
        let mut payload = json!({ "next_cursor": null });
        let before = payload.clone();
        strip_claims_from_items(&mut payload);
        assert_eq!(payload, before);
    }
}
