use axum::Json;
use axum::extract::State;
use serde::Serialize;

use super::AppState;

#[derive(Serialize)]
pub struct MeResponse {
    pub id: String,
    pub tenant_name: String,
}

pub async fn get_me(State(state): State<AppState>) -> Json<MeResponse> {
    Json(MeResponse {
        id: state.config.dev_user_id.clone(),
        tenant_name: state.config.dev_tenant_name.clone(),
    })
}
