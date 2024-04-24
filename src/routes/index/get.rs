use axum::Json;
use serde::Serialize;

#[derive(Serialize)]
pub struct StatusResponse {
    pub result: bool,
}

pub async fn get() -> Json<StatusResponse> {
    Json(StatusResponse { result: true })
}
