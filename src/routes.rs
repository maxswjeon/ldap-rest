use axum::{extract, Json};
use serde::{Deserialize, Serialize};

use chrono::{offset::Utc, DateTime};

pub async fn index() -> Json<StatusResponse> {
    Json(StatusResponse { result: true })
}

#[derive(Deserialize)]
pub struct RequestJson {
    pub public_key: String,
    pub data: String,
    pub timestamp: DateTime<Utc>,
    pub signature: String,
}

#[derive(Serialize)]
pub struct StatusResponse {
    pub result: bool,
}

#[derive(Serialize)]
pub struct SuccessResponse {
    pub result: bool,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub result: bool,
    pub message: String,
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum ResponseJson {
    Success(SuccessResponse),
    Error(ErrorResponse),
}

pub async fn request(extract::Json(payload): extract::Json<RequestJson>) -> Json<ResponseJson> {
    Json(ResponseJson::Success(SuccessResponse { result: true }))
}
