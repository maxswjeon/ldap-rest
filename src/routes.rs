use crate::{config::load_public_key, types::PublicKeyWrap};

use std::sync::Arc;

use axum::{extract, Json};

use axum_macros::debug_handler;
use base64ct::{Base64, Encoding};
use serde::{Deserialize, Serialize};

use chrono::{offset::Utc, DateTime, TimeDelta};
use p521::SecretKey;
use sha2::{Digest, Sha512};

pub struct AppState {
    pub key_public: String,
    pub key_private: SecretKey,
    pub authorized_keys: Vec<PublicKeyWrap>,
}

pub async fn public(extract::State(state): extract::State<Arc<AppState>>) -> String {
    state.key_public.clone()
}

#[derive(Deserialize)]
pub struct RequestJson {
    pub public_key: String,
    pub data: String,
    pub timestamp: DateTime<Utc>,
    pub signature: String,
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
pub enum ResponseJson {
    Success(SuccessResponse),
    Error(ErrorResponse),
}

#[debug_handler]
pub async fn request(
    extract::State(state): extract::State<Arc<AppState>>,
    extract::Json(payload): extract::Json<RequestJson>,
) -> Json<ResponseJson> {
    let allowed_window = TimeDelta::minutes(1);

    if Utc::now() - payload.timestamp > allowed_window {
        return Json(ResponseJson::Error(ErrorResponse {
            result: false,
            message: "Timestamp out of window".to_string(),
        }));
    }

    let key = match load_public_key(payload.public_key) {
        Ok(val) => val,
        Err(err) => {
            return Json(ResponseJson::Error(ErrorResponse {
                result: false,
                message: format!("{:?}", err),
            }));
        }
    };

    if !state.authorized_keys.contains(&key) {
        return Json(ResponseJson::Error(ErrorResponse {
            result: false,
            message: "Unauthorized".to_string(),
        }));
    }

    let mut signature_bytes = Vec::<u8>::with_capacity(payload.signature.len());
    let signature = match Base64::decode(payload.signature, &mut signature_bytes) {
        Ok(val) => val,
        Err(_) => {
            return Json(ResponseJson::Error(ErrorResponse {
                result: false,
                message: "Failed to decode signature".to_string(),
            }));
        }
    };

    let mut payload_bytes = Vec::<u8>::with_capacity(payload.data.len());
    let data = match Base64::decode(payload.data, &mut payload_bytes) {
        Ok(val) => val,
        Err(_) => {
            return Json(ResponseJson::Error(ErrorResponse {
                result: false,
                message: "Failed to decode data".to_string(),
            }));
        }
    };

    let mut hasher = Sha512::new();
    hasher.update(&data);
    hasher.update(payload.timestamp);
    let digest = hasher.finalize();

    Json(ResponseJson::Success(SuccessResponse { result: true }))
}
