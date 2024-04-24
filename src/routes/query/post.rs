use std::sync::Arc;

use axum::{extract, http::StatusCode};
use axum_extra::extract::WithRejection;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use ssh_key::{Algorithm, PublicKey, SshSig};

use crate::{
    types::{
        query::QueryCommand,
        routes::{ErrorResponse, RejectionError, Response},
    },
    AppState,
};

#[derive(Deserialize)]
pub struct QueryRequest {
    pub public_key: String,
    pub data: String,
    pub timestamp: i64,
    pub signature: String,
}

#[derive(Serialize)]
pub struct SignatureData {
    pub data: String,
    pub timestamp: i64,
    pub public_key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct QueryData {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub commands: Vec<QueryCommand>,
}

#[derive(Serialize)]
struct SuccessResponse {
    result: bool,
}

pub async fn post(
    extract::State(state): extract::State<Arc<AppState>>,
    WithRejection(extract::Json(payload), _): WithRejection<
        extract::Json<QueryRequest>,
        RejectionError,
    >,
) -> Response {
    let time_request = match DateTime::from_timestamp(payload.timestamp, 0) {
        Some(val) => val,
        None => {
            return Response {
                status: StatusCode::BAD_REQUEST,
                body: Box::new(ErrorResponse {
                    result: false,
                    message: "Invalid timestamp".to_string(),
                }),
            }
        }
    };

    if Utc::now() - time_request > chrono::Duration::minutes(5) {
        return Response {
            status: StatusCode::BAD_REQUEST,
            body: Box::new(ErrorResponse {
                result: false,
                message: "Timestamp is too old".to_string(),
            }),
        };
    }

    let padded_key = format!("ssh-ed25519 {} request", &payload.public_key).to_string();
    let public_key = match PublicKey::from_openssh(&padded_key) {
        Ok(val) => val,
        Err(err) => {
            return Response {
                status: StatusCode::BAD_REQUEST,
                body: Box::new(ErrorResponse {
                    result: false,
                    message: format!("Invalid public key: {:?}", err),
                }),
            };
        }
    };

    if public_key.algorithm() != Algorithm::Ed25519 {
        return Response {
            status: StatusCode::BAD_REQUEST,
            body: Box::new(ErrorResponse {
                result: false,
                message: "Invalid public key algorithm".to_string(),
            }),
        };
    }

    let authorized_keys = match state.authorized_keys.lock() {
        Ok(val) => val,
        Err(_) => {
            tracing::error!("Failed to acquire lock on authorized keys");
            return Response {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                body: Box::new(ErrorResponse {
                    result: false,
                    message: "Internal Server Error".to_string(),
                }),
            };
        }
    };

    if !authorized_keys
        .iter()
        .any(|entry| *entry.public_key() == public_key)
    {
        return Response {
            status: StatusCode::UNAUTHORIZED,
            body: Box::new(ErrorResponse {
                result: false,
                message: "Unauthorized".to_string(),
            }),
        };
    }

    let padded_signature = format!(
        "-----BEGIN SSH SIGNATURE-----\n{}\n-----END SSH SIGNATURE-----",
        &payload.signature
    )
    .to_string();
    let signature = match padded_signature.parse::<SshSig>() {
        Ok(val) => val,
        Err(err) => {
            return Response {
                status: StatusCode::BAD_REQUEST,
                body: Box::new(ErrorResponse {
                    result: false,
                    message: format!("Invalid signature: {:?}", err),
                }),
            };
        }
    };

    let signature_data = SignatureData {
        data: payload.data.clone(),
        timestamp: payload.timestamp,
        public_key: payload.public_key,
    };
    let message = match serde_json::to_string(&signature_data) {
        Ok(val) => val,
        Err(err) => {
            return Response {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                body: Box::new(ErrorResponse {
                    result: false,
                    message: format!("Failed to serialize payload: {:?}", err),
                }),
            };
        }
    };

    let namespace = dotenv::var("NAMESPACE").unwrap_or_else(|_| "ldap-rest".to_string());
    match public_key.verify(namespace.as_str(), message.as_bytes(), &signature) {
        Ok(()) => {}
        Err(err) => {
            return Response {
                status: StatusCode::BAD_REQUEST,
                body: Box::new(ErrorResponse {
                    result: false,
                    message: format!("Failed to verify signature: {:?}", err),
                }),
            };
        }
    };

    let queries = match serde_json::from_str::<Vec<QueryRequest>>(&payload.data) {
        Ok(val) => val,
        Err(err) => {
            return Response {
                status: StatusCode::BAD_REQUEST,
                body: Box::new(ErrorResponse {
                    result: false,
                    message: format!("Failed to parse request: {:?}", err),
                }),
            };
        }
    };

    Response {
        status: StatusCode::OK,
        body: Box::new(SuccessResponse { result: true }),
    }
}
