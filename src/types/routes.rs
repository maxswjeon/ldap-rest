use axum::{body::Body, extract::rejection::*, http::StatusCode, response::IntoResponse, Json};
use erased_serde::Serialize;
use thiserror::Error;

pub struct Response {
    pub status: StatusCode,
    pub body: Box<dyn Serialize>,
}

impl IntoResponse for Response {
    fn into_response(self) -> axum::http::Response<Body> {
        let mut res =
            axum::http::Response::new(Json(self.body.as_ref()).into_response().into_body());
        *res.status_mut() = self.status;
        res
    }
}

#[derive(serde::Serialize)]
pub struct ErrorResponse {
    pub result: bool,
    pub message: String,
}

#[derive(Debug, Error)]
pub enum RejectionError {
    #[error(transparent)]
    BytesExtractorRejection(#[from] BytesRejection),

    #[error(transparent)]
    StringExtractorRejection(#[from] StringRejection),

    #[error(transparent)]
    ExtensionExtractorRejection(#[from] ExtensionRejection),

    #[error(transparent)]
    BufferBodyRejection(#[from] FailedToBufferBody),

    #[error(transparent)]
    FormExtractorRejection(#[from] FormRejection),

    #[error(transparent)]
    HostExtractorRejection(#[from] HostRejection),

    #[error(transparent)]
    JsonExtractorRejection(#[from] JsonRejection),

    #[error(transparent)]
    MatchedPathExtractorRejection(#[from] MatchedPathRejection),

    #[error(transparent)]
    PathExtractorRejection(#[from] PathRejection),

    #[error(transparent)]
    QueryExtractorRejection(#[from] QueryRejection),

    #[error(transparent)]
    RawFormExtractorRejection(#[from] RawFormRejection),

    #[error(transparent)]
    RawPathParamsExtractorRejection(#[from] RawPathParamsRejection),
}

impl IntoResponse for RejectionError {
    fn into_response(self) -> axum::http::Response<Body> {
        let (status, text) = match self {
            Self::BytesExtractorRejection(rej) => (rej.status(), rej.body_text()),
            Self::StringExtractorRejection(rej) => (rej.status(), rej.body_text()),
            Self::ExtensionExtractorRejection(rej) => (rej.status(), rej.body_text()),
            Self::BufferBodyRejection(rej) => (rej.status(), rej.body_text()),
            Self::FormExtractorRejection(rej) => (rej.status(), rej.body_text()),
            Self::HostExtractorRejection(rej) => (rej.status(), rej.body_text()),
            Self::JsonExtractorRejection(rej) => (rej.status(), rej.body_text()),
            Self::MatchedPathExtractorRejection(rej) => (rej.status(), rej.body_text()),
            Self::PathExtractorRejection(rej) => (rej.status(), rej.body_text()),
            Self::QueryExtractorRejection(rej) => (rej.status(), rej.body_text()),
            Self::RawFormExtractorRejection(rej) => (rej.status(), rej.body_text()),
            Self::RawPathParamsExtractorRejection(rej) => (rej.status(), rej.body_text()),
        };

        let message = match text.is_empty() {
            true => text,
            false => status
                .canonical_reason()
                .unwrap_or_else(|| status.as_str())
                .to_string(),
        };

        Response {
            status,
            body: Box::new(ErrorResponse {
                result: false,
                message,
            }),
        }
        .into_response()
    }
}
