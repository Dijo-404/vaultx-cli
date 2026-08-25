//! Errors surfaced by the control-plane API.
//!
//! Display strings are static and secret-free: no token, assertion, or
//! payload material is ever embedded.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use thiserror::Error;

/// Error type for store and handler failures.
#[derive(Debug, Error)]
pub enum ControlPlaneError {
    /// The addressed resource does not exist.
    #[error("not found")]
    NotFound,

    /// Credentials are missing, unknown, or invalid.
    #[error("unauthorized")]
    Unauthorized,

    /// Authenticated but not permitted (wrong token class or membership).
    #[error("forbidden")]
    Forbidden,

    /// Malformed request content.
    #[error("bad request: {0}")]
    BadRequest(&'static str),

    /// Device signature did not verify against the transmitted key.
    #[error("signature verification failed")]
    SignatureInvalid,

    /// Content hash disagrees with the object id or claimed hash.
    #[error("content hash mismatch")]
    HashMismatch,

    /// A ref-level disagreement that the caller must reconcile; carries a
    /// JSON detail body for the 409 response.
    #[error("conflict")]
    Conflict(serde_json::Value),

    /// Backend storage failure. Payload is a secret-free description.
    #[error("storage failure: {0}")]
    Storage(String),
}

impl ControlPlaneError {
    fn status(&self) -> StatusCode {
        match self {
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Unauthorized | Self::SignatureInvalid => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::HashMismatch => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Storage(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for ControlPlaneError {
    fn into_response(self) -> Response {
        let status = self.status();
        match self {
            // Conflict responses carry caller-actionable detail.
            Self::Conflict(detail) => (status, Json(detail)).into_response(),
            other => (
                status,
                Json(serde_json::json!({ "error": other.to_string() })),
            )
                .into_response(),
        }
    }
}
