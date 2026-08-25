//! Transport seam between the sync client and the control plane.
//!
//! The trait is intentionally HTTP-agnostic: production deployments back
//! it with a real client, while tests drive an in-process axum router.

use crate::error::SyncResultOf;

/// A single control-plane request. `json_body` carries the UTF-8 JSON
/// serialization of a protocol DTO when present.
#[derive(Clone, Debug)]
pub struct TransportRequest {
    /// HTTP method (`GET`, `POST`, `PUT`).
    pub method: &'static str,
    /// Path including the leading slash (e.g. `/projects/proj_x/refs/main`).
    pub path: String,
    /// Serialized JSON body, if any.
    pub json_body: Option<String>,
}

impl TransportRequest {
    /// A requestless `GET` for `path`.
    #[must_use]
    pub fn get(path: impl Into<String>) -> Self {
        Self {
            method: "GET",
            path: path.into(),
            json_body: None,
        }
    }

    /// A `POST` with a JSON body.
    #[must_use]
    pub fn post(path: impl Into<String>, json_body: String) -> Self {
        Self {
            method: "POST",
            path: path.into(),
            json_body: Some(json_body),
        }
    }

    /// A `PUT` with a JSON body.
    #[must_use]
    pub fn put(path: impl Into<String>, json_body: String) -> Self {
        Self {
            method: "PUT",
            path: path.into(),
            json_body: Some(json_body),
        }
    }
}

/// The control plane's response to one [`TransportRequest`].
#[derive(Clone, Debug)]
pub struct TransportResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response body; empty string when the server sent none.
    pub body: String,
}

impl TransportResponse {
    /// True for 2xx statuses.
    #[must_use]
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Parses the body as JSON of `T`.
    ///
    /// # Errors
    /// [`crate::SyncError::Protocol`] when decoding fails.
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> SyncResultOf<T> {
        serde_json::from_str(&self.body)
            .map_err(|_| crate::error::SyncError::Protocol("response decode"))
    }
}

/// Delivery abstraction over the control-plane REST surface. Native async
/// fn in trait; implementors must be callable from multiple tasks.
pub trait ControlPlaneTransport: Send + Sync {
    /// Sends `request`, returning the raw response envelope.
    ///
    /// # Errors
    /// [`crate::SyncError::Transport`] for delivery failures; HTTP-level
    /// rejections are returned as responses, not errors.
    fn send(
        &self,
        request: TransportRequest,
    ) -> impl std::future::Future<Output = SyncResultOf<TransportResponse>> + Send;
}
