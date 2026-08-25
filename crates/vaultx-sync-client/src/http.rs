//! [`HttpTransport`]: the ONE hardened reqwest-backed
//! [`ControlPlaneTransport`] (rustls only, redirects off, capped bodies,
//! bounded timeouts). The bearer token rides only in the Authorization
//! header and never appears in error strings or `Debug` output.
//!
//! Both the CLI and the TUI build their sync clients through this module
//! so neither surface can quietly regress a hardening knob.

use std::sync::Arc;
use std::time::Duration;

use crate::error::SyncError;
use crate::setup_error::{io_message, SyncSetupResult};
use crate::transport::{ControlPlaneTransport, TransportRequest, TransportResponse};

/// Outbound connect timeout (mirrors the broker transport).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Per-read timeout (mirrors the broker transport).
const READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Whole-request ceiling (mirrors the broker transport).
const TOTAL_TIMEOUT: Duration = Duration::from_secs(60);
/// Hard ceiling on any single control-plane response body.
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// [`ControlPlaneTransport`] backed by reqwest.
#[derive(Clone)]
pub struct HttpTransport {
    client: reqwest::Client,
    server: String,
    bearer: Arc<String>,
}

impl std::fmt::Debug for HttpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpTransport")
            .field("server", &self.server)
            .field("bearer", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl HttpTransport {
    /// Builds the hardened client for `server`, authenticating with
    /// `token`.
    ///
    /// # Errors
    /// [`crate::SyncSetupError::Io`] when the HTTP client cannot be built.
    pub fn new(server: &str, token: &str) -> SyncSetupResult<Self> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(READ_TIMEOUT)
            .timeout(TOTAL_TIMEOUT)
            .build()
            .map_err(|err| io_message(format!("cannot build HTTP client: {err}")))?;
        Ok(Self {
            client,
            server: server.trim_end_matches('/').to_owned(),
            bearer: Arc::new(token.to_owned()),
        })
    }

    fn url(&self, request: &TransportRequest) -> String {
        format!("{}{}", self.server, request.path)
    }
}

impl ControlPlaneTransport for HttpTransport {
    async fn send(&self, request: TransportRequest) -> Result<TransportResponse, SyncError> {
        let url = self.url(&request);
        let builder = match request.method {
            "GET" => self.client.get(&url),
            "POST" => self.client.post(&url),
            "PUT" => self.client.put(&url),
            _ => return Err(SyncError::Protocol("unsupported method")),
        };
        let mut outgoing = builder.bearer_auth(self.bearer.as_str());
        if let Some(body) = request.json_body {
            outgoing = outgoing
                .header("content-type", "application/json")
                .body(body);
        }
        let response = outgoing.send().await.map_err(|err| {
            // err Display carries method+URL only — headers (and therefore
            // the bearer token) are never embedded.
            SyncError::Transport(err.to_string())
        })?;
        let status = response.status().as_u16();
        // Cap the read so a hostile/misbehaving proxy cannot exhaust
        // memory with an unbounded body.
        let body = read_capped(response, MAX_RESPONSE_BYTES).await?;
        Ok(TransportResponse { status, body })
    }
}

/// Reads a response body up to `cap` bytes; anything larger is a
/// protocol error rather than an OOM.
async fn read_capped(mut response: reqwest::Response, cap: usize) -> Result<String, SyncError> {
    let mut bytes: Vec<u8> = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| SyncError::Transport(err.to_string()))?
    {
        if bytes.len() + chunk.len() > cap {
            return Err(SyncError::Protocol("response body exceeds size limit"));
        }
        bytes.extend_from_slice(&chunk);
    }
    String::from_utf8(bytes).map_err(|_| SyncError::Protocol("response body is not valid UTF-8"))
}
