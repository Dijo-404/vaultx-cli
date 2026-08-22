//! Outbound transport seam (plan §18 "hardened HTTP client").
//!
//! The engine builds a fully authorized, credential-injected
//! [`OutboundRequest`] and hands it to this seam. **No real HTTP client
//! exists in this crate yet**: `reqwest` (or an equivalent) lands with
//! the IPC/server task that owns the broker process. Everything above the
//! wire — canonicalization, egress policy, authorization, injection,
//! sanitization — is complete and testable through fakes implementing
//! [`TransportExecutor`].
//!
//! # Contract for future implementations (DNS rebinding hook)
//!
//! A real executor must honor the rebinding contract from
//! `vaultx_http::netpolicy` before connecting: resolve DNS only after
//! policy approval, run
//! [`EgressGuard::recheck_resolved`](vaultx_http::EgressGuard::recheck_resolved)
//! over every returned address, and connect only to an address that
//! passed. The engine's pre-authorization host check is provisional for
//! hostnames; this re-check is what closes DNS rebinding. Redirects must
//! be re-authorized per hop (`vaultx_http::RedirectAuthorizer`) and
//! credentials must never travel to an unauthorized target.
//!
//! # Session-revocation window (documented TOCTOU)
//!
//! The engine validates the session once, before authorization and
//! injection; it does **not** re-check revocation between validation and
//! transport execution, and the executor has no session context to check.
//! A session revoked mid-flight therefore completes its single in-flight
//! request and is refused from the next one onward — a single-flight
//! time-of-check/time-of-use window. This is accepted for v1 because the
//! broker executes one synchronous pipeline per request locally; if
//! long-lived streaming exchanges arrive with the IPC layer, they must
//! either poll the [`SessionStore`](crate::session::SessionStore) for
//! revocation or carry a cancellation channel wired to it.

use crate::error::BrokerError;
use crate::inject::OutboundRequest;

/// Raw result of one outbound exchange, prior to response sanitization.
#[derive(Clone, PartialEq, Eq)]
pub struct ExecutedResponse {
    /// Upstream HTTP status code.
    pub status: u16,
    /// Upstream response headers as received.
    pub headers: Vec<(String, String)>,
    /// Upstream response body bytes.
    pub body: Vec<u8>,
}

impl std::fmt::Debug for ExecutedResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Manual implementation: upstream responses routinely carry
        // session cookies and token-bearing payloads. Debug shows the
        // status, header names with values redacted for known-sensitive
        // names, and the body as a byte count only.
        f.debug_struct("ExecutedResponse")
            .field("status", &self.status)
            .field(
                "headers",
                &self
                    .headers
                    .iter()
                    .map(|(name, value)| {
                        if is_sensitive_response_header(name) {
                            format!("{name}: [redacted]")
                        } else {
                            format!("{name}: {value}")
                        }
                    })
                    .collect::<Vec<String>>(),
            )
            .field("body_len_bytes", &self.body.len())
            .finish()
    }
}

/// Response headers whose values never belong in diagnostics.
fn is_sensitive_response_header(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    matches!(
        lowered.as_str(),
        "set-cookie" | "cookie" | "authorization" | "proxy-authorization" | "www-authenticate"
    )
}

/// Executes one authorized outbound request.
///
/// Implementations must be safe to share across threads and must perform
/// no authorization of their own — every decision has already been made
/// by the engine by the time this is called.
pub trait TransportExecutor: Send + Sync {
    /// Performs the exchange described by `outbound`.
    ///
    /// # Errors
    /// Returns [`BrokerError::TransportFailure`] describing the failure
    /// class; messages must never include request bodies, auth headers,
    /// or response payloads.
    fn execute(&self, outbound: &OutboundRequest) -> Result<ExecutedResponse, BrokerError>;
}
