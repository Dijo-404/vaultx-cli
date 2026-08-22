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

use crate::error::BrokerError;
use crate::inject::OutboundRequest;

/// Raw result of one outbound exchange, prior to response sanitization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutedResponse {
    /// Upstream HTTP status code.
    pub status: u16,
    /// Upstream response headers as received.
    pub headers: Vec<(String, String)>,
    /// Upstream response body bytes.
    pub body: Vec<u8>,
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
