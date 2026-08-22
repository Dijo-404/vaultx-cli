//! Error type for the HTTP policy crate.
//!
//! No variant ever carries secret material: this crate is pure request
//! policy logic and never sees credential plaintext (see the crate-level
//! contract in [`crate`]).

use thiserror::Error;

use crate::netpolicy::Classification;

/// Errors surfaced by URL canonicalization, egress policy, header
/// filtering, redirect evaluation, and size/sanitization limits.
#[derive(Debug, Error)]
pub enum HttpPolicyError {
    /// The input string is not a syntactically valid URL, or a required
    /// component (e.g. host) is missing.
    #[error("invalid url: {0}")]
    InvalidUrl(String),
    /// The scheme is not `https`. Every other scheme — including `http`,
    /// `file`, and custom application schemes — is rejected by the
    /// canonicalizer.
    #[error("unsupported url scheme `{0}`; only https is allowed")]
    UnsupportedScheme(String),
    /// The authority carried userinfo (`user[:password]@`). Userinfo in
    /// URLs leaks credentials into logs and enables confusion attacks;
    /// it is never accepted.
    #[error("userinfo (`user:pass@`) is disallowed in urls")]
    UserInfoDisallowed,
    /// Reserved for transports that later opt in to explicit cleartext
    /// `http` for constrained environments (e.g. localhost dev mode).
    /// The canonicalizer itself always reports
    /// [`HttpPolicyError::UnsupportedScheme`] instead.
    #[error("insecure http scheme is disallowed")]
    InsecureSchemeDisallowed,
    /// An explicit port was present but outside `1..=65535`.
    #[error("invalid port `{0}`")]
    InvalidPort(String),
    /// A destination IP resolved to an address class denied by egress
    /// policy (loopback, link-local, private space, multicast,
    /// unspecified, or metadata service).
    #[error("destination address class is not permitted for egress: {0}")]
    PrivateDestination(Classification),
    /// A request header on the agent-controlled deny list was supplied.
    #[error("request header `{0}` may not be set by callers")]
    DisallowedHeader(String),
    /// A redirect target was refused (hop limit, scheme downgrade, or
    /// authorization failure). The reason is safe to surface.
    #[error("redirect denied: {0}")]
    RedirectDenied(String),
    /// A request body exceeded the configured ceiling. `limit` is the
    /// observed size and `max` the configured maximum.
    #[error("request body too large: {limit} bytes exceeds {max} byte limit")]
    BodyTooLarge {
        /// Observed body size in bytes.
        limit: u64,
        /// Configured maximum in bytes.
        max: u64,
    },
    /// A response body exceeded the configured ceiling. `limit` is the
    /// observed size and `max` the configured maximum.
    #[error("response body too large: {limit} bytes exceeds {max} byte limit")]
    ResponseTooLarge {
        /// Observed body size in bytes.
        limit: u64,
        /// Configured maximum in bytes.
        max: u64,
    },
    /// A header name or value contained characters outside the RFC 7230
    /// grammar (or a CR/LF/NUL injection attempt).
    #[error("invalid header value or name: {0}")]
    InvalidHeaderValue(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_messages_are_stable_and_secret_safe() {
        let cases = vec![
            HttpPolicyError::InvalidUrl("not a url".to_owned()),
            HttpPolicyError::UnsupportedScheme("ftp".to_owned()),
            HttpPolicyError::UserInfoDisallowed,
            HttpPolicyError::InsecureSchemeDisallowed,
            HttpPolicyError::InvalidPort("99999".to_owned()),
            HttpPolicyError::PrivateDestination(Classification::Loopback),
            HttpPolicyError::DisallowedHeader("authorization".to_owned()),
            HttpPolicyError::RedirectDenied("hop limit".to_owned()),
            HttpPolicyError::BodyTooLarge { limit: 10, max: 5 },
            HttpPolicyError::ResponseTooLarge { limit: 10, max: 5 },
            HttpPolicyError::InvalidHeaderValue("crlf".to_owned()),
        ];
        for err in &cases {
            assert!(!err.to_string().is_empty());
            // This crate must stay secret-blind; nothing in an error can
            // ever echo credential material.
            assert!(!err.to_string().to_lowercase().contains("hunter2"));
        }
        assert_eq!(
            HttpPolicyError::UnsupportedScheme("file".to_owned()).to_string(),
            "unsupported url scheme `file`; only https is allowed"
        );
        assert_eq!(
            HttpPolicyError::BodyTooLarge {
                limit: 300_000,
                max: 262_144
            }
            .to_string(),
            "request body too large: 300000 bytes exceeds 262144 byte limit"
        );
    }
}
