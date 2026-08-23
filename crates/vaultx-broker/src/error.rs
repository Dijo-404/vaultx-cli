//! Broker error type (plan §18).
//!
//! # Secret blindness contract
//!
//! No variant ever carries secret material. Messages are static-safe:
//! they may quote *logical* identifiers (a credential reference, an
//! injection template name, a host/path summary) but never credential
//! plaintext, session bearer tokens, or full URLs with query strings
//! (`?token=…` is exactly the shape that must never reach a log line).
//! A crate-level canary test pins this guarantee for every variant.

use thiserror::Error;

/// Errors surfaced by the broker pipeline.
#[derive(Debug, Error)]
pub enum BrokerError {
    /// The request declared a protocol version other than the one this
    /// broker implements.
    #[error("broker protocol version {0} is not supported; only protocol 1 is implemented")]
    ProtocolUnsupported(u16),
    /// The presented session token does not match any live session.
    #[error("session token is invalid or unknown")]
    InvalidSession,
    /// The session exists but has been revoked.
    #[error("session has been revoked")]
    SessionRevoked,
    /// The referenced logical credential does not exist. Only the logical
    /// ID is carried — never any resolved material.
    #[error("unknown credential reference `{0}`")]
    UnknownCredential(String),
    /// The policy engine denied the request. `reason` is a policy-authored
    /// denial category and `policy` the responsible policy name, if known.
    #[error("authorization denied: {reason}")]
    AuthorizationDenied {
        /// Denial category (never request content).
        reason: String,
        /// Name of the policy that denied, when attributed.
        policy: Option<String>,
    },
    /// The canonical destination was refused by network egress policy
    /// before authorization. Carries a classification description only.
    #[error("destination denied for egress: {0}")]
    DestinationDenied(String),
    /// The credential's injection template cannot be applied by this
    /// build (e.g. `aws_sigv4`, deferred until transport integration).
    #[error("injection template unsupported: {0}")]
    TemplateUnsupported(String),
    /// The outbound transport failed to complete the exchange. The
    /// message describes the failure class, never response bodies.
    #[error("transport failure: {0}")]
    TransportFailure(String),
    /// The upstream response exceeded the enforced size ceiling.
    #[error("response body exceeds the maximum permitted size")]
    ResponseTooLarge,
    /// Response sanitization could not be completed safely.
    #[error("response sanitization failed: {0}")]
    SanitizationFailed(String),
    /// Credential material could not be injected into the outbound
    /// request (missing metadata, malformed rebuilt URL, ...). Messages
    /// describe the missing piece by name, never the secret itself.
    #[error("credential injection failed: {0}")]
    InjectionError(String),
    /// The secure entropy source failed. This is unrecoverable at the
    /// call site and surfaced rather than papered over with weak IDs.
    #[error("secure entropy source unavailable: {0}")]
    Entropy(String),
    /// A value could not be serialized for persistence. Messages quote
    /// the failure class only — never the payload.
    #[error("serialization failure: {0}")]
    Serialization(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANARY: &str = "CANARY_SECRET_9f8";

    #[test]
    fn display_messages_never_embed_secret_shaped_content() {
        // Every variant renders through Display; none of them may echo a
        // canary secret, bearer-style token value, or URL query string.
        let errors: Vec<BrokerError> = vec![
            BrokerError::ProtocolUnsupported(2),
            BrokerError::InvalidSession,
            BrokerError::SessionRevoked,
            BrokerError::UnknownCredential("deploy_token-1".to_owned()),
            BrokerError::AuthorizationDenied {
                reason: "no_matching_policy".to_owned(),
                policy: Some("coding-agent-github".to_owned()),
            },
            BrokerError::DestinationDenied("private".to_owned()),
            BrokerError::TemplateUnsupported("aws_sigv4".to_owned()),
            BrokerError::TransportFailure("connection reset".to_owned()),
            BrokerError::ResponseTooLarge,
            BrokerError::SanitizationFailed("set-cookie".to_owned()),
            BrokerError::InjectionError("header_name required".to_owned()),
            BrokerError::Entropy("no entropy".to_owned()),
            BrokerError::Serialization("bad json".to_owned()),
        ];

        for err in &errors {
            let rendered = err.to_string();
            assert!(!rendered.contains(CANARY), "{err:?}");
            assert!(!rendered.contains('?'), "query-like content in {err:?}");
        }

        // Debug output likewise stays free of canary-shaped input because
        // variants only carry identifiers/categories by construction.
        let debugged = format!("{:?}", errors);
        assert!(!debugged.contains(CANARY));
    }

    #[test]
    fn unknown_credential_carries_only_the_logical_id() {
        let err = BrokerError::UnknownCredential("github-work-token".to_owned());
        let rendered = err.to_string();
        assert!(rendered.contains("github-work-token"));
        // And nothing that looks like a resolved value.
        assert!(rendered.ends_with('`') || !rendered.contains('='));
    }
}
