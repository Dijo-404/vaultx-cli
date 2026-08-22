//! The vaultx outbound request broker — the product's core differentiated
//! subsystem (plan §3, §18–§21).
//!
//! A brokered credential can be used by an agent **without the upstream
//! credential becoming part of the agent environment, prompt context,
//! tool output, or normal process-visible configuration.** The agent
//! speaks a small structured protocol ([`request`]); the engine runs the
//! §20 pipeline (parse → session auth → canonicalize → network policy →
//! authorize → resolve → inject → execute → sanitize → audit) and hands
//! back only sanitized data.
//!
//! # Layout
//!
//! - [`error`]: [`BrokerError`]; every variant is
//!   secret-blind by construction.
//! - [`request`]: protocol types ([`BrokerRequest`],
//!   [`BrokerResponse`], [`RequestId`]).
//! - [`session`]: bearer-token session authentication with verifier-hash
//!   storage and constant-time comparison (plan §25).
//! - [`inject`]: credential injection templates — plaintext touches only
//!   an [`OutboundRequest`] inside broker scope
//!   (plan §21; INV-018).
//! - [`credential`]: the resolution seam standing in for the encrypted
//!   vault until repository integration.
//! - [`transport`]: the outbound execution seam; the real hardened HTTP
//!   client lands with the IPC/server task.
//! - [`engine`]: [`BrokerEngine`], wiring all seams
//!   into the exact pipeline order.
//!
//! # Trust boundary
//!
//! This crate is a separate trust zone from the CLI/TUI: it is the only
//! place credential plaintext is ever resolved, and nothing here writes
//! secret material into errors, responses, or audit events. Audit output
//! goes through `vaultx-audit`, whose schema has no field capable of
//! carrying secrets.

pub mod credential;
pub mod engine;
pub mod error;
pub mod inject;
pub mod request;
pub mod session;
pub mod transport;

pub use credential::{CredentialSource, InMemoryCredentialSource};
pub use engine::{
    scrub_secret_patterns, BrokerDependencies, BrokerEngine, BrokerService, MAX_RESPONSE_BODY_BYTES,
};
pub use error::BrokerError;
pub use inject::{
    ApiKeyHeaderInjector, AwsSigv4Injector, BasicPasswordInjector, BearerInjector,
    CredentialInjector, CredentialMetadata, CustomStaticHeaderPlusSecretInjector,
    GithubBearerInjector, InjectionTemplateId, InjectorRegistry, OutboundRequest,
    QueryParameterInjector,
};
pub use request::{
    BrokerBody, BrokerRequest, BrokerResponse, Decision, RequestId, PROTOCOL_VERSION,
};
pub use session::{hash_token, AgentSessionRecord, InMemorySessionStore, SessionStore, TokenHash};
pub use transport::{ExecutedResponse, TransportExecutor};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_surface_is_reachable() {
        // Smoke test pinning the re-exports stay wired.
        assert_eq!(PROTOCOL_VERSION, 1);
        let registry = InjectorRegistry::new();
        assert_eq!(
            registry
                .get(InjectionTemplateId::Bearer)
                .map(CredentialInjector::template),
            Some(InjectionTemplateId::Bearer)
        );
        assert_eq!(MAX_RESPONSE_BODY_BYTES, 1024 * 1024);
    }
}
