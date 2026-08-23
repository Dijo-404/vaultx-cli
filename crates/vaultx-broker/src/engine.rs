//! The broker engine: the full §20 pipeline in one place.
//!
//! # Pipeline order (plan §19/§20 — do not reorder)
//!
//! ```text
//!  1. parse protocol version        → deny "protocol_unsupported"
//!  2. authenticate session          → deny "invalid_session"/"session_revoked"
//!  3. canonicalize URL              → deny "invalid_destination"
//!  4. DNS/network policy (literal)  → deny "destination_denied"
//!  5. authorization                 → policy Deny { reason, policy }
//!  6. resolve credential            → deny "credential_unavailable"
//!     (template + metadata + plaintext, decrypted in memory only)
//!  7. strip caller sensitive headers (INV-004), inject auth material
//!     inside broker scope only (INV-018)
//!  8. execute outbound              → deny "transport_failure"
//!  9. sanitize response             → deny "response_too_large"
//! 10. write audit event, return safe response
//! ```
//!
//! Every outcome writes exactly one audit event before the response
//! leaves the engine; audit carries a [`SafeDestinationSummary`]
//! (host/port/path only — never the query string) plus the actor
//! principal and credential logical reference.
//!
//! # Security invariants honored here
//!
//! * **INV-002/003** — the upstream credential never becomes part of the
//!   agent-visible request, response, errors, or audit trail. Plaintext
//!   exists only inside credential resolution and injection scope.
//! * **INV-004** — agent-supplied `Authorization`/`Proxy-Authorization`
//!   (and other sensitive headers) are stripped before injection;
//!   injected values cannot be overridden by caller input.
//! * **INV-017** — everything here is provider-neutral: destinations,
//!   credentials, and templates come from configuration/seams, never
//!   from provider-specific code paths.
//! * **INV-018** — credential plaintext is resolved and consumed strictly
//!   between steps 6 and 7; the [`SecretBytes`] buffer itself is dropped
//!   before transport execution. Scope caveat: *plaintext-derived*
//!   strings (the `Authorization` header value, the encoded query
//!   parameter for `query_parameter` templates) are ordinary heap data
//!   and persist non-zeroized through transport execution. That residual
//!   exposure is inherent to HTTP credential injection — every HTTP
//!   client holds rendered header values in flight — and is bounded by
//!   the broker process boundary, not by zeroization.
//!
//! # Shape
//!
//! [`BrokerService::execute_broker_request`] is synchronous per plan §45
//! for this stage; the async wrapper arrives with the IPC layer together
//! with the real transport implementation.

use std::collections::BTreeMap;
use std::sync::Arc;

use vaultx_audit::{
    AppendStore, AuditAction, AuditDecision, CapabilityName, CorrelationId, NewAuditEvent,
    SafeAuditMetadata, SafeDestinationSummary,
};
use vaultx_crypto::secret::SecretBytes;
use vaultx_http::{filter_request_headers, redact_headers, CanonicalUrl, EgressGuard};
use vaultx_policy::{
    Action, AuthorizationContext, AuthorizationDecision, AuthorizationRequest, Authorizer,
    Principal,
};
use vaultx_types::{CredentialRef, EnvironmentId, ProjectId, SessionId};

use crate::credential::CredentialSource;
use crate::error::BrokerError;
use crate::inject::{InjectorRegistry, OutboundRequest};
use crate::request::{BrokerRequest, BrokerResponse, Decision, RequestId, PROTOCOL_VERSION};
use crate::session::{AgentSessionRecord, SessionStore};
use crate::transport::TransportExecutor;

/// Hard ceiling on upstream response bodies delivered to agents
/// (1 MiB). Oversized responses are denied wholesale rather than
/// truncated, so an agent can never mistake a partial body for complete
/// data.
pub const MAX_RESPONSE_BODY_BYTES: usize = 1024 * 1024;

/// Response header redacted unconditionally from every proxied response:
/// upstream cookies are session state of the *upstream*, not something a
/// brokered agent should ever receive.
const ALWAYS_REDACTED_RESPONSE_HEADERS: [&str; 1] = ["set-cookie"];

/// Static actor used for audit events emitted before session validation
/// could bind a real identity.
const UNAUTHENTICATED_ACTOR: &str = "agent:unknown";

/// Denial reason carried by responses when the audit store rejects the
/// event for an outcome. HTTP 500: the broker itself is degraded.
pub const AUDIT_WRITE_FAILED_REASON: &str = "audit_write_failed";

/// Truncates a denial reason to the audit schema's byte budget at a
/// UTF-8 character boundary, so foreign [`Authorizer`] implementations
/// cannot crash the pipeline with oversized categories.
fn bounded_reason(reason: &str) -> String {
    let max = vaultx_audit::AuditDecision::MAX_DENY_REASON_BYTES;
    if reason.len() <= max {
        return reason.to_owned();
    }
    let mut end = max;
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    reason[..end].to_owned()
}

/// The response returned whenever an audit append fails, regardless of
/// what the underlying decision was: denial of service is preferable to
/// unauditable success or silently dropped deny records.
fn audit_write_failed_response(request_id: RequestId) -> BrokerResponse {
    BrokerResponse {
        request_id,
        status: 500,
        headers: Vec::new(),
        body: Vec::new(),
        decision: Decision::Deny {
            reason: AUDIT_WRITE_FAILED_REASON.to_owned(),
            policy: None,
        },
    }
}

/// Secret-shaped token patterns scrubbed from response bodies as
/// defense-in-depth (plan §20 "global secret-pattern redaction").
///
/// Each entry is `(prefix, minimum alphanumeric run after prefix)`. A
/// match replaces the matched span with `[redacted]`. Best-effort by
/// design: it catches accidental echo in text payloads but cannot catch
/// transformed encodings, and must never be treated as the primary
/// protection mechanism (policy is).
///
/// Two prefixes get shape-aware matchers instead of a plain run:
/// `AKIA…` keys are fixed-width with a restricted charset, and
/// `github_pat_…` fine-grained tokens embed an internal `_` separator —
/// matching only the leading alphanumeric run would redact the 22-char
/// id while leaving the ~59-char secret tail in place.
const BODY_SCRUB_RULES: [(&str, usize); 4] = [
    // GitHub classic personal access tokens (`ghp_` + 36 chars).
    ("ghp_", 36),
    // GitHub fine-grained PATs (`github_pat_<22+ alnum>_<59-char tail>`).
    ("github_pat_", FINE_GRAINED_PAT_ID_MIN),
    // OpenAI-style API keys (`sk-` + 20+ chars).
    ("sk-", 20),
    // AWS access key ids (`AKIA` + exactly 16 uppercase/digit chars).
    ("AKIA", 16),
];

/// Minimum length of the alphanumeric id segment of a fine-grained PAT.
const FINE_GRAINED_PAT_ID_MIN: usize = 22;
/// Minimum accepted length of the underscore-containing tail segment.
const FINE_GRAINED_PAT_TAIL_MIN: usize = 20;

fn ascii_alnum_run(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .take_while(|byte| byte.is_ascii_alphanumeric())
        .count()
}

/// End offset of an AWS-style key id following the `AKIA` prefix, when
/// the next sixteen bytes are all uppercase ASCII letters or digits.
fn aws_key_id_run(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 16 {
        return None;
    }
    bytes[..16]
        .iter()
        .all(|byte| byte.is_ascii_digit() || byte.is_ascii_uppercase())
        .then_some(16)
}

/// Total span following the `github_pat_` prefix that constitutes one
/// fine-grained token: an alphanumeric id of [`FINE_GRAINED_PAT_ID_MIN`]+
/// characters, then optionally `_` plus a `[A-Za-z0-9_]{`[`FINE_GRAINED_
/// PAT_TAIL_MIN`]`,}` tail. Without the separator the plain-run rule
/// applies (the whole alnum run is the match); with it, the tail — which
/// contains underscores and would otherwise split the run — is consumed
/// too. Returns `None` when even the id segment is too short.
fn fine_grained_pat_span(bytes: &[u8]) -> Option<usize> {
    let id_len = ascii_alnum_run(bytes);
    if id_len < FINE_GRAINED_PAT_ID_MIN {
        return None;
    }
    let after_id = &bytes[id_len..];
    match after_id.first() {
        Some(b'_') => {
            let tail_len = after_id[1..]
                .iter()
                .take_while(|byte| byte.is_ascii_alphanumeric() || **byte == b'_')
                .count();
            if tail_len >= FINE_GRAINED_PAT_TAIL_MIN {
                Some(id_len + 1 + tail_len)
            } else {
                // Separator present but the tail is short: still redact
                // the qualifying id segment (over-redact, never under).
                Some(id_len)
            }
        }
        _ => Some(id_len),
    }
}

/// Replaces recognized secret-shaped spans with `[redacted]`.
///
/// Hand-rolled byte scanner (no regex dependency): linear scan, at each
/// position attempt the fixed prefixes, and on a qualifying match emit
/// the sentinel and jump past the matched span.
#[must_use]
pub fn scrub_secret_patterns(body: &[u8]) -> Vec<u8> {
    const REDACTED: &[u8] = b"[redacted]";
    let mut out = Vec::with_capacity(body.len());
    let mut index = 0;
    'scan: while index < body.len() {
        let rest = &body[index..];
        for (prefix, min_run) in BODY_SCRUB_RULES {
            let prefix_bytes = prefix.as_bytes();
            if !rest.starts_with(prefix_bytes) {
                continue;
            }
            // Shape-aware matchers for prefixes whose real-world tokens
            // embed separators; every other rule matches a plain alnum
            // run of the required minimum length.
            let run_len = if prefix == "AKIA" {
                match aws_key_id_run(&rest[prefix_bytes.len()..]) {
                    Some(len) => len,
                    None => continue,
                }
            } else if prefix == "github_pat_" {
                match fine_grained_pat_span(&rest[prefix_bytes.len()..]) {
                    Some(len) => len,
                    None => continue,
                }
            } else {
                ascii_alnum_run(&rest[prefix_bytes.len()..])
            };
            if run_len >= min_run {
                out.extend_from_slice(REDACTED);
                index += prefix_bytes.len() + run_len;
                continue 'scan;
            }
        }
        out.push(body[index]);
        index += 1;
    }
    out
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// Wiring for [`BrokerEngine`]. All seams are shared references so the
/// engine itself is cheap to share across threads.
pub struct BrokerDependencies {
    /// Policy evaluation boundary (deny-by-default).
    pub authorizer: Arc<dyn Authorizer>,
    /// Session authentication boundary.
    pub sessions: Arc<dyn SessionStore>,
    /// Credential resolution boundary (vault stand-in until integration).
    pub credentials: Arc<dyn CredentialSource>,
    /// Injection template registry (built-ins preloaded).
    pub injectors: Arc<InjectorRegistry>,
    /// Outbound transport seam (real client lands with IPC task).
    pub transport: Arc<dyn TransportExecutor>,
    /// Append-only audit sink; every outcome is recorded here.
    pub audit: Arc<dyn AppendStore>,
    /// Project whose policies/vault this broker instance serves.
    pub project: ProjectId,
    /// Whether private/loopback/link-local destinations may be contacted.
    /// Metadata-service endpoints are denied regardless (hard invariant).
    pub egress_allow_private: bool,
}

/// Provider-neutral outbound request broker core (plan §3).
#[derive(Clone)]
pub struct BrokerEngine {
    authorizer: Arc<dyn Authorizer>,
    sessions: Arc<dyn SessionStore>,
    credentials: Arc<dyn CredentialSource>,
    injectors: Arc<InjectorRegistry>,
    transport: Arc<dyn TransportExecutor>,
    audit: Arc<dyn AppendStore>,
    project: ProjectId,
    egress_guard: EgressGuard,
}

impl BrokerEngine {
    /// Assembles the engine from its dependencies.
    #[must_use]
    pub fn new(deps: BrokerDependencies) -> Self {
        Self {
            authorizer: deps.authorizer,
            sessions: deps.sessions,
            credentials: deps.credentials,
            injectors: deps.injectors,
            transport: deps.transport,
            audit: deps.audit,
            project: deps.project,
            egress_guard: EgressGuard::new(deps.egress_allow_private),
        }
    }

    /// Actor recorded on audit events when no authenticated identity is
    /// available yet. Uses the presented value only after confirming it
    /// parses as a session id — the raw bearer token itself is never
    /// echoed into audit output.
    fn unauthenticated_actor(req: &BrokerRequest) -> Principal {
        SessionId::parse(&req.session_token)
            .map(|id| format!("session:{id}"))
            .ok()
            .and_then(|value| Principal::parse(&value).ok())
            .unwrap_or_else(|| {
                Principal::parse(UNAUTHENTICATED_ACTOR).expect("static principal parses")
            })
    }

    fn destination_summary(canonical: &CanonicalUrl) -> Option<SafeDestinationSummary> {
        // IP-literal or over-long hosts fail the audit summary grammar;
        // such events simply carry no destination rather than failing a
        // decision that was already made correctly.
        SafeDestinationSummary::new(
            canonical.host(),
            canonical.port_or_default(),
            &canonical.path(),
        )
        .ok()
    }

    /// Shared denial path: writes the deny audit event, then builds the
    /// wire denial response. Audit-write failure does not change the
    /// denial outcome (the request was already refused); it is surfaced
    /// nowhere because there is no secret-safe channel for it here.
    #[allow(clippy::too_many_arguments)]
    fn deny(
        &self,
        request_id: RequestId,
        correlation_id: &CorrelationId,
        actor: Principal,
        environment: Option<EnvironmentId>,
        credential: Option<CredentialRef>,
        destination: Option<SafeDestinationSummary>,
        capability: Option<CapabilityName>,
        method: &str,
        reason: &str,
        policy: Option<String>,
    ) -> BrokerResponse {
        let mut metadata = SafeAuditMetadata::default();
        let _ = metadata.try_insert("http.method", method);
        let _ = metadata.try_insert("stage.reason", reason);
        // Attribute the deciding policy when the authorization stage
        // identified one. "policy" passes the metadata key rules (it is
        // neither sensitive nor malformed); a foreign policy name that
        // somehow fails validation is dropped rather than failing the
        // audit write of an already-made decision.
        if let Some(name) = &policy {
            let _ = metadata.try_insert("policy", name);
        }
        let event = NewAuditEvent {
            correlation_id: correlation_id.clone(),
            actor,
            project: self.project.clone(),
            environment,
            action: AuditAction::HttpRequest,
            // Foreign `Authorizer` implementations may produce reasons of
            // arbitrary length; degrade to a truncated category instead
            // of failing the audit write (or panicking).
            decision: AuditDecision::Deny {
                reason: bounded_reason(reason),
            },
            credential,
            destination,
            capability,
            policy_ids: Vec::new(),
            metadata,
        };
        // Fail-closed on every outcome: an unwritable audit record is a
        // broker failure, not a detail to swallow. For deny outcomes this
        // *upgrades* the response severity (500) without leaking any new
        // information; for allows it prevents undetected data delivery.
        match self.audit.append(event) {
            Ok(_) => BrokerResponse::denied(request_id, reason, policy),
            Err(_) => audit_write_failed_response(request_id),
        }
    }

    /// Builds the authorization query from canonical request parts.
    ///
    /// The context is assembled exclusively from the canonical URL and
    /// the validated body length — raw caller strings never reach policy.
    fn authorization_request(
        &self,
        req: &BrokerRequest,
        actor: &Principal,
        canonical: &CanonicalUrl,
        environment: Option<EnvironmentId>,
    ) -> AuthorizationRequest {
        let query: BTreeMap<String, String> = canonical.query_pairs().into_iter().collect();
        AuthorizationRequest {
            principal: actor.clone(),
            action: Action::HttpRequest,
            resource: req.credential.clone(),
            context: AuthorizationContext {
                host: canonical.host().to_owned(),
                method: req.method,
                path: canonical.path(),
                query,
                body_len_bytes: req.body.wire_len_bytes(),
                environment,
            },
        }
    }

    /// Resolves template, metadata, and plaintext for one credential.
    /// Any failure collapses to the same external denial so callers can
    /// not distinguish which resolution step leaked existence.
    fn resolve_credential(
        &self,
        credential: &CredentialRef,
        environment: &EnvironmentId,
    ) -> Result<
        (
            crate::inject::InjectionTemplateId,
            crate::inject::CredentialMetadata,
            SecretBytes,
        ),
        BrokerError,
    > {
        let template = self
            .credentials
            .template_for_in_env(credential, environment)
            .map_err(|_| BrokerError::UnknownCredential(credential.to_string()))?;
        let metadata = self
            .credentials
            .metadata_for(credential)
            .map_err(|_| BrokerError::UnknownCredential(credential.to_string()))?;
        let secret = self
            .credentials
            .resolve(credential, environment)
            .map_err(|_| BrokerError::UnknownCredential(credential.to_string()))?;
        Ok((template, metadata, secret))
    }

    /// Runs the §20 pipeline end-to-end. See the module documentation
    /// for the exact stage order and their denial reasons.
    fn execute_pipeline(&self, req: BrokerRequest) -> BrokerResponse {
        // Identity/correlation bootstrap. Both fallbacks exist solely to
        // keep the service signature infallible under entropy failure;
        // they are deterministic, non-secret, and flagged in tests.
        let request_id =
            RequestId::generate().unwrap_or_else(|_| RequestId::deterministic_fallback());
        let correlation_id = CorrelationId::generate().unwrap_or_else(|_| {
            CorrelationId::parse(request_id.as_str()).expect("request id satisfies grammar")
        });
        // The hint is informational only: parsed into a capability name
        // for audit ergonomics, never consulted for authorization.
        let capability = req
            .capability_hint
            .as_deref()
            .and_then(|hint| CapabilityName::parse(hint).ok());

        // Stage 1 — protocol version gate.
        if req.protocol != PROTOCOL_VERSION {
            return self.deny(
                request_id,
                &correlation_id,
                Self::unauthenticated_actor(&req),
                None,
                Some(req.credential),
                None,
                capability,
                req.method.as_str(),
                "protocol_unsupported",
                None,
            );
        }

        // Stage 2 — session authentication (verifier hash compare).
        let record: AgentSessionRecord = match self.sessions.validate(&req.session_token) {
            Ok(record) => record,
            Err(BrokerError::SessionRevoked) => {
                return self.deny(
                    request_id,
                    &correlation_id,
                    Self::unauthenticated_actor(&req),
                    None,
                    Some(req.credential),
                    None,
                    capability,
                    req.method.as_str(),
                    "session_revoked",
                    None,
                );
            }
            Err(_) => {
                return self.deny(
                    request_id,
                    &correlation_id,
                    Self::unauthenticated_actor(&req),
                    None,
                    Some(req.credential),
                    None,
                    capability,
                    req.method.as_str(),
                    "invalid_session",
                    None,
                );
            }
        };
        // Authorization identity is the *agent* principal carried by the
        // validated session record, not the session id: policies are
        // authored against agent identities (plan §23) and the session
        // proves possession of the agent's identity.
        let actor = Principal::parse(&format!("agent:{}", record.agent))
            .expect("agent principals always parse");
        let environment = record.environment;

        // Stage 3 — canonicalization (scheme/host/port/path normalization;
        // http:// and friends already die here).
        let canonical = match CanonicalUrl::parse(&req.url) {
            Ok(canonical) => canonical,
            Err(_) => {
                return self.deny(
                    request_id,
                    &correlation_id,
                    actor,
                    Some(environment),
                    Some(req.credential),
                    None,
                    capability,
                    req.method.as_str(),
                    "invalid_destination",
                    None,
                );
            }
        };
        let destination = Self::destination_summary(&canonical);

        // Stage 4 — network egress gate on literal hosts. Hostnames pass
        // provisionally; the transport re-checks resolved addresses
        // post-DNS (see transport.rs contract). No `policy` attribution:
        // this denial precedes policy evaluation, and the §19 response
        // field carries policy identifiers only.
        if self.egress_guard.check_host(canonical.host()).is_err() {
            return self.deny(
                request_id,
                &correlation_id,
                actor,
                Some(environment),
                Some(req.credential),
                destination,
                capability,
                req.method.as_str(),
                "destination_denied",
                None,
            );
        }

        // Stage 5 — authorization against the canonical request plus
        // policy context (capability_hint deliberately absent).
        let authz = self.authorization_request(&req, &actor, &canonical, Some(environment.clone()));
        let allowed_policy: Option<vaultx_types::PolicyName> =
            match self.authorizer.authorize(&authz) {
                AuthorizationDecision::Allow { policy } => Some(policy),
                AuthorizationDecision::Deny { reason, policy } => {
                    return self.deny(
                        request_id,
                        &correlation_id,
                        actor,
                        Some(environment),
                        Some(req.credential),
                        destination,
                        capability,
                        req.method.as_str(),
                        &reason.to_string(),
                        policy.map(|name| name.to_string()),
                    );
                }
            };

        // Stage 6 — resolve credential (template, metadata, plaintext).
        let (template, metadata, secret) =
            match self.resolve_credential(&req.credential, &environment) {
                Ok(resolved) => resolved,
                Err(_) => {
                    return self.deny(
                        request_id,
                        &correlation_id,
                        actor,
                        Some(environment),
                        Some(req.credential),
                        destination,
                        capability,
                        req.method.as_str(),
                        "credential_unavailable",
                        None,
                    );
                }
            };

        // Stage 7 — strip agent-controlled sensitive headers, then inject
        // inside broker scope. INV-004: whatever the caller presented in
        // `authorization`, it is gone by now; INV-018: `secret` dies at
        // the end of this block.
        let (safe_headers, _rejected_names) = filter_request_headers(&req.headers);
        let mut outbound = OutboundRequest {
            canonical_url: canonical,
            method: req.method,
            headers: safe_headers,
            body: req.body,
        };
        let injection_result =
            self.injectors
                .apply_for(template, &mut outbound, &secret, &metadata);
        drop(secret);
        if let Err(injection_error) = injection_result {
            let reason = match &injection_error {
                BrokerError::TemplateUnsupported(_) => "template_unsupported",
                _ => "injection_failed",
            };
            return self.deny(
                request_id,
                &correlation_id,
                actor,
                Some(environment),
                Some(req.credential),
                destination,
                capability,
                req.method.as_str(),
                reason,
                None,
            );
        }

        // Stage 8 — execute the authorized outbound request.
        let executed = match self.transport.execute(&outbound) {
            Ok(executed) => executed,
            Err(_) => {
                return self.deny(
                    request_id,
                    &correlation_id,
                    actor,
                    Some(environment),
                    Some(req.credential),
                    destination,
                    capability,
                    req.method.as_str(),
                    "transport_failure",
                    None,
                );
            }
        };

        // Stage 9 — sanitize: size ceiling first, then header redaction
        // and best-effort secret-pattern scrubbing.
        if executed.body.len() > MAX_RESPONSE_BODY_BYTES {
            return self.deny(
                request_id,
                &correlation_id,
                actor,
                Some(environment),
                Some(req.credential),
                destination,
                capability,
                req.method.as_str(),
                "response_too_large",
                None,
            );
        }
        let sanitized_headers = redact_headers(
            &executed.headers,
            &ALWAYS_REDACTED_RESPONSE_HEADERS
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<String>>(),
        );
        let sanitized_body = scrub_secret_patterns(&executed.body);

        // Stage 10 — audit precedes delivery; without a written event the
        // response fails closed.
        let mut audit_metadata = SafeAuditMetadata::default();
        let _ = audit_metadata.try_insert("http.method", req.method.as_str());
        let _ = audit_metadata.try_insert("http.status", &executed.status.to_string());
        if let Some(policy) = &allowed_policy {
            let _ = audit_metadata.try_insert("policy", policy.as_str());
        }
        let appended = self.audit.append(NewAuditEvent {
            correlation_id: correlation_id.clone(),
            actor: actor.clone(),
            project: self.project.clone(),
            environment: Some(environment),
            action: AuditAction::HttpRequest,
            decision: AuditDecision::Allow,
            credential: Some(req.credential),
            destination,
            capability,
            policy_ids: Vec::new(),
            metadata: audit_metadata,
        });
        if appended.is_err() {
            return audit_write_failed_response(request_id);
        }

        BrokerResponse {
            request_id,
            status: executed.status,
            headers: sanitized_headers,
            body: sanitized_body,
            decision: Decision::Allow,
        }
    }
}

/// Synchronous broker surface (async wrapper arrives with the IPC layer).
pub trait BrokerService {
    /// Executes one brokered request through the full pipeline.
    fn execute_broker_request(&self, req: BrokerRequest) -> BrokerResponse;
}

impl BrokerService for BrokerEngine {
    fn execute_broker_request(&self, req: BrokerRequest) -> BrokerResponse {
        self.execute_pipeline(req)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::InMemoryCredentialSource;
    use crate::inject::{CredentialMetadata, InjectionTemplateId};
    use crate::request::BrokerBody;
    use crate::session::InMemorySessionStore;
    use crate::transport::ExecutedResponse;
    use std::sync::Mutex;
    use vaultx_audit::{AuditFilter, JsonlAppendStore};
    use vaultx_policy::{parse_policy_yaml, HttpMethod, RuleEngine};
    use vaultx_types::{AgentId, EnvironmentId};

    const SECRET_CANARY: &str = "CANARY_BROKER_SECRET_9f8";
    /// A `ghp_`-shaped token that appears in an upstream response body and
    /// must be scrubbed before delivery (36+ alnum chars after the prefix).
    const RESPONSE_TOKEN: &str = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ab";
    /// Agent identity every standard-fixture session is created for;
    /// policies are authored against this principal (plan §23).
    const FIXTURE_AGENT_ID: &str = "agent_coding";

    // -- fixtures ------------------------------------------------------------

    #[derive(Clone, Default)]
    struct CapturingTransport {
        captured: Arc<Mutex<Vec<OutboundRequest>>>,
        response: Option<ExecutedResponse>,
        fail: bool,
    }

    impl CapturingTransport {
        fn with_response(status: u16, headers: Vec<(String, String)>, body: &[u8]) -> Self {
            Self {
                captured: Arc::new(Mutex::new(Vec::new())),
                response: Some(ExecutedResponse {
                    status,
                    headers,
                    body: body.to_vec(),
                }),
                fail: false,
            }
        }

        fn failing() -> Self {
            Self {
                captured: Arc::new(Mutex::new(Vec::new())),
                response: None,
                fail: true,
            }
        }

        fn last(&self) -> OutboundRequest {
            self.captured
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .last()
                .cloned()
                .expect("transport captured an outbound request")
        }
    }

    impl TransportExecutor for CapturingTransport {
        fn execute(&self, outbound: &OutboundRequest) -> Result<ExecutedResponse, BrokerError> {
            self.captured
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(outbound.clone());
            if self.fail {
                return Err(BrokerError::TransportFailure(
                    "connection refused".to_owned(),
                ));
            }
            Ok(self.response.clone().expect("fixture response configured"))
        }
    }

    /// Append store that rejects every write — simulates a degraded audit
    /// sink so tests can pin the engine's fail-closed behavior.
    struct FailingAuditStore;

    impl AppendStore for FailingAuditStore {
        fn append(
            &self,
            _event: NewAuditEvent,
        ) -> Result<vaultx_audit::AuditEvent, vaultx_audit::AuditError> {
            Err(vaultx_audit::AuditError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "forced failure",
            )))
        }

        fn latest_hash(&self) -> Result<Option<String>, vaultx_audit::AuditError> {
            Ok(None)
        }

        fn verify_chain(&self) -> Result<(), vaultx_audit::AuditError> {
            Ok(())
        }

        fn query(
            &self,
            _filter: &vaultx_audit::AuditFilter,
        ) -> Result<Vec<vaultx_audit::AuditEvent>, vaultx_audit::AuditError> {
            Ok(Vec::new())
        }
    }

    struct Fixture {
        engine: BrokerEngine,
        sessions: Arc<InMemorySessionStore>,
        credentials: Arc<InMemoryCredentialSource>,
        transport: CapturingTransport,
        audit: Arc<JsonlAppendStore>,
        _audit_dir: tempfile::TempDir,
        raw_token: String,
        session_id: SessionId,
    }

    fn policy_yaml(name: &str, principal: &str, credential: &str) -> String {
        format!(
            "name: {name}\n\
             principal: \"{principal}\"\n\
             credential: {credential}\n\
             http:\n  \
             hosts: [api.github.com]\n  \
             allow:\n    - methods: [GET]\n      paths: [/repos/acme/backend/**]\n  \
             deny:\n    - methods: [DELETE]\n      paths: [\"/**\"]\n"
        )
    }

    fn standard_fixture(transport: CapturingTransport, allow_private: bool) -> Fixture {
        let dir = tempfile::tempdir().expect("temp dir");
        let audit = Arc::new(JsonlAppendStore::open(dir.path().join("audit.jsonl")));
        let sessions = Arc::new(InMemorySessionStore::new());
        let credentials = Arc::new(InMemoryCredentialSource::new());

        // Credentials the fixture policies reference. `ghost-token` is
        // deliberately *not* registered so its policy authorizes but the
        // resolution stage fails.
        credentials.insert(
            CredentialRef::parse("github-work-token").unwrap(),
            SecretBytes::from_bytes(SECRET_CANARY.as_bytes()),
            InjectionTemplateId::GithubBearer,
            CredentialMetadata::default(),
        );
        credentials.insert(
            CredentialRef::parse("sigv4-token").unwrap(),
            SecretBytes::from_bytes(b"AKIDEXAMPLE"),
            InjectionTemplateId::AwsSigv4,
            CredentialMetadata::default(),
        );
        // api_key_header without the required header_name → injection error.
        credentials.insert(
            CredentialRef::parse("broken-api-key").unwrap(),
            SecretBytes::from_bytes(b"keyvalue"),
            InjectionTemplateId::ApiKeyHeader,
            CredentialMetadata::default(),
        );
        let query_meta = CredentialMetadata {
            query_param_name: Some("token".to_owned()),
            ..CredentialMetadata::default()
        };
        credentials.insert(
            CredentialRef::parse("query-token").unwrap(),
            SecretBytes::from_bytes(b"querysecret"),
            InjectionTemplateId::QueryParameter,
            query_meta,
        );

        let (session_id, raw_token) = sessions
            .create(
                &AgentId::parse(FIXTURE_AGENT_ID).unwrap(),
                &EnvironmentId::parse("env_development").unwrap(),
            )
            .expect("session created");
        let principal = format!("agent:{FIXTURE_AGENT_ID}");
        let documents = [
            ("coding-agent-github", "github-work-token"),
            ("ghost-cred-policy", "ghost-token"),
            ("sigv4-agent", "sigv4-token"),
            ("broken-api-key-agent", "broken-api-key"),
            ("query-agent", "query-token"),
        ]
        .map(|(name, credential)| {
            parse_policy_yaml(&policy_yaml(name, &principal, credential)).expect("valid policy")
        });
        let authorizer = RuleEngine::from_documents(documents).expect("fixture policies compile");

        let engine = BrokerEngine::new(BrokerDependencies {
            authorizer: Arc::new(authorizer),
            sessions: sessions.clone(),
            credentials: credentials.clone(),
            injectors: Arc::new(InjectorRegistry::new()),
            transport: Arc::new(transport.clone()),
            audit: audit.clone(),
            project: ProjectId::parse("proj_core").unwrap(),
            egress_allow_private: allow_private,
        });

        Fixture {
            engine,
            sessions,
            credentials,
            transport,
            audit,
            _audit_dir: dir,
            raw_token,
            session_id,
        }
    }

    fn happy_transport() -> CapturingTransport {
        CapturingTransport::with_response(
            200,
            vec![
                (
                    "set-cookie".to_owned(),
                    "sid=upstreamsession; HttpOnly".to_owned(),
                ),
                ("content-type".to_owned(), "application/json".to_owned()),
            ],
            br#"{"echo":"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ab","ok":true}"#,
        )
    }

    fn broker_request(fixture: &Fixture) -> BrokerRequest {
        BrokerRequest {
            protocol: PROTOCOL_VERSION,
            session_token: fixture.raw_token.clone(),
            credential: CredentialRef::parse("github-work-token").unwrap(),
            method: HttpMethod::GET,
            url: "https://api.github.com/repos/acme/backend/issues".to_owned(),
            headers: Vec::new(),
            body: BrokerBody::None,
            capability_hint: None,
        }
    }

    fn audit_events(fixture: &Fixture) -> Vec<vaultx_audit::AuditEvent> {
        fixture.audit.query(&AuditFilter::default()).unwrap()
    }

    fn deny_reason(response: &BrokerResponse) -> (String, Option<String>) {
        match &response.decision {
            Decision::Deny { reason, policy } => (reason.clone(), policy.clone()),
            other => panic!("expected Deny decision, got {other:?}"),
        }
    }

    // -- required test matrix --------------------------------------------------

    #[test]
    fn happy_path_allow_injects_credential_and_sanitizes_response() {
        let fixture = standard_fixture(happy_transport(), false);
        let mut request = broker_request(&fixture);
        request.headers.push((
            "authorization".to_owned(),
            "Bearer evil-caller-value".to_owned(),
        ));
        request
            .headers
            .push(("x-custom".to_owned(), "keep-me".to_owned()));

        let response = fixture.engine.execute_broker_request(request);

        // Decision + sanitized response shape.
        assert_eq!(response.decision, Decision::Allow);
        assert_eq!(response.status, 200);

        // INV-004/018: injection happened inside broker scope on the
        // outbound capture — with the injected value, not caller's.
        let outbound = fixture.transport.last();
        assert!(
            outbound
                .headers
                .iter()
                .any(|(name, value)| name == "authorization"
                    && value == &format!("token {SECRET_CANARY}")),
            "outbound must carry injected github_bearer header"
        );
        assert!(!format!("{:?}", outbound.headers).contains("evil-caller-value"));
        assert!(outbound
            .headers
            .iter()
            .any(|(name, value)| name == "x-custom" && value == "keep-me"));

        // INV-002/003: no credential plaintext anywhere in the agent-
        // visible response.
        let body_text = String::from_utf8_lossy(&response.body).into_owned();
        assert!(!body_text.contains(SECRET_CANARY));
        assert!(!body_text.contains(RESPONSE_TOKEN), "scrubbed token gone");
        assert!(body_text.contains("[redacted]"), "token replaced");
        let set_cookie = response
            .headers
            .iter()
            .find(|(name, _)| name == "set-cookie")
            .map(|(_, value)| value.as_str())
            .expect("set-cookie header preserved");
        assert_eq!(set_cookie, "[redacted]");
        assert!(response
            .headers
            .iter()
            .any(|(name, value)| name == "content-type" && value == "application/json"));

        // Audit: exactly one allow event with safe destination summary.
        let events = audit_events(&fixture);
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.decision, AuditDecision::Allow);
        assert_eq!(event.actor.as_str(), &format!("agent:{FIXTURE_AGENT_ID}"));
        let destination = event.destination.as_ref().expect("destination recorded");
        assert_eq!(destination.host(), "api.github.com");
        assert_eq!(destination.port(), 443);
        assert_eq!(destination.path(), "/repos/acme/backend/issues");
        assert_eq!(
            event
                .credential
                .as_ref()
                .map(vaultx_types::CredentialRef::as_str),
            Some("github-work-token")
        );
        // The deciding policy is attributed in audit metadata.
        assert_eq!(
            event.metadata.get("policy"),
            Some("coding-agent-github"),
            "allow events record the deciding policy"
        );

        // The audit record never contains secret material.
        let raw_audit = std::fs::read_to_string(fixture._audit_dir.path().join("audit.jsonl"))
            .expect("audit readable");
        assert!(!raw_audit.contains(SECRET_CANARY));
        assert!(!raw_audit.contains(RESPONSE_TOKEN));
    }

    #[test]
    fn bad_session_is_denied_and_audited() {
        let fixture = standard_fixture(happy_transport(), false);
        let mut request = broker_request(&fixture);
        request.session_token = "definitely-not-a-token".to_owned();

        let response = fixture.engine.execute_broker_request(request);
        let (reason, policy) = deny_reason(&response);
        assert_eq!(reason, "invalid_session");
        assert_eq!(policy, None);
        assert_eq!(response.status, 403);
        assert!(response.body.is_empty());

        let events = audit_events(&fixture);
        assert_eq!(events.len(), 1);
        assert!(matches!(
            &events[0].decision,
            AuditDecision::Deny { reason } if reason == "invalid_session"
        ));
        // No transport execution ever happened.
        assert!(fixture.captured_empty());
    }

    #[test]
    fn revoked_session_is_denied_with_dedicated_reason() {
        let fixture = standard_fixture(happy_transport(), false);
        fixture.sessions.revoke(&fixture.session_id).unwrap();

        let response = fixture
            .engine
            .execute_broker_request(broker_request(&fixture));
        let (reason, _) = deny_reason(&response);
        assert_eq!(reason, "session_revoked");

        let events = audit_events(&fixture);
        assert!(matches!(
            &events[0].decision,
            AuditDecision::Deny { reason } if reason == "session_revoked"
        ));
    }

    #[test]
    fn unknown_credential_denied_after_authorization_passes() {
        let fixture = standard_fixture(happy_transport(), false);
        let mut request = broker_request(&fixture);
        request.credential = CredentialRef::parse("ghost-token").unwrap();

        let response = fixture.engine.execute_broker_request(request);
        let (reason, _) = deny_reason(&response);
        assert_eq!(reason, "credential_unavailable");

        let events = audit_events(&fixture);
        assert!(matches!(
            &events[0].decision,
            AuditDecision::Deny { reason } if reason == "credential_unavailable"
        ));
    }

    #[test]
    fn unauthorized_host_denied_with_policy_attribution() {
        let fixture = standard_fixture(happy_transport(), false);
        let mut request = broker_request(&fixture);
        request.url = "https://evil.example.com/repos/acme/backend/issues".to_owned();

        let response = fixture.engine.execute_broker_request(request);
        let (reason, policy) = deny_reason(&response);
        assert_eq!(reason, "no_matching_allow");
        assert_eq!(policy.as_deref(), Some("coding-agent-github"));

        let events = audit_events(&fixture);
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0].decision, AuditDecision::Deny { .. }));
        // Deny events attribute the policy that produced the denial.
        assert_eq!(
            events[0].metadata.get("policy"),
            Some("coding-agent-github")
        );
    }

    #[test]
    fn explicit_deny_rule_wins_over_allow() {
        let fixture = standard_fixture(happy_transport(), false);
        let mut request = broker_request(&fixture);
        request.method = HttpMethod::DELETE;

        let response = fixture.engine.execute_broker_request(request);
        let (reason, policy) = deny_reason(&response);
        assert_eq!(reason, "explicit_deny");
        assert_eq!(policy.as_deref(), Some("coding-agent-github"));
        let events = audit_events(&fixture);
        assert_eq!(
            events[0].metadata.get("policy"),
            Some("coding-agent-github")
        );
        assert!(fixture.captured_empty(), "nothing reached transport");
    }

    #[test]
    fn inv004_caller_authorization_header_cannot_override_injection() {
        let fixture = standard_fixture(happy_transport(), false);
        let mut request = broker_request(&fixture);
        request.headers = vec![
            (
                "AUTHORIZATION".to_owned(),
                "Bearer attacker-chosen".to_owned(),
            ),
            ("Proxy-Authorization".to_owned(), "Basic smuggle".to_owned()),
        ];

        let response = fixture.engine.execute_broker_request(request);
        assert_eq!(response.decision, Decision::Allow);

        let outbound = fixture.transport.last();
        let auth_headers: Vec<&(String, String)> = outbound
            .headers
            .iter()
            .filter(|(name, _)| name == "authorization" || name == "proxy-authorization")
            .collect();
        assert_eq!(auth_headers.len(), 1, "exactly one auth header survives");
        assert_eq!(
            auth_headers[0],
            &("authorization".to_owned(), format!("token {SECRET_CANARY}"))
        );
    }

    #[test]
    fn http_scheme_is_rejected_at_canonicalization() {
        let fixture = standard_fixture(happy_transport(), false);
        let mut request = broker_request(&fixture);
        request.url = "http://api.github.com/repos/acme/backend/issues".to_owned();

        let response = fixture.engine.execute_broker_request(request);
        let (reason, _) = deny_reason(&response);
        assert_eq!(reason, "invalid_destination");

        let events = audit_events(&fixture);
        assert!(matches!(
            &events[0].decision,
            AuditDecision::Deny { reason } if reason == "invalid_destination"
        ));
    }

    #[test]
    fn private_ip_literal_denied_pre_authorization() {
        for target in [
            "https://127.0.0.1/repos/acme/backend/issues",
            "https://10.0.0.5/x",
            "https://169.254.169.254/latest/meta-data/",
        ] {
            let fixture = standard_fixture(happy_transport(), false);
            let mut request = broker_request(&fixture);
            request.url = target.to_owned();
            let response = fixture.engine.execute_broker_request(request);
            let (reason, _) = deny_reason(&response);
            assert_eq!(reason, "destination_denied", "{target}");
            assert!(fixture.captured_empty());

            let events = audit_events(&fixture);
            assert!(
                matches!(&events[0].decision,
                    AuditDecision::Deny { reason } if reason == "destination_denied"),
                "{target}"
            );
        }

        // Metadata endpoints stay denied even in allow-private mode.
        let lax = standard_fixture(happy_transport(), true);
        let mut request = broker_request(&lax);
        request.url = "https://169.254.169.254/latest/meta-data/".to_owned();
        let response = lax.engine.execute_broker_request(request);
        let (reason, _) = deny_reason(&response);
        assert_eq!(reason, "destination_denied");

        // While genuinely private destinations pass the egress gate when
        // explicitly allowed (authorization still applies).
        let lax = standard_fixture(happy_transport(), true);
        let mut doc = parse_policy_yaml(&policy_yaml(
            "private-host-agent",
            &format!("agent:{FIXTURE_AGENT_ID}"),
            "github-work-token",
        ))
        .unwrap();
        doc.http.hosts = vec!["10.0.0.5".to_owned()];
        let mut engine_docs = vec![doc];
        engine_docs.push(
            parse_policy_yaml(&policy_yaml(
                "coding-agent-github",
                &format!("agent:{FIXTURE_AGENT_ID}"),
                "github-work-token",
            ))
            .unwrap(),
        );
        let rebuilt = BrokerEngine::new(BrokerDependencies {
            authorizer: Arc::new(RuleEngine::from_documents(engine_docs).unwrap()),
            sessions: lax.sessions.clone(),
            credentials: lax.credentials.clone(),
            injectors: Arc::new(InjectorRegistry::new()),
            transport: Arc::new(lax.transport.clone()),
            audit: lax.audit.clone(),
            project: ProjectId::parse("proj_core").unwrap(),
            egress_allow_private: true,
        });
        let mut request = broker_request(&lax);
        request.url = "https://10.0.0.5/repos/acme/backend/issues".to_owned();
        let response = rebuilt.execute_broker_request(request);
        assert_eq!(response.decision, Decision::Allow);
    }

    #[test]
    fn protocol_other_than_one_is_denied() {
        let fixture = standard_fixture(happy_transport(), false);
        let mut request = broker_request(&fixture);
        request.protocol = 2;

        let response = fixture.engine.execute_broker_request(request);
        let (reason, _) = deny_reason(&response);
        assert_eq!(reason, "protocol_unsupported");
        assert!(fixture.captured_empty());

        let events = audit_events(&fixture);
        assert!(matches!(
            &events[0].decision,
            AuditDecision::Deny { reason } if reason == "protocol_unsupported"
        ));
    }

    #[test]
    fn audit_events_chain_and_verify_after_mixed_outcomes() {
        let fixture = standard_fixture(happy_transport(), false);

        // Request 1: allowed.
        let allowed = fixture
            .engine
            .execute_broker_request(broker_request(&fixture));
        assert_eq!(allowed.decision, Decision::Allow);
        // Request 2: denied by host.
        let mut denied = broker_request(&fixture);
        denied.url = "https://evil.example.com/x".to_owned();
        let refused = fixture.engine.execute_broker_request(denied);
        assert!(matches!(refused.decision, Decision::Deny { .. }));
        // Request 3: denied by session.
        let mut bad_session = broker_request(&fixture);
        bad_session.session_token = "garbage".to_owned();
        let rejected = fixture.engine.execute_broker_request(bad_session);
        assert!(matches!(rejected.decision, Decision::Deny { .. }));

        let events = audit_events(&fixture);
        assert_eq!(events.len(), 3);
        assert_eq!(
            events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert!(matches!(events[0].decision, AuditDecision::Allow));
        assert!(matches!(events[1].decision, AuditDecision::Deny { .. }));
        assert!(matches!(events[2].decision, AuditDecision::Deny { .. }));
        fixture.audit.verify_chain().expect("chain intact");
    }

    #[test]
    fn capability_hint_never_influences_the_decision() {
        // A hint claiming a powerful capability cannot rescue a request
        // whose actual method/path policy denies.
        let fixture = standard_fixture(happy_transport(), false);
        let mut request = broker_request(&fixture);
        request.capability_hint = Some("github.pull_request.create".to_owned());
        request.method = HttpMethod::POST;
        request.url = "https://api.github.com/repos/acme/backend/pulls".to_owned();

        let response = fixture.engine.execute_broker_request(request);
        let (reason, _) = deny_reason(&response);
        assert_eq!(reason, "no_matching_allow");

        // Conversely a garbage hint does not sink an otherwise allowed
        // request — it is informational only.
        let permissive = standard_fixture(happy_transport(), false);
        let mut fine = broker_request(&permissive);
        fine.capability_hint = Some("NOT A CAPABILITY!!".to_owned());
        let response = permissive.engine.execute_broker_request(fine);
        assert_eq!(response.decision, Decision::Allow);

        // A valid hint lands in the audit event as the capability; a
        // garbage hint simply records none.
        let events = audit_events(&permissive);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].capability, None);

        let hinted = standard_fixture(happy_transport(), false);
        let mut with_hint = broker_request(&hinted);
        with_hint.capability_hint = Some("github.pull_request.create".to_owned());
        let response = hinted.engine.execute_broker_request(with_hint);
        assert_eq!(response.decision, Decision::Allow);
        let events = audit_events(&hinted);
        assert_eq!(
            events[0]
                .capability
                .as_ref()
                .map(vaultx_audit::CapabilityName::as_str),
            Some("github.pull_request.create")
        );
    }

    #[test]
    fn transport_failure_denied_and_audited() {
        let fixture = standard_fixture(CapturingTransport::failing(), false);
        let response = fixture
            .engine
            .execute_broker_request(broker_request(&fixture));
        let (reason, _) = deny_reason(&response);
        assert_eq!(reason, "transport_failure");

        let events = audit_events(&fixture);
        assert!(matches!(
            &events[0].decision,
            AuditDecision::Deny { reason } if reason == "transport_failure"
        ));
    }

    #[test]
    fn oversized_response_denied_wholesale() {
        let oversized = vec![b'a'; MAX_RESPONSE_BODY_BYTES + 1];
        let fixture = standard_fixture(
            CapturingTransport::with_response(200, Vec::new(), &oversized),
            false,
        );
        let response = fixture
            .engine
            .execute_broker_request(broker_request(&fixture));
        let (reason, _) = deny_reason(&response);
        assert_eq!(reason, "response_too_large");

        // Exactly at the ceiling passes.
        let at_limit = vec![b'a'; MAX_RESPONSE_BODY_BYTES];
        let fixture = standard_fixture(
            CapturingTransport::with_response(200, Vec::new(), &at_limit),
            false,
        );
        let response = fixture
            .engine
            .execute_broker_request(broker_request(&fixture));
        assert_eq!(response.decision, Decision::Allow);
    }

    #[test]
    fn deferred_sigv4_template_surfaces_unsupported_deny() {
        let fixture = standard_fixture(happy_transport(), false);
        let mut request = broker_request(&fixture);
        request.credential = CredentialRef::parse("sigv4-token").unwrap();

        let response = fixture.engine.execute_broker_request(request);
        let (reason, _) = deny_reason(&response);
        assert_eq!(reason, "template_unsupported");

        let events = audit_events(&fixture);
        assert!(matches!(
            &events[0].decision,
            AuditDecision::Deny { reason } if reason == "template_unsupported"
        ));
    }

    #[test]
    fn missing_injection_metadata_surfaces_injection_failed() {
        let fixture = standard_fixture(happy_transport(), false);
        let mut request = broker_request(&fixture);
        request.credential = CredentialRef::parse("broken-api-key").unwrap();

        let response = fixture.engine.execute_broker_request(request);
        let (reason, _) = deny_reason(&response);
        assert_eq!(reason, "injection_failed");
        assert!(fixture.captured_empty());
    }

    #[test]
    fn query_parameter_injection_reaches_the_outbound_url() {
        let fixture = standard_fixture(happy_transport(), false);
        let mut request = broker_request(&fixture);
        request.credential = CredentialRef::parse("query-token").unwrap();
        request.url = "https://api.github.com/repos/acme/backend/issues?x=1".to_owned();

        let response = fixture.engine.execute_broker_request(request);
        assert_eq!(response.decision, Decision::Allow);

        let outbound = fixture.transport.last();
        let pairs = outbound.canonical_url.query_pairs();
        assert!(pairs.contains(&("x".to_owned(), "1".to_owned())));
        assert!(pairs.contains(&("token".to_owned(), "querysecret".to_owned())));

        // The returned response must not carry the injected query secret.
        let body_text = String::from_utf8_lossy(&response.body).into_owned();
        assert!(!body_text.contains("querysecret"));
    }

    #[test]
    fn authorization_matches_agent_principal_from_validated_session() {
        // F-1: the engine authorizes as `agent:<record.agent>` — a policy
        // written against that agent principal must allow, and one written
        // for a different agent must default-deny.
        let build = |policy_principal: &str| {
            let dir = tempfile::tempdir().unwrap();
            let audit = Arc::new(JsonlAppendStore::open(dir.path().join("audit.jsonl")));
            let sessions = Arc::new(InMemorySessionStore::new());
            let credentials = InMemoryCredentialSource::new();
            credentials.insert(
                CredentialRef::parse("github-work-token").unwrap(),
                SecretBytes::from_bytes(SECRET_CANARY.as_bytes()),
                InjectionTemplateId::GithubBearer,
                CredentialMetadata::default(),
            );
            let (_, raw_token) = sessions
                .create(
                    &AgentId::parse("agent_test_agent").unwrap(),
                    &EnvironmentId::parse("env_development").unwrap(),
                )
                .unwrap();
            let document = parse_policy_yaml(&policy_yaml(
                "agent-policy",
                policy_principal,
                "github-work-token",
            ))
            .unwrap();
            let transport = happy_transport();
            let engine = BrokerEngine::new(BrokerDependencies {
                authorizer: Arc::new(RuleEngine::from_documents([document]).unwrap()),
                sessions,
                credentials: Arc::new(credentials),
                injectors: Arc::new(InjectorRegistry::new()),
                transport: Arc::new(transport.clone()),
                audit,
                project: ProjectId::parse("proj_core").unwrap(),
                egress_allow_private: false,
            });
            (engine, raw_token, dir)
        };

        let request_for = |raw_token: &str| BrokerRequest {
            protocol: PROTOCOL_VERSION,
            session_token: raw_token.to_owned(),
            credential: CredentialRef::parse("github-work-token").unwrap(),
            method: HttpMethod::GET,
            url: "https://api.github.com/repos/acme/backend/issues".to_owned(),
            headers: Vec::new(),
            body: BrokerBody::None,
            capability_hint: None,
        };

        // Matching principal: allowed end-to-end.
        let (engine, token, _dir) = build("agent:agent_test_agent");
        let response = engine.execute_broker_request(request_for(&token));
        assert_eq!(response.decision, Decision::Allow);

        // Mismatched principal: silently default-denied by policy.
        let (engine, token, _dir) = build("agent:mismatch");
        let response = engine.execute_broker_request(request_for(&token));
        let (reason, _) = deny_reason(&response);
        assert_eq!(reason, "no_matching_policy");
    }

    #[test]
    fn unauthenticated_actor_falls_back_without_echoing_tokens() {
        // A syntactically session-shaped token gets used as the actor id
        // (it is an identifier); arbitrary garbage falls back to the
        // static unauthenticated principal. Either way the raw token
        // bytes are never echoed into audit metadata.
        let fixture = standard_fixture(happy_transport(), false);
        let mut request = broker_request(&fixture);
        request.session_token = "sess_deadbeefdeadbeefdeadbeefdeadbeef".to_owned();
        let response = fixture.engine.execute_broker_request(request);
        let (reason, _) = deny_reason(&response);
        assert_eq!(reason, "invalid_session");
        let events = audit_events(&fixture);
        assert_eq!(
            events[0].actor.as_str(),
            "session:sess_deadbeefdeadbeefdeadbeefdeadbeef"
        );

        let mut request = broker_request(&fixture);
        request.session_token = "@@@ not an id @@@".to_owned();
        let response = fixture.engine.execute_broker_request(request);
        assert_eq!(deny_reason(&response).0, "invalid_session");
        let events = audit_events(&fixture);
        let last = events.last().unwrap();
        assert_eq!(last.actor.as_str(), UNAUTHENTICATED_ACTOR);
        assert!(!serde_json::to_string(last).unwrap().contains("@@@"));
    }

    #[test]
    fn deny_responses_never_leak_secret_material_into_audit_file() {
        // Drive several deny paths, then inspect the raw audit file.
        let fixture = standard_fixture(CapturingTransport::failing(), false);
        for mutate in [
            |req: &mut BrokerRequest| req.credential = CredentialRef::parse("ghost-token").unwrap(),
            |req: &mut BrokerRequest| req.credential = CredentialRef::parse("sigv4-token").unwrap(),
            |_req: &mut BrokerRequest| {},
        ] {
            let mut request = broker_request(&fixture);
            mutate(&mut request);
            let response = fixture.engine.execute_broker_request(request);
            assert!(matches!(response.decision, Decision::Deny { .. }));
        }
        let raw_audit =
            std::fs::read_to_string(fixture._audit_dir.path().join("audit.jsonl")).unwrap();
        assert!(!raw_audit.contains(SECRET_CANARY));
        assert!(
            !raw_audit.contains('?'),
            "no query-bearing content in audit"
        );
        fixture.audit.verify_chain().unwrap();
    }

    impl Fixture {
        fn captured_empty(&self) -> bool {
            self.transport
                .captured
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty()
        }
    }

    // -- scrubber unit tests ---------------------------------------------------

    #[test]
    fn scrub_replaces_known_secret_shapes() {
        let scrubbed = scrub_secret_patterns(
            format!("start {RESPONSE_TOKEN} end sk-abcdefghijklmnopqrst tail").as_bytes(),
        );
        let text = String::from_utf8(scrubbed).unwrap();
        assert_eq!(text, "start [redacted] end [redacted] tail");
    }

    #[test]
    fn scrub_matches_aws_access_key_ids_only_with_full_charset_run() {
        let with_key = b"id=AKIAIOSFODNN7EXAMPLE,id=other";
        let text = String::from_utf8(scrub_secret_patterns(with_key)).unwrap();
        assert_eq!(text, "id=[redacted],id=other");

        // Shorter or lowercase runs do not match the AKIA rule.
        let partial = b"AKIAiosfodnn7example";
        assert_eq!(
            String::from_utf8(scrub_secret_patterns(partial)).unwrap(),
            "AKIAiosfodnn7example"
        );
    }

    #[test]
    fn scrub_ignores_short_runs_and_plain_text() {
        let plain = b"the quick brown fox ghp_123 sk-short";
        assert_eq!(
            scrub_secret_patterns(plain),
            plain.to_vec(),
            "non-matching bodies pass through byte-identical"
        );
        assert_eq!(scrub_secret_patterns(b""), Vec::<u8>::new());
    }

    #[test]
    fn scrub_handles_adjacent_and_multiple_matches() {
        // Separated by a delimiter: two independent redactions.
        let spaced = format!("{RESPONSE_TOKEN} {RESPONSE_TOKEN}")
            .as_bytes()
            .to_vec();
        let text = String::from_utf8(scrub_secret_patterns(&spaced)).unwrap();
        assert_eq!(text, "[redacted] [redacted]");

        // Directly adjacent tokens share one alphanumeric run ("…ab" +
        // "ghp…" are all alnum up to the second token's underscore); the
        // scanner consumes the entire run conservatively, leaving only
        // the non-alnum remainder. It can over-redact, never under-redact.
        let doubled = format!("{RESPONSE_TOKEN}{RESPONSE_TOKEN}")
            .as_bytes()
            .to_vec();
        let text = String::from_utf8(scrub_secret_patterns(&doubled)).unwrap();
        assert_eq!(text, "[redacted]_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ab");
    }

    #[test]
    fn scrub_covers_full_fine_grained_pat_shape() {
        // Realistic fine-grained PAT: `github_pat_<22 alnum>_<59 tail>`
        // where the tail itself contains underscores. The entire token —
        // including the secret-bearing tail — must vanish.
        let token = format!(
            "github_pat_{}_{}_{}",
            "ABCDEFGHIJKLMNOPQRSTUV", // 22-char id
            "ABCDEFGHIJKLMNOPQRSTUV", // separator-adjacent id part
            format_args!("{}_{}", "a".repeat(30), "Z".repeat(28)), // 59-char tail with `_`
        );
        let body = format!("token={token};next=1");
        let text = String::from_utf8(scrub_secret_patterns(body.as_bytes())).unwrap();
        assert_eq!(text, "token=[redacted];next=1");
        assert!(!text.contains("aaaa"), "no tail fragment survives");
    }

    #[test]
    fn scrub_regression_underscore_split_bypass_is_closed() {
        // Regression for the original defect: matching only the leading
        // alnum run redacted the 22-char id while leaving the ~59-char
        // secret tail in plain text. The tail must be consumed too.
        let token = format!("github_pat_{}_{}", "B".repeat(30), "C".repeat(40),);
        let body = format!("<{token}>");
        let text = String::from_utf8(scrub_secret_patterns(body.as_bytes())).unwrap();
        assert_eq!(text, "<[redacted]>");
        assert!(!text.contains('C'), "secret tail must not survive");
    }

    #[test]
    fn scrub_fine_grained_pat_edge_shapes() {
        // Separator present but short tail: the qualifying id segment is
        // still redacted (over-redaction is acceptable; under is not).
        let body = b"github_pat_ABCDEFGHIJKLMNOPQRSTUVWX_short";
        let text = String::from_utf8(scrub_secret_patterns(body)).unwrap();
        assert_eq!(text, "[redacted]_short");

        // No separator at all: a long classic-shaped run still matches
        // through the fallback path.
        let body = format!("github_pat_{}", "D".repeat(38));
        let text = String::from_utf8(scrub_secret_patterns(body.as_bytes())).unwrap();
        assert_eq!(text, "[redacted]");

        // Below the id threshold entirely: not a PAT shape, untouched.
        let body = b"github_pat_shortvalue_moretail";
        assert_eq!(
            scrub_secret_patterns(body),
            body.to_vec(),
            "short runs pass through unchanged"
        );
    }

    #[test]
    fn bounded_reason_truncates_to_audit_budget_at_char_boundary() {
        use vaultx_audit::AuditDecision;
        assert_eq!(bounded_reason("short"), "short");

        let exact = "x".repeat(AuditDecision::MAX_DENY_REASON_BYTES);
        assert_eq!(bounded_reason(&exact), exact);

        let over = format!("{exact}yyyy");
        assert_eq!(bounded_reason(&over), exact);

        // Multi-byte input truncates at a character boundary, never
        // mid-codepoint, and always fits the budget afterwards.
        let multi = "é".repeat(200); // 400 bytes
        let truncated = bounded_reason(&multi);
        assert!(truncated.len() <= AuditDecision::MAX_DENY_REASON_BYTES);
        assert!(truncated.chars().all(|c| c == 'é'));
        assert!(AuditDecision::deny(truncated).is_ok());
    }

    #[test]
    fn audit_write_failure_fails_closed_before_delivery_on_allow_paths() {
        // A store that rejects every append: the would-be-allow response
        // must become a 500 denial and the transport must never execute.
        let sessions = Arc::new(InMemorySessionStore::new());
        let credentials = Arc::new(InMemoryCredentialSource::new());
        credentials.insert(
            CredentialRef::parse("github-work-token").unwrap(),
            SecretBytes::from_bytes(SECRET_CANARY.as_bytes()),
            InjectionTemplateId::GithubBearer,
            CredentialMetadata::default(),
        );
        let (_, raw_token) = sessions
            .create(
                &AgentId::parse("agent_coding").unwrap(),
                &EnvironmentId::parse("env_development").unwrap(),
            )
            .unwrap();
        let document = parse_policy_yaml(&policy_yaml(
            "coding-agent-github",
            &format!("agent:{FIXTURE_AGENT_ID}"),
            "github-work-token",
        ))
        .unwrap();
        let transport = happy_transport();
        let engine = BrokerEngine::new(BrokerDependencies {
            authorizer: Arc::new(RuleEngine::from_documents([document]).unwrap()),
            sessions,
            credentials,
            injectors: Arc::new(InjectorRegistry::new()),
            transport: Arc::new(transport.clone()),
            audit: Arc::new(FailingAuditStore),
            project: ProjectId::parse("proj_core").unwrap(),
            egress_allow_private: false,
        });

        let request = BrokerRequest {
            protocol: PROTOCOL_VERSION,
            session_token: raw_token,
            credential: CredentialRef::parse("github-work-token").unwrap(),
            method: HttpMethod::GET,
            url: "https://api.github.com/repos/acme/backend/issues".to_owned(),
            headers: Vec::new(),
            body: BrokerBody::None,
            capability_hint: None,
        };
        let response = engine.execute_broker_request(request);

        assert_eq!(response.status, 500);
        assert_eq!(
            response.decision,
            Decision::Deny {
                reason: AUDIT_WRITE_FAILED_REASON.to_owned(),
                policy: None,
            }
        );
        assert!(response.body.is_empty());
        // The exchange itself happened (stage 8 precedes the audit write
        // at stage 10) — fail-closed here means the *result* is withheld
        // from the agent, not that the wire was never touched.
        let captured = transport
            .captured
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(captured.len(), 1);
    }

    #[test]
    fn audit_write_failure_upgrades_deny_outcomes_rather_than_silently_dropping() {
        // Deny records are the probing-detection layer: when the store is
        // broken, the caller must see a broker-level 500 instead of a
        // quietly-swallowed deny reason.
        let sessions = Arc::new(InMemorySessionStore::new());
        let credentials = Arc::new(InMemoryCredentialSource::new());
        credentials.insert(
            CredentialRef::parse("github-work-token").unwrap(),
            SecretBytes::from_bytes(SECRET_CANARY.as_bytes()),
            InjectionTemplateId::GithubBearer,
            CredentialMetadata::default(),
        );
        let (_, raw_token) = sessions
            .create(
                &AgentId::parse("agent_coding").unwrap(),
                &EnvironmentId::parse("env_development").unwrap(),
            )
            .unwrap();
        let document = parse_policy_yaml(&policy_yaml(
            "coding-agent-github",
            &format!("agent:{FIXTURE_AGENT_ID}"),
            "github-work-token",
        ))
        .unwrap();
        let transport = CapturingTransport::failing();
        let engine = BrokerEngine::new(BrokerDependencies {
            authorizer: Arc::new(RuleEngine::from_documents([document]).unwrap()),
            sessions,
            credentials,
            injectors: Arc::new(InjectorRegistry::new()),
            transport: Arc::new(transport),
            audit: Arc::new(FailingAuditStore),
            project: ProjectId::parse("proj_core").unwrap(),
            egress_allow_private: false,
        });

        // DELETE matches the explicit deny rule; with a healthy store this
        // surfaces as `explicit_deny`, but the broken audit sink upgrades
        // the response to the broker-level failure.
        let request = BrokerRequest {
            protocol: PROTOCOL_VERSION,
            session_token: raw_token,
            credential: CredentialRef::parse("github-work-token").unwrap(),
            method: HttpMethod::DELETE,
            url: "https://api.github.com/repos/acme/backend/issues".to_owned(),
            headers: Vec::new(),
            body: BrokerBody::None,
            capability_hint: None,
        };
        let response = engine.execute_broker_request(request);
        assert_eq!(response.status, 500);
        assert_eq!(
            response.decision,
            Decision::Deny {
                reason: AUDIT_WRITE_FAILED_REASON.to_owned(),
                policy: None,
            }
        );
    }

    #[test]
    fn max_response_body_constant_is_one_mebibyte() {
        assert_eq!(MAX_RESPONSE_BODY_BYTES, 1_048_576);
    }
}
