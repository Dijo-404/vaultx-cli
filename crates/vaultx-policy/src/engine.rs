//! Rule engine implementing the [`Authorizer`] seam (plan §22).
//!
//! [`RuleEngine`] evaluates compiled policy documents with a strict,
//! documented evaluation order and a **default-deny** posture. The trait is
//! the integration seam for the broker: in production this crate is meant
//! to be backed by Cedar as the policy evaluator, but Cedar is *not*
//! integrated yet — the trait exists so callers can be wired against the
//! final authorization surface today and swap evaluators later without
//! touching call sites.
//!
//! Broker mapping: `principal` is the agent/session identity, `action` is
//! always [`Action::HttpRequest`], `resource` is the credential logical ID,
//! and `context` carries canonical host/method/path/query/body metadata plus
//! the active environment.
//!
//! # Canonicalization contract (caller obligations)
//!
//! The engine performs **no normalization** on request context: matching is
//! literal and segment-based. The broker transport layer MUST deliver an
//! [`AuthorizationContext`] whose `path` is already percent-decoded with
//! dot segments (`.` / `..`) resolved, and whose `host` is already
//! lowercased without port. Non-canonical contexts are rejected outright
//! with [`DenyReason::InvalidContext`] rather than normalized, because
//! silent upstream normalization differences are a classic deny-evasion
//! vector.

use vaultx_types::PolicyName;

use crate::error::PolicyError;
use crate::loader::validate_policy;
use crate::matcher::{host_matches, path_matches};
use crate::model::{
    Action, AuthorizationContext, HttpMethod, MethodPathRule, PolicyDocument, Principal, Resource,
};

/// Authorization decision boundary used by the broker.
///
/// Implementations must be safe to share across threads; decisions are
/// derived purely from the request and immutable configuration.
pub trait Authorizer: Send + Sync {
    /// Decides whether `request` may proceed. The default decision of any
    /// implementation must be deny when nothing matches.
    fn authorize(&self, request: &AuthorizationRequest) -> AuthorizationDecision;
}

/// A single authorization query: who wants to do what to which resource,
/// under which context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationRequest {
    /// Agent or session identity (`agent:<name>` / `session:<id>`).
    pub principal: Principal,
    /// Operation being performed; only HTTP proxying exists today.
    pub action: Action,
    /// Logical ID of the brokered credential being accessed.
    pub resource: Resource,
    /// Canonical request metadata evaluated against policy rules.
    pub context: AuthorizationContext,
}

/// Outcome of an authorization check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorizationDecision {
    /// Request permitted by the named policy.
    Allow {
        /// Name of the policy that allowed the request.
        policy: PolicyName,
    },
    /// Request denied. Denial is the default whenever no rule allows.
    Deny {
        /// Why the request was denied.
        reason: DenyReason,
        /// Policy responsible, when a specific candidate was identified.
        policy: Option<PolicyName>,
    },
}

/// Canonical denial reasons surfaced by the rule engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyReason {
    /// No policy is bound to the engine or none matched the
    /// principal/credential pair.
    NoMatchingPolicy,
    /// An explicit deny rule matched method+path.
    ExplicitDeny,
    /// Host matched but no allow rule covered method+path (also reported
    /// when the host itself is outside the policy's host list).
    NoMatchingAllow,
    /// The active environment is not in the policy's allowlist.
    EnvironmentDenied,
    /// Body size exceeded the policy's request limit.
    BodyTooLarge,
    /// The [`AuthorizationContext`] was not in canonical form (see the
    /// module-level canonicalization contract). Never attributed to a
    /// policy.
    InvalidContext,
}

impl std::fmt::Display for DenyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::NoMatchingPolicy => "no_matching_policy",
            Self::ExplicitDeny => "explicit_deny",
            Self::NoMatchingAllow => "no_matching_allow",
            Self::EnvironmentDenied => "environment_denied",
            Self::BodyTooLarge => "body_too_large",
            Self::InvalidContext => "invalid_context",
        };
        f.write_str(text)
    }
}

/// A parsed and fully validated policy document ready for evaluation.
#[derive(Clone, Debug)]
pub struct CompiledPolicy {
    document: PolicyDocument,
}

impl CompiledPolicy {
    /// Validates `document` upfront; compilation fails fast so invalid
    /// policies never enter an engine.
    ///
    /// # Errors
    /// Returns any validation error produced by
    /// [`crate::loader::validate_policy`].
    pub fn compile(document: PolicyDocument) -> Result<Self, PolicyError> {
        validate_policy(&document)?;
        Ok(Self { document })
    }

    /// Read-only access to the validated document.
    #[must_use]
    pub fn document(&self) -> &PolicyDocument {
        &self.document
    }
}

/// Deterministic rule-based [`Authorizer`] over a set of
/// [`CompiledPolicy`] documents.
///
/// # Evaluation order
///
/// For each authorization request:
///
/// 1. **Context validation** — the request context must be canonical
///    (see [`AuthorizationContext::validate`]); otherwise deny with
///    [`DenyReason::InvalidContext`].
/// 2. **No policy bound** — an engine holding zero policies denies with
///    [`DenyReason::NoMatchingPolicy`] (default-deny).
/// 3. **Candidate selection** — policies whose `principal` equals the
///    request principal AND whose `credential` equals the request resource
///    become candidates. Non-candidates are skipped silently.
/// 4. **Explicit-deny pass (global, first)** — every candidate's deny rules
///    are scanned *before any allow is considered*. The first candidate
///    with a deny rule matching method+path denies immediately with
///    [`DenyReason::ExplicitDeny`]. This pass ignores environment/host
///    gates: an explicit deny in ANY matching policy wins over allows in
///    every other policy, regardless of insertion order.
/// 5. **Allow pass** — only if no explicit deny matched, candidates are
///    evaluated in insertion order through four gates: environment
///    allowlist (empty/absent means unconstrained), host list
///    (case-insensitive exact match), allow-rule match on method+path,
///    then body-size limit. The first candidate passing every gate allows,
///    naming its policy. Gate failures report [`DenyReason`]
///    `EnvironmentDenied`, `NoMatchingAllow`, and `BodyTooLarge`
///    respectively.
///
/// Aggregate decision: the first explicit deny beats everything; else the
/// first allow (insertion order) wins; else the failure reason recorded for
/// the first failing candidate.
#[derive(Clone, Debug, Default)]
pub struct RuleEngine {
    policies: Vec<CompiledPolicy>,
}

impl RuleEngine {
    /// Creates an empty engine; every request is denied until policies are
    /// added.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds an engine from policy documents, validating each one and
    /// rejecting duplicate policy names.
    ///
    /// # Errors
    /// Returns the first validation failure or duplicate name encountered.
    pub fn from_documents<I>(documents: I) -> Result<Self, PolicyError>
    where
        I: IntoIterator<Item = PolicyDocument>,
    {
        let mut engine = Self::new();
        for document in documents {
            engine.push(document)?;
        }
        Ok(engine)
    }

    /// Compiles and appends one policy document, rejecting a document
    /// whose name already exists in the engine.
    ///
    /// # Errors
    /// Returns validation failures ([`PolicyError::InvalidPolicy`] and
    /// friends) or [`PolicyError::DuplicatePolicyName`]. The engine is
    /// never mutated on failure.
    pub fn push(&mut self, document: PolicyDocument) -> Result<(), PolicyError> {
        let compiled = CompiledPolicy::compile(document)?;
        let name = compiled.document().name.clone();
        if self
            .policies
            .iter()
            .any(|existing| existing.document().name == name)
        {
            return Err(PolicyError::DuplicatePolicyName(name));
        }
        self.policies.push(compiled);
        Ok(())
    }

    /// All compiled policies in evaluation order.
    #[must_use]
    pub fn policies(&self) -> &[CompiledPolicy] {
        &self.policies
    }

    /// Runs full evaluation and returns a per-candidate explanation of how
    /// the decision was reached, intended for `vaultx policy explain`.
    #[must_use]
    pub fn explain(&self, request: &AuthorizationRequest) -> PolicyExplanation {
        let mut trace = Vec::new();
        let decision = self.evaluate(request, Some(&mut trace));
        PolicyExplanation {
            decision,
            considered: trace,
        }
    }

    /// Shared evaluation core. When `trace` is `Some`, every candidate
    /// verdict is recorded; [`Authorizer::authorize`] passes `None` so the
    /// fast path allocates nothing beyond the returned decision.
    fn evaluate(
        &self,
        request: &AuthorizationRequest,
        mut trace: Option<&mut Vec<CandidateEvaluation>>,
    ) -> AuthorizationDecision {
        // 1. Context must be canonical before any rule sees it.
        if request.context.validate().is_err() {
            return AuthorizationDecision::Deny {
                reason: DenyReason::InvalidContext,
                policy: None,
            };
        }

        // 2. Default-deny when no policies are bound at all.
        if self.policies.is_empty() {
            return AuthorizationDecision::Deny {
                reason: DenyReason::NoMatchingPolicy,
                policy: None,
            };
        }

        let ctx_method = request.context.method;
        let ctx_path = request.context.path.as_str();

        // 3.+4. Explicit-deny pass across ALL candidates, ignoring env and
        // host gates: deny in any matching policy beats allows everywhere.
        for compiled in &self.policies {
            let doc = &compiled.document;
            if !is_candidate(doc, request) {
                continue;
            }
            if rules_match(&doc.http.deny, ctx_method, ctx_path) {
                if let Some(entries) = trace.as_deref_mut() {
                    entries.push(CandidateEvaluation {
                        policy: doc.name.clone(),
                        outcome: CandidateOutcome::DeniedByExplicitDeny,
                    });
                }
                return AuthorizationDecision::Deny {
                    reason: DenyReason::ExplicitDeny,
                    policy: Some(doc.name.clone()),
                };
            }
        }

        // 5. Allow pass over candidates in insertion order.
        let mut first_failure: Option<(DenyReason, PolicyName)> = None;
        for compiled in &self.policies {
            let doc = &compiled.document;
            if !is_candidate(doc, request) {
                continue;
            }
            match evaluate_gates(doc, &request.context) {
                GateOutcome::Allowed => {
                    if let Some(entries) = trace.as_deref_mut() {
                        entries.push(CandidateEvaluation {
                            policy: doc.name.clone(),
                            outcome: CandidateOutcome::Allowed,
                        });
                    }
                    return AuthorizationDecision::Allow {
                        policy: doc.name.clone(),
                    };
                }
                GateOutcome::Failed(reason, outcome) => {
                    if first_failure.is_none() {
                        first_failure = Some((reason, doc.name.clone()));
                    }
                    if let Some(entries) = trace.as_deref_mut() {
                        entries.push(CandidateEvaluation {
                            policy: doc.name.clone(),
                            outcome,
                        });
                    }
                }
            }
        }

        first_failure.map_or_else(
            || AuthorizationDecision::Deny {
                reason: DenyReason::NoMatchingPolicy,
                policy: None,
            },
            |(reason, policy)| AuthorizationDecision::Deny {
                reason,
                policy: Some(policy),
            },
        )
    }
}

/// True when `doc` applies to `request`'s principal and credential.
fn is_candidate(doc: &PolicyDocument, request: &AuthorizationRequest) -> bool {
    doc.principal == request.principal && doc.credential == request.resource
}

/// Outcome of gates 5a–5d for one candidate after the global deny pass.
enum GateOutcome {
    /// Every gate passed; the candidate allows.
    Allowed,
    /// The candidate failed at `reason`, reported as `outcome`.
    Failed(DenyReason, CandidateOutcome),
}

fn evaluate_gates(doc: &PolicyDocument, context: &AuthorizationContext) -> GateOutcome {
    // 5a. Environment gate.
    if !doc.environment.allow.is_empty()
        && !context
            .environment
            .as_ref()
            .is_some_and(|env| doc.environment.allow.iter().any(|allowed| allowed == env))
    {
        return GateOutcome::Failed(
            DenyReason::EnvironmentDenied,
            CandidateOutcome::DeniedByEnvironment,
        );
    }

    // 5b. Host gate.
    if !host_matches(&doc.http.hosts, &context.host) {
        return GateOutcome::Failed(DenyReason::NoMatchingAllow, CandidateOutcome::DeniedByHost);
    }

    let method = context.method;
    let path = context.path.as_str();

    // 5c. At least one allow rule must match.
    if !rules_match(&doc.http.allow, method, path) {
        return GateOutcome::Failed(
            DenyReason::NoMatchingAllow,
            CandidateOutcome::DeniedByMissingAllow,
        );
    }

    // 5d. Request body constraint.
    if let Some(max_bytes) = doc.request.max_body_bytes {
        if context.body_len_bytes > max_bytes {
            return GateOutcome::Failed(
                DenyReason::BodyTooLarge,
                CandidateOutcome::DeniedByBodyLimit,
            );
        }
    }

    GateOutcome::Allowed
}

fn rules_match(rules: &[MethodPathRule], method: HttpMethod, path: &str) -> bool {
    rules.iter().any(|rule| {
        rule.methods.contains(&method)
            && rule.paths.iter().any(|pattern| path_matches(pattern, path))
    })
}

impl Authorizer for RuleEngine {
    fn authorize(&self, request: &AuthorizationRequest) -> AuthorizationDecision {
        // Fast path: no explanation trace is allocated.
        self.evaluate(request, None)
    }
}

/// Full trace of one authorization evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyExplanation {
    /// Final decision reached by the engine.
    pub decision: AuthorizationDecision,
    /// Every candidate policy that was evaluated, in order, with its
    /// outcome. Policies filtered out during candidate selection (step 2)
    /// are intentionally omitted.
    pub considered: Vec<CandidateEvaluation>,
}

/// How one candidate policy concluded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateOutcome {
    /// The candidate allowed the request.
    Allowed,
    /// Rejected at the environment gate.
    DeniedByEnvironment,
    /// Rejected because the request host is not in the host list.
    DeniedByHost,
    /// Rejected by an explicit deny rule.
    DeniedByExplicitDeny,
    /// No allow rule covered method+path.
    DeniedByMissingAllow,
    /// Allow rules matched but the body exceeded the size limit.
    DeniedByBodyLimit,
}

/// Per-candidate entry inside a [`PolicyExplanation`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateEvaluation {
    /// Name of the candidate policy.
    pub policy: PolicyName,
    /// Outcome recorded for this candidate.
    pub outcome: CandidateOutcome,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        AuthorizationContext, EnvironmentRules, MethodPathRule, RequestConstraints,
    };
    use std::collections::BTreeMap;
    use vaultx_types::{CredentialRef, EnvironmentId};

    const PLAN_YAML: &str = r#"
name: coding-agent-github
principal: agent:coding-agent
credential: github-work-token
environment:
  allow: [env_development]
http:
  hosts: [api.github.com]
  allow:
    - methods: [GET]
      paths: [/repos/acme/backend/**]
    - methods: [POST]
      paths: [/repos/acme/backend/pulls]
  deny:
    - methods: [DELETE]
      paths: ["/**"]
request:
  max_body_bytes: 262144
  deny_headers: [authorization, proxy-authorization]
response:
  max_body_bytes: 1048576
  redact_headers: [set-cookie]
"#;

    fn principal() -> Principal {
        Principal::parse("agent:coding-agent").unwrap()
    }

    fn env(id: &str) -> EnvironmentId {
        EnvironmentId::parse(id).unwrap()
    }

    fn context(method: HttpMethod, path: &str) -> AuthorizationContext {
        AuthorizationContext {
            host: "api.github.com".to_owned(),
            method,
            path: path.to_owned(),
            query: BTreeMap::new(),
            body_len_bytes: 0,
            environment: Some(env("env_development")),
        }
    }

    fn request(ctx: AuthorizationContext) -> AuthorizationRequest {
        AuthorizationRequest {
            principal: principal(),
            action: Action::HttpRequest,
            resource: CredentialRef::parse("github-work-token").unwrap(),
            context: ctx,
        }
    }

    fn rule(methods: &[HttpMethod], paths: &[&str]) -> MethodPathRule {
        MethodPathRule {
            methods: methods.to_vec(),
            paths: paths.iter().map(|p| (*p).to_owned()).collect(),
        }
    }

    fn plan_document() -> PolicyDocument {
        crate::loader::parse_policy_yaml(PLAN_YAML).unwrap()
    }

    fn assert_deny(decision: AuthorizationDecision, reason: DenyReason, policy: Option<&str>) {
        match decision {
            AuthorizationDecision::Deny {
                reason: r,
                policy: p,
            } => {
                assert_eq!(r, reason);
                assert_eq!(p.as_ref().map(PolicyName::as_str), policy);
            }
            other => panic!("expected Deny({reason}), got {other:?}"),
        }
    }

    #[test]
    fn empty_engine_denies_everything() {
        let engine = RuleEngine::new();
        let decision = engine.authorize(&request(context(HttpMethod::GET, "/anything")));
        assert_deny(decision, DenyReason::NoMatchingPolicy, None);
        let explanation = engine.explain(&request(context(HttpMethod::GET, "/anything")));
        assert!(explanation.considered.is_empty());
    }

    #[test]
    fn plan_yaml_example_parses_verbatim_shape() {
        let doc = plan_document();
        assert_eq!(doc.name.as_str(), "coding-agent-github");
        assert_eq!(doc.principal.as_str(), "agent:coding-agent");
        assert_eq!(doc.credential.as_str(), "github-work-token");
        assert_eq!(doc.environment.allow, vec![env("env_development")]);
        assert_eq!(doc.http.hosts, vec!["api.github.com".to_owned()]);
        assert_eq!(doc.http.allow.len(), 2);
        assert_eq!(doc.http.deny.len(), 1);
        assert_eq!(doc.request.max_body_bytes, Some(262_144));
        assert_eq!(
            doc.request.deny_headers,
            vec!["authorization".to_owned(), "proxy-authorization".to_owned()]
        );
        assert_eq!(doc.response.max_body_bytes, Some(1_048_576));
        assert_eq!(doc.response.redact_headers, vec!["set-cookie".to_owned()]);
    }

    #[test]
    fn allow_happy_path_get_issues() {
        let engine = RuleEngine::from_documents([plan_document()]).unwrap();
        let decision = engine.authorize(&request(context(
            HttpMethod::GET,
            "/repos/acme/backend/issues",
        )));
        assert_eq!(
            decision,
            AuthorizationDecision::Allow {
                policy: PolicyName::parse("coding-agent-github").unwrap()
            }
        );
    }

    #[test]
    fn explicit_deny_beats_allow() {
        // DELETE matches the deny rule `/**` even though the body limit is
        // also violated and an unrelated allow rule exists.
        let engine = RuleEngine::from_documents([plan_document()]).unwrap();
        let mut ctx = context(HttpMethod::DELETE, "/repos/acme/backend/pulls");
        ctx.body_len_bytes = u64::MAX;
        assert_deny(
            engine.authorize(&request(ctx)),
            DenyReason::ExplicitDeny,
            Some("coding-agent-github"),
        );
    }

    fn broad_allowing_delete() -> PolicyDocument {
        let mut broad = plan_document();
        broad.name = PolicyName::parse("coding-agent-broad").unwrap();
        broad.environment.allow.clear();
        broad.http.deny.clear();
        broad.http.allow.push(rule(&[HttpMethod::DELETE], &["/**"]));
        broad
    }

    #[test]
    fn cross_candidate_deny_precedence_in_both_insertion_orders() {
        // plan_document() denies DELETE /**.

        // [broad(allow), narrow(deny)]: the first candidate would allow,
        // but pass 1 must still find narrow's deny rule.
        let engine =
            RuleEngine::from_documents([broad_allowing_delete(), plan_document()]).unwrap();
        assert_deny(
            engine.authorize(&request(context(HttpMethod::DELETE, "/secret/x"))),
            DenyReason::ExplicitDeny,
            Some("coding-agent-github"),
        );

        // [narrow(deny), broad(allow)]: same result in reverse order.
        let engine =
            RuleEngine::from_documents([plan_document(), broad_allowing_delete()]).unwrap();
        assert_deny(
            engine.authorize(&request(context(HttpMethod::DELETE, "/secret/x"))),
            DenyReason::ExplicitDeny,
            Some("coding-agent-github"),
        );

        // explain() attributes the deny to the denying policy.
        let engine =
            RuleEngine::from_documents([broad_allowing_delete(), plan_document()]).unwrap();
        let explanation = engine.explain(&request(context(HttpMethod::DELETE, "/secret/x")));
        assert_eq!(
            explanation.considered[0].policy.as_str(),
            "coding-agent-github"
        );
        assert_eq!(
            explanation.considered[0].outcome,
            CandidateOutcome::DeniedByExplicitDeny
        );
    }

    #[test]
    fn non_canonical_contexts_are_rejected_before_rules_run() {
        let engine = RuleEngine::from_documents([plan_document()]).unwrap();

        let cases: Vec<AuthorizationContext> = vec![
            // Relative path.
            AuthorizationContext {
                path: "repos/acme/x".to_owned(),
                ..context(HttpMethod::GET, "/repos/acme")
            },
            // Empty segment (double slash).
            AuthorizationContext {
                path: "//acme/backend".to_owned(),
                ..context(HttpMethod::GET, "/repos/acme")
            },
            // Trailing slash.
            AuthorizationContext {
                path: "/repos/acme/".to_owned(),
                ..context(HttpMethod::GET, "/repos/acme")
            },
            // Dot segment.
            AuthorizationContext {
                path: "/repos/../secrets".to_owned(),
                ..context(HttpMethod::GET, "/repos/acme")
            },
            // Uppercase host.
            AuthorizationContext {
                host: "API.GitHub.com".to_owned(),
                ..context(HttpMethod::GET, "/repos/acme")
            },
            // Empty host.
            AuthorizationContext {
                host: String::new(),
                ..context(HttpMethod::GET, "/repos/acme")
            },
        ];

        for ctx in cases {
            let decision = engine.authorize(&request(ctx.clone()));
            assert_deny(decision, DenyReason::InvalidContext, None);

            // The explanation reports the same rejection with an empty
            // trace: no rule ever saw the non-canonical context.
            let explanation = engine.explain(&request(ctx));
            assert!(explanation.considered.is_empty());
            assert_deny(explanation.decision, DenyReason::InvalidContext, None);
        }
    }

    #[test]
    fn canonical_root_path_is_authorizable() {
        let mut doc = plan_document();
        doc.name = PolicyName::parse("coding-agent-root").unwrap();
        doc.http.allow.push(rule(&[HttpMethod::HEAD], &["/**"]));
        let engine = RuleEngine::from_documents([doc]).unwrap();
        assert!(matches!(
            engine.authorize(&request(context(HttpMethod::HEAD, "/"))),
            AuthorizationDecision::Allow { .. }
        ));
    }

    #[test]
    fn duplicate_policy_names_are_rejected() {
        let mut engine = RuleEngine::new();
        engine.push(plan_document()).unwrap();

        let duplicate = plan_document();
        let err = engine.push(duplicate).unwrap_err();
        assert!(matches!(err, PolicyError::DuplicatePolicyName(_)));
        assert_eq!(engine.policies().len(), 1);

        let from_docs = RuleEngine::from_documents([plan_document(), plan_document()]);
        assert!(matches!(
            from_docs.unwrap_err(),
            PolicyError::DuplicatePolicyName(_)
        ));

        // Distinct names still coexist.
        let mut other = plan_document();
        other.name = PolicyName::parse("coding-agent-other").unwrap();
        let engine = RuleEngine::from_documents([plan_document(), other]).unwrap();
        assert_eq!(engine.policies().len(), 2);
    }

    #[test]
    fn no_matching_allow_rule_denies() {
        let engine = RuleEngine::from_documents([plan_document()]).unwrap();
        // POST to a path only covered by GET rules.
        assert_deny(
            engine.authorize(&request(context(
                HttpMethod::POST,
                "/repos/acme/backend/issues",
            ))),
            DenyReason::NoMatchingAllow,
            Some("coding-agent-github"),
        );
        // GET outside the allowed prefix.
        assert_deny(
            engine.authorize(&request(context(HttpMethod::GET, "/orgs/acme/members"))),
            DenyReason::NoMatchingAllow,
            Some("coding-agent-github"),
        );
    }

    #[test]
    fn wrong_host_denies() {
        let engine = RuleEngine::from_documents([plan_document()]).unwrap();
        let mut ctx = context(HttpMethod::GET, "/repos/acme/backend/issues");
        ctx.host = "evil.example.com".to_owned();
        assert_deny(
            engine.authorize(&request(ctx.clone())),
            DenyReason::NoMatchingAllow,
            Some("coding-agent-github"),
        );
        let explanation = engine.explain(&request(ctx));
        assert_eq!(
            explanation.considered[0].outcome,
            CandidateOutcome::DeniedByHost
        );
    }

    #[test]
    fn environment_not_in_allowlist_denies() {
        let engine = RuleEngine::from_documents([plan_document()]).unwrap();

        let mut ctx = context(HttpMethod::GET, "/repos/acme/backend/issues");
        ctx.environment = Some(env("env_production"));
        assert_deny(
            engine.authorize(&request(ctx)),
            DenyReason::EnvironmentDenied,
            Some("coding-agent-github"),
        );

        // Unknown (absent) environment fails a non-empty allowlist too.
        let mut ctx = context(HttpMethod::GET, "/repos/acme/backend/issues");
        ctx.environment = None;
        assert_deny(
            engine.authorize(&request(ctx)),
            DenyReason::EnvironmentDenied,
            Some("coding-agent-github"),
        );
    }

    #[test]
    fn absent_allowlist_permits_any_environment() {
        let mut doc = plan_document();
        doc.environment.allow.clear();
        doc.name = PolicyName::parse("coding-agent-any-env").unwrap();
        let engine = RuleEngine::from_documents([doc]).unwrap();

        for environment in [None, Some(env("env_prod")), Some(env("env_staging"))] {
            let mut ctx = context(HttpMethod::GET, "/repos/acme/backend/issues");
            ctx.environment = environment;
            assert!(matches!(
                engine.authorize(&request(ctx)),
                AuthorizationDecision::Allow { .. }
            ));
        }
    }

    #[test]
    fn body_too_large_denies_only_after_allow_match() {
        let mut doc = plan_document();
        doc.request.max_body_bytes = Some(100);
        let engine = RuleEngine::from_documents([doc]).unwrap();

        // Allow rule matched but the body exceeds the limit.
        let mut ctx = context(HttpMethod::GET, "/repos/acme/backend/issues");
        ctx.body_len_bytes = 101;
        assert_deny(
            engine.authorize(&request(ctx)),
            DenyReason::BodyTooLarge,
            Some("coding-agent-github"),
        );

        // Exactly at the limit passes.
        let mut ctx = context(HttpMethod::GET, "/repos/acme/backend/issues");
        ctx.body_len_bytes = 100;
        assert!(matches!(
            engine.authorize(&request(ctx)),
            AuthorizationDecision::Allow { .. }
        ));

        // No allow rule matched: NoMatchingAllow is reported even with an
        // oversized body because constraints are checked after allow rules.
        let mut ctx = context(HttpMethod::GET, "/outside/prefix");
        ctx.body_len_bytes = 101;
        assert_deny(
            engine.authorize(&request(ctx)),
            DenyReason::NoMatchingAllow,
            Some("coding-agent-github"),
        );
    }

    #[test]
    fn non_candidate_policies_are_skipped_silently() {
        let mut wrong_principal = plan_document();
        wrong_principal.principal = Principal::parse("session:sess_other").unwrap();
        let engine = RuleEngine::from_documents([wrong_principal]).unwrap();
        let explanation = engine.explain(&request(context(HttpMethod::GET, "/repos/acme")));
        assert!(explanation.considered.is_empty());
        assert_deny(explanation.decision, DenyReason::NoMatchingPolicy, None);

        let mut wrong_credential = plan_document();
        wrong_credential.credential = CredentialRef::parse("other-token").unwrap();
        let engine = RuleEngine::from_documents([wrong_credential]).unwrap();
        let explanation = engine.explain(&request(context(HttpMethod::GET, "/repos/acme")));
        assert!(explanation.considered.is_empty());
        assert_deny(explanation.decision, DenyReason::NoMatchingPolicy, None);
    }

    #[test]
    fn explain_lists_considered_policy_names_and_outcomes() {
        let failing_env = plan_document();
        let mut allowing = plan_document();
        allowing.name = PolicyName::parse("coding-agent-broad").unwrap();
        allowing.environment.allow.clear();
        allowing.http.allow.push(rule(
            &[HttpMethod::GET],
            &["/repos/acme/backend/**", "/extra/*"],
        ));

        // Request hits production: first candidate fails the environment
        // gate, second allows.
        let mut ctx = context(HttpMethod::GET, "/repos/acme/backend/issues");
        ctx.environment = Some(env("env_prod"));
        let engine = RuleEngine::from_documents([failing_env, allowing]).unwrap();
        let explanation = engine.explain(&request(ctx));

        let names: Vec<_> = explanation
            .considered
            .iter()
            .map(|c| c.policy.as_str())
            .collect();
        assert_eq!(names, vec!["coding-agent-github", "coding-agent-broad"]);
        assert_eq!(
            explanation.considered[0].outcome,
            CandidateOutcome::DeniedByEnvironment
        );
        assert_eq!(explanation.considered[1].outcome, CandidateOutcome::Allowed);
        assert!(matches!(
            explanation.decision,
            AuthorizationDecision::Allow { .. }
        ));

        // Nothing matches at all: no candidates considered.
        let mut ctx = context(HttpMethod::GET, "/nowhere");
        ctx.host = "unknown.host".to_owned();
        let empty_engine = RuleEngine::new();
        let explanation = empty_engine.explain(&request(ctx));
        assert!(explanation.considered.is_empty());
    }

    #[test]
    fn compiled_policy_validates_upfront() {
        let mut invalid = plan_document();
        invalid.http.allow.clear();
        assert!(matches!(
            CompiledPolicy::compile(invalid),
            Err(PolicyError::InvalidPolicy { field, .. }) if field == "http.allow"
        ));

        let valid = plan_document();
        let compiled = CompiledPolicy::compile(valid).unwrap();
        assert_eq!(compiled.document().name.as_str(), "coding-agent-github");

        // push() rejects invalid documents and leaves the engine untouched.
        let mut engine = RuleEngine::from_documents([plan_document()]).unwrap();
        let mut bad = plan_document();
        bad.request.max_body_bytes = Some(0);
        assert!(engine.push(bad).is_err());
        assert_eq!(engine.policies().len(), 1);
    }

    #[test]
    fn document_without_optional_sections_still_compiles() {
        let yaml = r#"
name: minimal-policy
principal: session:sess_abc123
credential: github-work-token
http:
  hosts: [api.github.com]
  allow:
    - methods: [HEAD]
      paths: ["/health"]
"#;
        let doc = crate::loader::parse_policy_yaml(yaml).unwrap();
        assert!(matches!(
            doc.environment,
            EnvironmentRules { ref allow } if allow.is_empty()
        ));
        assert_eq!(doc.request, RequestConstraints::default());
        let engine = RuleEngine::from_documents([doc]).unwrap();
        let req = AuthorizationRequest {
            principal: Principal::parse("session:sess_abc123").unwrap(),
            action: Action::HttpRequest,
            resource: CredentialRef::parse("github-work-token").unwrap(),
            context: AuthorizationContext {
                host: "api.github.com".to_owned(),
                method: HttpMethod::HEAD,
                path: "/health".to_owned(),
                query: BTreeMap::new(),
                body_len_bytes: 0,
                environment: None,
            },
        };
        assert!(matches!(
            engine.authorize(&req),
            AuthorizationDecision::Allow { .. }
        ));
    }
}

/// Property test for plan §36 INV-009 ("Policy defaults to deny") and
/// plan §43's default-deny posture: arbitrary requests are denied by an
/// empty engine and by engines holding only non-candidate policies.
#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::BTreeMap;
    use vaultx_types::CredentialRef;

    /// Content for generated IDs; first character avoids letters that
    /// begin registered ID prefixes so typed-ID parsing stays total.
    fn hosts() -> impl Strategy<Value = String> {
        proptest::collection::vec("[a-z][a-z0-9]{1,7}", 1..=3usize)
            .prop_map(|labels| labels.join("."))
            .boxed()
    }

    fn paths() -> impl Strategy<Value = String> {
        // Segments exclude `.` / `..` / empty so every generated context
        // passes canonical validation; this property pins rule-level
        // default denial, not the separate invalid-context rejection.
        prop_oneof![
            Just("/".to_owned()),
            proptest::collection::vec("[a-z0-9_~-]{1,8}", 1..=3usize)
                .prop_map(|segments| format!("/{}", segments.join("/"))),
        ]
    }

    fn methods() -> impl Strategy<Value = HttpMethod> {
        prop::sample::select(vec![
            HttpMethod::GET,
            HttpMethod::POST,
            HttpMethod::PUT,
            HttpMethod::PATCH,
            HttpMethod::DELETE,
            HttpMethod::HEAD,
            HttpMethod::OPTIONS,
        ])
    }

    fn request_for(host: String, method: HttpMethod, path: String) -> AuthorizationRequest {
        AuthorizationRequest {
            principal: Principal::parse("agent:prop-agent").unwrap(),
            action: Action::HttpRequest,
            resource: CredentialRef::parse("prop-token").unwrap(),
            context: AuthorizationContext {
                host,
                method,
                path,
                query: BTreeMap::new(),
                body_len_bytes: 0,
                environment: None,
            },
        }
    }

    /// A valid document bound to a different principal than
    /// [`request_for`] uses — never a candidate for its requests.
    fn wrong_principal_document(host: &str) -> PolicyDocument {
        crate::loader::parse_policy_yaml(&format!(
            "name: prop-other-principal\n\
             principal: session:sess_unrelated\n\
             credential: prop-token\n\
             http:\n\
             \x20 hosts: [{host}]\n\
             \x20 allow:\n\
             \x20   - methods: [GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS]\n\
             \x20     paths: [\"/**\"]\n"
        ))
        .unwrap()
    }

    /// A valid document bound to a different credential — also never a
    /// candidate.
    fn wrong_credential_document(host: &str) -> PolicyDocument {
        let mut document = wrong_principal_document(host);
        document.principal = Principal::parse("agent:prop-agent").unwrap();
        document.credential = CredentialRef::parse("other-token").unwrap();
        document.name = PolicyName::parse("prop-other-credential").unwrap();
        document
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn empty_and_mismatched_engines_default_deny_arbitrary_requests(
            host in hosts(),
            method in methods(),
            path in paths(),
            body_len in any::<u64>(),
        ) {
            let mut request = request_for(host.clone(), method, path);
            request.context.body_len_bytes = body_len;

            let empty = RuleEngine::new();
            assert!(matches!(
                empty.authorize(&request),
                AuthorizationDecision::Deny {
                    reason: DenyReason::NoMatchingPolicy,
                    policy: None,
                }
            ));

            let mismatched = RuleEngine::from_documents([
                wrong_principal_document(&host),
                wrong_credential_document(&host),
            ])
            .unwrap();
            assert!(matches!(
                mismatched.authorize(&request),
                AuthorizationDecision::Deny {
                    reason: DenyReason::NoMatchingPolicy,
                    policy: None,
                }
            ));
        }
    }
}
