//! Cedar-backed [`Authorizer`] implementation (plan §22: Cedar behind the
//! internal trait).
//!
//! Each validated [`PolicyDocument`] is translated into equivalent Cedar
//! policy text scoped with string-literal entity UIDs
//! (`Agent::"agent:x"` / `Session::"session:y"`,
//! `Credential::"<ref>"`, `Action::"http_request"`); request metadata rides
//! in the Cedar context record (`host`, `method`, `path`, `environment`).
//! The translation is exact:
//!
//! * every explicit deny rule becomes one `forbid` policy;
//! * every document becomes exactly one `permit` policy whose condition
//!   conjoins the environment allowlist, the host list, and the disjunction
//!   of its allow rules — so a satisfied permit corresponds 1:1 with a
//!   candidate passing the native gates;
//! * Cedar's global forbid-beats-permit semantics reproduce the native
//!   explicit-deny-first evaluation order because forbid conditions never
//!   mention environment/host/body gates.
//!
//! # Glob translation policy (fail-closed)
//!
//! Cedar has no glob operator, so path patterns are translated into exact
//! string predicates:
//!
//! * literal patterns become `context.path == "<pattern>"`;
//! * a trailing `/**` becomes
//!   `context.path == "<prefix>" || context.path like "<prefix>/*"`
//!   (the zero-segment boundary case included; Cedar's `like` wildcard
//!   matches any remaining characters), and bare `/**` becomes
//!   `context.path like "/*"`. Literal stars inside the prefix are escaped
//!   as `\*`, so the translation stays exact for arbitrary segment text;
//! * a `*` wildcard in any *non-final* position cannot be encoded exactly:
//!   one prefix-style `like` predicate would over-match across extra
//!   segments, so such a document **refuses compilation** with
//!   [`PolicyError::CedarUnsupportedPattern`] naming the offending pattern.
//!   Nothing is approximated; the failure is loud and attributed. A
//!   trailing single `*` (exactly-one-segment semantics) is equally
//!   unencodable and rejected the same way.
//!
//! The request-body limit stays **outside** Cedar: after a `Permit`, the
//! satisfied permits are mapped back to their documents and checked in
//! insertion order exactly like the native engine's final gate, so
//! decisions and attributions match [`crate::RuleEngine`] even when
//! candidates disagree on `request.max_body_bytes`.
//!
//! Non-canonical contexts are rejected with [`DenyReason::InvalidContext`]
//! before Cedar ever sees them, mirroring the canonicalization contract
//! documented on [`crate::RuleEngine`].

use std::collections::BTreeMap;

use cedar_policy::{
    Authorizer as CedarEngine, Context, Decision, Entities, EntityUid, Policy, PolicyId, PolicySet,
    Request,
};
use vaultx_types::{EnvironmentId, PolicyName};

use crate::engine::{
    AuthorizationDecision, AuthorizationRequest, Authorizer, CandidateEvaluation, CandidateOutcome,
    DenyReason, PolicyExplanation,
};
use crate::error::PolicyError;
use crate::matcher::validate_pattern;
use crate::model::{MethodPathRule, PolicyDocument, Principal, PRINCIPAL_AGENT_PREFIX};

/// Cedar UID text for the single supported action.
const ACTION_UID_TEXT: &str = "Action::\"http_request\"";

/// One compiled Cedar policy statement plus its stable `@id`.
struct CedarStatement {
    id: String,
    text: String,
}

/// Escapes `value` for embedding inside a double-quoted Cedar string
/// literal.
fn escape_cedar_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{{{:x}}}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Escapes `value` for embedding inside a Cedar `like` pattern literal:
/// backslashes and stars are escaped so every star we emit is an intended
/// wildcard, on top of the plain string-literal escapes.
fn escape_like_pattern(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '*' => out.push_str("\\*"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&escape_cedar_string(&c.to_string())),
            c => out.push(c),
        }
    }
    out
}

/// Builds `Type::"id"` UID text with escaping applied to `id`.
fn entity_uid_text(type_name: &str, id: &str) -> String {
    format!("{type_name}::\"{}\"", escape_cedar_string(id))
}

/// Maps a [`Principal`] onto its typed Cedar UID: agents use the `Agent`
/// entity type, sessions the `Session` type; the EID keeps the full
/// `scheme:identity` spelling so round-trips stay lossless.
fn principal_uid_text(principal: &Principal) -> String {
    if principal.as_str().starts_with(PRINCIPAL_AGENT_PREFIX) {
        entity_uid_text("Agent", principal.as_str())
    } else {
        entity_uid_text("Session", principal.as_str())
    }
}

/// Translates one path pattern into an exact Cedar predicate.
///
/// # Errors
/// Returns the pattern-validation error verbatim for malformed input and
/// [`PolicyError::CedarUnsupportedPattern`] for mid-pattern wildcards.
fn path_condition(doc: &PolicyName, pattern: &str) -> Result<String, PolicyError> {
    validate_pattern(pattern)?;
    let segments: Vec<&str> = pattern[1..].split('/').collect();
    match segments.split_last() {
        Some((last, prefix)) if *last == "**" => {
            let prefix_path = format!("/{}", prefix.join("/"));
            if prefix.is_empty() {
                Ok("context.path like \"/*\"".to_owned())
            } else {
                let literal = escape_cedar_string(&prefix_path);
                let like_tail = escape_like_pattern(&prefix_path);
                // Parenthesized: the disjunction must never leak into an
                // enclosing && / || chain ungrouped.
                Ok(format!(
                    "(context.path == \"{literal}\" || context.path like \"{like_tail}/*\")"
                ))
            }
        }
        _ => {
            if segments.contains(&"*") {
                return Err(PolicyError::CedarUnsupportedPattern {
                    policy: doc.to_string(),
                    pattern: pattern.to_owned(),
                });
            }
            Ok(format!(
                "context.path == \"{}\"",
                escape_cedar_string(pattern)
            ))
        }
    }
}

/// Builds the `[...]`-membership predicate used for method/host/environment
/// allowlists.
fn membership_predicate(attribute: &str, values: &[String]) -> String {
    let items: Vec<String> = values
        .iter()
        .map(|value| format!("\"{}\"", escape_cedar_string(value)))
        .collect();
    format!("[{}].contains(context.{attribute})", items.join(", "))
}

/// Translates one method+path rule into a Cedar condition.
fn rule_condition(doc: &PolicyName, rule: &MethodPathRule) -> Result<String, PolicyError> {
    let methods: Vec<String> = rule
        .methods
        .iter()
        .map(|method| method.as_str().to_owned())
        .collect();
    debug_assert!(!methods.is_empty());
    let method_part = membership_predicate("method", &methods);

    let path_parts: Vec<String> = rule
        .paths
        .iter()
        .map(|pattern| path_condition(doc, pattern))
        .collect::<Result<_, _>>()?;
    let path_part = if path_parts.len() == 1 {
        path_parts.into_iter().next().expect("non-empty")
    } else {
        format!("({})", path_parts.join(" || "))
    };
    // Parenthesized so a rule never bleeds into the enclosing disjunction.
    Ok(format!("({method_part} && {path_part})"))
}

/// Translates one validated [`PolicyDocument`] into its Cedar policy
/// statements: one `forbid` per deny rule plus a single conjunction-shaped
/// `permit`. Statement ids are `<name>#allow` and `<name>#deny#<i>` so
/// evaluation results always map back to their source document.
///
/// # Errors
/// Fails closed on any validation error or untranslatable glob (see the
/// module-level glob policy).
fn compile_statements(document: &PolicyDocument) -> Result<Vec<CedarStatement>, PolicyError> {
    crate::loader::validate_policy(document)?;

    let name = &document.name;
    let principal = principal_uid_text(&document.principal);
    let resource = entity_uid_text("Credential", document.credential.as_str());

    // Cedar 4.x assigns ids through the parse API (`Policy::parse`), not
    // through an annotation, so the id travels alongside the text.
    let build_statement = |id: String, effect: &str, condition: String| CedarStatement {
        text: format!(
            "{effect}(principal == {principal}, \
                 action == {ACTION_UID_TEXT}, resource == {resource})\nwhen {{ {condition} }};"
        ),
        id,
    };

    let mut statements = Vec::new();
    for (index, rule) in document.http.deny.iter().enumerate() {
        let condition = rule_condition(name, rule)?;
        statements.push(build_statement(
            format!("{}#deny#{index}", name.as_str()),
            "forbid",
            condition,
        ));
    }

    let allow_conditions: Vec<String> = document
        .http
        .allow
        .iter()
        .map(|rule| rule_condition(name, rule))
        .collect::<Result<_, _>>()?;
    let allow_disjunction = if allow_conditions.len() == 1 {
        allow_conditions.into_iter().next().expect("non-empty")
    } else {
        format!("({})", allow_conditions.join(" || "))
    };

    let mut permit_parts = Vec::new();
    if !document.environment.allow.is_empty() {
        let environments: Vec<String> = document
            .environment
            .allow
            .iter()
            .map(|environment| environment.as_str().to_owned())
            .collect();
        permit_parts.push(membership_predicate("environment", &environments));
    }
    permit_parts.push(membership_predicate("host", &document.http.hosts));
    permit_parts.push(allow_disjunction);

    statements.push(build_statement(
        format!("{}#allow", name.as_str()),
        "permit",
        permit_parts.join(" && "),
    ));
    Ok(statements)
}

/// Renders the human-readable Cedar policy text for one document (the
/// `vaultx policy cedar` view).
///
/// # Errors
/// Fails closed on any validation error or untranslatable glob, exactly
/// like engine construction.
pub fn compile_document_to_cedar(document: &PolicyDocument) -> Result<String, PolicyError> {
    let texts: Vec<String> = compile_statements(document)?
        .into_iter()
        .map(|statement| statement.text)
        .collect();
    Ok(texts.join("\n"))
}

/// Which side of the decision a compiled Cedar policy belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum StatementKind {
    Allow,
    Deny,
}

/// Bookkeeping for one compiled document inside a [`CedarAuthorizer`].
#[derive(Clone, Debug)]
struct CompiledDocument {
    name: PolicyName,
    max_body_bytes: Option<u64>,
}

/// Cedar-backed [`Authorizer`] over a set of policy documents.
///
/// Decisions are deny-by-default and attribute explicit denials to the
/// first (insertion-order) document whose deny rule matched, matching
/// [`crate::RuleEngine`]. Documents whose patterns cannot be expressed
/// exactly in Cedar refuse compilation (see the module glob policy).
#[derive(Debug)]
pub struct CedarAuthorizer {
    engine: CedarEngine,
    policies: PolicySet,
    documents: Vec<CompiledDocument>,
    statement_docs: BTreeMap<PolicyId, usize>,
    statement_kinds: BTreeMap<PolicyId, StatementKind>,
}

impl CedarAuthorizer {
    /// Compiles every document into Cedar, validating each one and
    /// rejecting duplicate policy names exactly like
    /// [`crate::RuleEngine::from_documents`].
    ///
    /// # Errors
    /// Returns validation failures, duplicate-name errors, Cedar parse
    /// failures ([`PolicyError::CedarCompile`]), and unsupported-glob
    /// rejections ([`PolicyError::CedarUnsupportedPattern`]).
    pub fn from_documents<I>(documents: I) -> Result<Self, PolicyError>
    where
        I: IntoIterator<Item = PolicyDocument>,
    {
        let mut authorizer = Self {
            engine: CedarEngine::new(),
            policies: PolicySet::new(),
            documents: Vec::new(),
            statement_docs: BTreeMap::new(),
            statement_kinds: BTreeMap::new(),
        };
        for document in documents {
            let name = document.name.clone();
            if authorizer
                .documents
                .iter()
                .any(|existing| existing.name == name)
            {
                return Err(PolicyError::DuplicatePolicyName(name));
            }
            let index = authorizer.documents.len();
            for stmt in compile_statements(&document)? {
                let kind = if stmt.id.ends_with("#allow") {
                    StatementKind::Allow
                } else {
                    StatementKind::Deny
                };
                let policy_id = PolicyId::new(stmt.id.clone());
                let policy = Policy::parse(Some(policy_id.clone()), stmt.text)
                    .map_err(|err| PolicyError::CedarCompile(name.to_string(), err.to_string()))?;
                authorizer
                    .policies
                    .add(policy)
                    .map_err(|err| PolicyError::CedarCompile(name.to_string(), err.to_string()))?;
                authorizer.statement_docs.insert(policy_id.clone(), index);
                authorizer.statement_kinds.insert(policy_id, kind);
            }
            authorizer.documents.push(CompiledDocument {
                name,
                max_body_bytes: document.request.max_body_bytes,
            });
        }
        Ok(authorizer)
    }

    /// Shared evaluation core; mirrors [`crate::RuleEngine`]'s decision
    /// contract. When `trace` is `Some`, every Cedar policy that determined
    /// the outcome is recorded (Cedar exposes no per-candidate gate trace,
    /// so failing candidates are intentionally not listed).
    fn evaluate(
        &self,
        request: &AuthorizationRequest,
        mut trace: Option<&mut Vec<CandidateEvaluation>>,
    ) -> AuthorizationDecision {
        if request.context.validate().is_err() {
            return AuthorizationDecision::Deny {
                reason: DenyReason::InvalidContext,
                policy: None,
            };
        }

        // Any failure while assembling Cedar's inputs is fail-closed.
        let fail_closed = || AuthorizationDecision::Deny {
            reason: DenyReason::NoMatchingPolicy,
            policy: None,
        };
        // Reborrowing push so a trace can be appended many times.
        fn push_trace(
            trace: &mut Option<&mut Vec<CandidateEvaluation>>,
            policy: PolicyName,
            outcome: CandidateOutcome,
        ) {
            if let Some(entries) = trace.as_deref_mut() {
                entries.push(CandidateEvaluation { policy, outcome });
            }
        }

        let context_json = serde_json::json!({
            "host": request.context.host,
            "method": request.context.method.as_str(),
            "path": request.context.path,
            "environment": request
                .context
                .environment
                .as_ref()
                .map(EnvironmentId::as_str)
                .unwrap_or_default(),
        });
        let (Ok(context), Ok(principal), Ok(resource), Ok(action)) = (
            Context::from_json_value(context_json, None),
            principal_uid_text(&request.principal).parse::<EntityUid>(),
            entity_uid_text("Credential", request.resource.as_str()).parse::<EntityUid>(),
            ACTION_UID_TEXT.parse::<EntityUid>(),
        ) else {
            return fail_closed();
        };
        let cedar_request = match Request::new(principal, action, resource, context, None) {
            Ok(cedar_request) => cedar_request,
            Err(_) => return fail_closed(),
        };
        let entities = Entities::empty();

        let response = self
            .engine
            .is_authorized(&cedar_request, &self.policies, &entities);
        let mut determining: Vec<(usize, StatementKind)> = response
            .diagnostics()
            .reason()
            .filter_map(|policy_id| {
                Some((
                    *self.statement_docs.get(policy_id)?,
                    *self.statement_kinds.get(policy_id)?,
                ))
            })
            .collect();
        determining.sort_unstable();

        match response.decision() {
            Decision::Allow => {
                let permits: Vec<usize> = determining
                    .iter()
                    .filter(|(_, kind)| *kind == StatementKind::Allow)
                    .map(|(index, _)| *index)
                    .collect();
                let Some(first) = permits.first().copied() else {
                    // A Permit without an attributable satisfied permit
                    // cannot be trusted; fail closed rather than guess.
                    return fail_closed();
                };
                for index in permits {
                    let passes_body = self.documents[index]
                        .max_body_bytes
                        .is_none_or(|max| request.context.body_len_bytes <= max);
                    let name = self.documents[index].name.clone();
                    let outcome = if passes_body {
                        push_trace(&mut trace, name, CandidateOutcome::Allowed);
                        return AuthorizationDecision::Allow {
                            policy: self.documents[index].name.clone(),
                        };
                    } else {
                        CandidateOutcome::DeniedByBodyLimit
                    };
                    push_trace(&mut trace, self.documents[index].name.clone(), outcome);
                }
                AuthorizationDecision::Deny {
                    reason: DenyReason::BodyTooLarge,
                    policy: Some(self.documents[first].name.clone()),
                }
            }
            Decision::Deny => {
                let forbids: Vec<usize> = determining
                    .iter()
                    .filter(|(_, kind)| *kind == StatementKind::Deny)
                    .map(|(index, _)| *index)
                    .collect();
                let Some(first) = forbids.first().copied() else {
                    return fail_closed();
                };
                for index in forbids {
                    push_trace(
                        &mut trace,
                        self.documents[index].name.clone(),
                        CandidateOutcome::DeniedByExplicitDeny,
                    );
                }
                AuthorizationDecision::Deny {
                    reason: DenyReason::ExplicitDeny,
                    policy: Some(self.documents[first].name.clone()),
                }
            }
        }
    }

    /// Runs full evaluation and returns an explanation of how the decision
    /// was reached, listing the Cedar policies that determined the outcome.
    #[must_use]
    pub fn explain(&self, request: &AuthorizationRequest) -> PolicyExplanation {
        let mut considered = Vec::new();
        let decision = self.evaluate(request, Some(&mut considered));
        PolicyExplanation {
            decision,
            considered,
        }
    }
}

impl Authorizer for CedarAuthorizer {
    fn authorize(&self, request: &AuthorizationRequest) -> AuthorizationDecision {
        self.evaluate(request, None)
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use crate::loader::parse_policy_yaml;
    use crate::model::{AuthorizationContext, HttpMethod};
    use std::collections::BTreeMap;

    pub(crate) const PLAN_YAML: &str = r#"
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
"#;

    pub(crate) const LOADER_YAML: &str = r#"
name: coding-agent-loader
principal: agent:coding-agent
credential: github-work-token
environment:
  allow: [env_development]
http:
  hosts: [api.github.com]
  allow:
    - methods: [GET]
      paths: [/repos/acme/backend/**]
request:
  max_body_bytes: 262144
"#;

    pub(crate) const SESSION_MINIMAL_YAML: &str = r#"
name: minimal-session-health
principal: session:sess_abc123
credential: github-work-token
http:
  hosts: [api.github.com]
  allow:
    - methods: [HEAD]
      paths: [/health]
"#;

    pub(crate) const MULTI_HOST_EXACT_YAML: &str = r#"
name: multi-host-exact
principal: agent:release-bot
credential: deploy-token
environment:
  allow: [env_prod, env_staging]
http:
  hosts: [api.example.com, builds.example.org]
  allow:
    - methods: [POST, PUT]
      paths: [/api/v1/deploy, /api/v1/rollback]
  deny:
    - methods: [DELETE]
      paths: [/api/v1/deploy]
"#;

    pub(crate) const ROOT_ALL_YAML: &str = r#"
name: root-all-methods
principal: agent:wide-agent
credential: wide-token
http:
  hosts: [wide.example.com]
  allow:
    - methods: [GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS]
      paths: ["/**"]
request:
  max_body_bytes: 100
"#;

    pub(crate) const DEEP_GLOB_DENY_YAML: &str = r#"
name: deep-glob-deny
principal: agent:deep-agent
credential: deep-token
http:
  hosts: [deep.example.com]
  allow:
    - methods: [GET]
      paths: [/repos/**]
  deny:
    - methods: [POST]
      paths: [/repos/acme/**]
"#;

    /// Every compilable fixture document used by the differential suites.
    pub(crate) fn corpus() -> Vec<PolicyDocument> {
        [
            PLAN_YAML,
            LOADER_YAML,
            SESSION_MINIMAL_YAML,
            MULTI_HOST_EXACT_YAML,
            ROOT_ALL_YAML,
            DEEP_GLOB_DENY_YAML,
        ]
        .iter()
        .map(|yaml| parse_policy_yaml(yaml).unwrap())
        .collect()
    }

    pub(crate) fn make_request(
        principal: &str,
        credential: &str,
        host: &str,
        method: HttpMethod,
        path: &str,
        environment: Option<&str>,
        body: u64,
    ) -> AuthorizationRequest {
        AuthorizationRequest {
            principal: Principal::parse(principal).unwrap(),
            action: crate::model::Action::HttpRequest,
            resource: crate::Resource::parse(credential).unwrap(),
            context: AuthorizationContext {
                host: host.to_owned(),
                method,
                path: path.to_owned(),
                query: BTreeMap::new(),
                body_len_bytes: body,
                environment: environment.map(EnvironmentId::parse).transpose().unwrap(),
            },
        }
    }

    fn deny_parts(decision: &AuthorizationDecision) -> Option<(DenyReason, Option<&str>)> {
        match decision {
            AuthorizationDecision::Allow { .. } => None,
            AuthorizationDecision::Deny { reason, policy } => {
                Some((*reason, policy.as_ref().map(PolicyName::as_str)))
            }
        }
    }

    /// Allow ⟺ allow; whenever either side reports `ExplicitDeny`, both
    /// sides must and must attribute the identical document.
    pub(crate) fn assert_decision_parity(
        native: &AuthorizationDecision,
        cedar: &AuthorizationDecision,
        description: &str,
    ) {
        match (native, cedar) {
            (AuthorizationDecision::Allow { .. }, AuthorizationDecision::Allow { .. }) => {}
            (left, right) => {
                let native_deny = deny_parts(left).unwrap_or_else(|| {
                    panic!("allow vs deny ({description}): native={left:?} cedar={right:?}")
                });
                let cedar_deny = deny_parts(right).unwrap_or_else(|| {
                    panic!("deny vs allow ({description}): native={left:?} cedar={right:?}")
                });
                if native_deny.0 == DenyReason::ExplicitDeny
                    || cedar_deny.0 == DenyReason::ExplicitDeny
                {
                    assert_eq!(
                        native_deny, cedar_deny,
                        "explicit-deny attribution drift ({description})"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use crate::model::HttpMethod;

    fn cedar_engine_from(yaml: &str) -> CedarAuthorizer {
        CedarAuthorizer::from_documents([crate::parse_policy_yaml(yaml).unwrap()]).unwrap()
    }

    fn native_engine_from(yaml: &str) -> crate::RuleEngine {
        crate::RuleEngine::from_documents([crate::parse_policy_yaml(yaml).unwrap()]).unwrap()
    }

    #[test]
    fn compiled_text_contains_expected_shapes() {
        let doc = crate::parse_policy_yaml(PLAN_YAML).unwrap();
        let text = compile_document_to_cedar(&doc).unwrap();
        assert!(text.contains("permit(principal == Agent::\"agent:coding-agent\""));
        assert!(text.contains("when {"));
        assert!(text.contains("[\"DELETE\"].contains(context.method)"));
        assert!(text.contains(
            "(context.path == \"/repos/acme/backend\" || context.path like \"/repos/acme/backend/*\")"
        ));
        assert!(text.contains("[\"env_development\"].contains(context.environment)"));

        // Every generated statement must round-trip through Cedar's parser.
        for statement in compile_statements(&doc).unwrap() {
            Policy::parse(None, statement.text.as_str())
                .unwrap_or_else(|err| panic!("statement {} must parse: {err}", statement.id));
        }
    }

    #[test]
    fn trailing_glob_boundary_cases_match_native() {
        let native = native_engine_from(PLAN_YAML);
        let cedar = cedar_engine_from(PLAN_YAML);

        let cases = [
            ("/repos/acme/backend", true),
            ("/repos/acme/backend/issues", true),
            ("/repos/acme/backend/a/b/c", true),
            ("/repos/acme/backendX", false),
            ("/repos/acme/backe", false),
            ("/repos/acme", false),
            ("/", false),
        ];
        for (path, expected) in cases {
            let req = make_request(
                "agent:coding-agent",
                "github-work-token",
                "api.github.com",
                HttpMethod::GET,
                path,
                Some("env_development"),
                0,
            );
            let n = native.authorize(&req);
            let c = cedar.authorize(&req);
            assert_eq!(
                matches!(n, AuthorizationDecision::Allow { .. }),
                expected,
                "native mismatch for {path}"
            );
            assert_decision_parity(&n, &c, path);
        }
    }

    #[test]
    fn basic_decisions_match_rule_engine() {
        let native = native_engine_from(PLAN_YAML);
        let cedar = cedar_engine_from(PLAN_YAML);

        let cases = vec![
            // Happy path.
            make_request(
                "agent:coding-agent",
                "github-work-token",
                "api.github.com",
                HttpMethod::GET,
                "/repos/acme/backend/issues",
                Some("env_development"),
                0,
            ),
            // Wrong environment.
            make_request(
                "agent:coding-agent",
                "github-work-token",
                "api.github.com",
                HttpMethod::GET,
                "/repos/acme/backend/issues",
                Some("env_prod"),
                0,
            ),
            // Absent environment fails the allowlist.
            make_request(
                "agent:coding-agent",
                "github-work-token",
                "api.github.com",
                HttpMethod::GET,
                "/repos/acme/backend/issues",
                None,
                0,
            ),
            // Wrong host.
            make_request(
                "agent:coding-agent",
                "github-work-token",
                "evil.example.com",
                HttpMethod::GET,
                "/repos/acme/backend/issues",
                Some("env_development"),
                0,
            ),
            // Method not allowed on matching path.
            make_request(
                "agent:coding-agent",
                "github-work-token",
                "api.github.com",
                HttpMethod::PUT,
                "/repos/acme/backend/issues",
                Some("env_development"),
                0,
            ),
            // Explicit deny beats everything.
            make_request(
                "agent:coding-agent",
                "github-work-token",
                "api.github.com",
                HttpMethod::DELETE,
                "/anything/at/all",
                Some("env_development"),
                0,
            ),
            // Non-candidate principal / credential.
            make_request(
                "agent:other",
                "github-work-token",
                "api.github.com",
                HttpMethod::GET,
                "/repos/acme/backend/issues",
                Some("env_development"),
                0,
            ),
            make_request(
                "agent:coding-agent",
                "other-token",
                "api.github.com",
                HttpMethod::GET,
                "/repos/acme/backend/issues",
                Some("env_development"),
                0,
            ),
            // Body limit honored at and beyond the boundary.
            make_request(
                "agent:coding-agent",
                "github-work-token",
                "api.github.com",
                HttpMethod::POST,
                "/repos/acme/backend/pulls",
                Some("env_development"),
                262_144,
            ),
            make_request(
                "agent:coding-agent",
                "github-work-token",
                "api.github.com",
                HttpMethod::POST,
                "/repos/acme/backend/pulls",
                Some("env_development"),
                262_145,
            ),
            // Non-canonical contexts are rejected before evaluation.
            make_request(
                "agent:coding-agent",
                "github-work-token",
                "API.GitHub.com",
                HttpMethod::GET,
                "/repos/acme/backend/issues",
                Some("env_development"),
                0,
            ),
            make_request(
                "agent:coding-agent",
                "github-work-token",
                "api.github.com",
                HttpMethod::GET,
                "/repos/../secrets",
                Some("env_development"),
                0,
            ),
            make_request(
                "agent:coding-agent",
                "github-work-token",
                "api.github.com",
                HttpMethod::GET,
                "/double//slash",
                Some("env_development"),
                0,
            ),
        ];

        for req in &cases {
            let n = native.authorize(req);
            let c = cedar.authorize(req);
            assert_decision_parity(&n, &c, &format!("{req:?}"));
        }

        let allows = cases
            .iter()
            .filter(|req| matches!(native.authorize(req), AuthorizationDecision::Allow { .. }))
            .count();
        assert_eq!(allows, 2, "fixture should mix allows and denies");
    }

    #[test]
    fn cross_candidate_explicit_deny_attribution_is_order_independent() {
        let mut broad = crate::parse_policy_yaml(ROOT_ALL_YAML).unwrap();
        broad.principal = Principal::parse("agent:coding-agent").unwrap();
        broad.credential = crate::Resource::parse("github-work-token").unwrap();
        broad.name = PolicyName::parse("coding-agent-broad").unwrap();
        broad.http.hosts = vec!["api.github.com".to_owned()];
        broad.request.max_body_bytes = None;

        for order in 0..2 {
            let documents: Vec<PolicyDocument> = if order == 0 {
                vec![broad.clone(), crate::parse_policy_yaml(PLAN_YAML).unwrap()]
            } else {
                vec![crate::parse_policy_yaml(PLAN_YAML).unwrap(), broad.clone()]
            };
            let native = crate::RuleEngine::from_documents(documents.clone()).unwrap();
            let cedar = CedarAuthorizer::from_documents(documents).unwrap();
            let req = make_request(
                "agent:coding-agent",
                "github-work-token",
                "api.github.com",
                HttpMethod::DELETE,
                "/secret/x",
                None,
                0,
            );
            let n = native.authorize(&req);
            let c = cedar.authorize(&req);
            assert_decision_parity(&n, &c, "cross-candidate deny");
            assert!(matches!(
                &c,
                AuthorizationDecision::Deny {
                    reason: DenyReason::ExplicitDeny,
                    policy: Some(policy),
                } if policy.as_str() == "coding-agent-github"
            ));
        }
    }

    #[test]
    fn body_limit_gate_runs_outside_cedar_in_insertion_order() {
        // Two candidates: narrow caps bodies at 10 bytes; wide caps at 100.
        // A 50-byte body must fall through to the wide document, mirroring
        // the native engine's per-candidate gate order.
        let mut narrow = crate::parse_policy_yaml(MULTI_HOST_EXACT_YAML).unwrap();
        narrow.name = PolicyName::parse("body-narrow").unwrap();
        narrow.http.allow = vec![MethodPathRule {
            methods: vec![HttpMethod::POST],
            paths: vec!["/api/v1/deploy".to_owned()],
        }];
        narrow.request.max_body_bytes = Some(10);
        let wide = crate::parse_policy_yaml(ROOT_ALL_YAML).unwrap();

        let native = crate::RuleEngine::from_documents([narrow.clone(), wide.clone()]).unwrap();
        let cedar = CedarAuthorizer::from_documents([narrow, wide]).unwrap();

        let mid = make_request(
            "agent:wide-agent",
            "wide-token",
            "wide.example.com",
            HttpMethod::POST,
            "/anywhere",
            None,
            50,
        );
        assert!(matches!(
            native.authorize(&mid),
            AuthorizationDecision::Allow { .. }
        ));
        assert!(matches!(
            cedar.authorize(&mid),
            AuthorizationDecision::Allow { ref policy } if policy.as_str() == "root-all-methods"
        ));

        let huge = make_request(
            "agent:wide-agent",
            "wide-token",
            "wide.example.com",
            HttpMethod::POST,
            "/anywhere",
            None,
            500,
        );
        assert!(matches!(
            native.authorize(&huge),
            AuthorizationDecision::Deny {
                reason: DenyReason::BodyTooLarge,
                ..
            }
        ));
        assert!(matches!(
            cedar.authorize(&huge),
            AuthorizationDecision::Deny {
                reason: DenyReason::BodyTooLarge,
                ..
            }
        ));
    }

    #[test]
    fn empty_and_mismatched_engines_default_deny() {
        let cedar = CedarAuthorizer::from_documents([] as [PolicyDocument; 0]).unwrap();
        let req = make_request(
            "agent:anyone",
            "any-token",
            "example.com",
            HttpMethod::GET,
            "/x",
            None,
            0,
        );
        assert!(matches!(
            cedar.authorize(&req),
            AuthorizationDecision::Deny {
                reason: DenyReason::NoMatchingPolicy,
                policy: None,
            }
        ));
    }

    #[test]
    fn duplicate_names_are_rejected_like_the_native_engine() {
        let mut docs = corpus();
        docs.push(docs[0].clone());
        let err = CedarAuthorizer::from_documents(docs).unwrap_err();
        assert!(matches!(err, PolicyError::DuplicatePolicyName(_)));
    }

    #[test]
    fn explain_reports_determining_policies() {
        let cedar = cedar_engine_from(PLAN_YAML);
        let explanation = cedar.explain(&make_request(
            "agent:coding-agent",
            "github-work-token",
            "api.github.com",
            HttpMethod::GET,
            "/repos/acme/backend/issues",
            Some("env_development"),
            0,
        ));
        assert_eq!(explanation.considered.len(), 1);
        assert_eq!(
            explanation.considered[0].policy.as_str(),
            "coding-agent-github"
        );
        assert_eq!(explanation.considered[0].outcome, CandidateOutcome::Allowed);
        assert!(matches!(
            explanation.decision,
            AuthorizationDecision::Allow { .. }
        ));

        let denial = cedar.explain(&make_request(
            "agent:coding-agent",
            "github-work-token",
            "api.github.com",
            HttpMethod::DELETE,
            "/x",
            Some("env_development"),
            0,
        ));
        assert_eq!(
            denial.considered[0].outcome,
            CandidateOutcome::DeniedByExplicitDeny
        );
        assert!(matches!(
            denial.decision,
            AuthorizationDecision::Deny {
                reason: DenyReason::ExplicitDeny,
                ..
            }
        ));
    }

    #[test]
    fn mid_pattern_wildcard_refuses_cedar_compilation_with_named_pattern() {
        let yaml = r#"
name: wildcard-doc
principal: agent:wild
credential: wild-token
http:
  hosts: [api.wild.com]
  allow:
    - methods: [GET]
      paths: [/repos/*/issues]
"#;
        let doc = crate::parse_policy_yaml(yaml).unwrap();
        let err = compile_document_to_cedar(&doc).unwrap_err();
        match &err {
            PolicyError::CedarUnsupportedPattern { policy, pattern } => {
                assert_eq!(policy, "wildcard-doc");
                assert_eq!(pattern, "/repos/*/issues");
            }
            other => panic!("expected unsupported-pattern error, got {other:?}"),
        }
        assert!(err.to_string().contains("/repos/*/issues"));

        // Engine construction fails closed for the whole set.
        assert!(CedarAuthorizer::from_documents([doc]).is_err());
    }

    #[test]
    fn trailing_single_star_wildcard_is_also_rejected() {
        let yaml = r#"
name: star-tail-doc
principal: agent:wild
credential: wild-token
http:
  hosts: [api.wild.com]
  deny:
    - methods: [GET]
      paths: [/repos/*]
  allow:
    - methods: [GET]
      paths: ["/**"]
"#;
        let doc = crate::parse_policy_yaml(yaml).unwrap();
        let err = compile_document_to_cedar(&doc).unwrap_err();
        assert!(matches!(
            err,
            PolicyError::CedarUnsupportedPattern { ref pattern, .. } if pattern == "/repos/*"
        ));
    }
}

/// Differential suite: the fixture corpus evaluated by both engines over a
/// systematic request matrix must agree on the allow/deny boundary, and
/// explicit-denial attribution must be identical.
#[cfg(test)]
mod differential {
    use super::testing::*;
    use super::*;
    use crate::model::HttpMethod;

    #[test]
    fn corpus_matrix_agrees_on_allow_deny_boundary() {
        let documents = corpus();
        let native = crate::RuleEngine::from_documents(documents.clone()).unwrap();
        let cedar = CedarAuthorizer::from_documents(documents).unwrap();

        let principals = [
            "agent:coding-agent",
            "agent:release-bot",
            "agent:wide-agent",
            "agent:deep-agent",
            "session:sess_abc123",
            "agent:nobody",
        ];
        let credentials = [
            "github-work-token",
            "deploy-token",
            "wide-token",
            "deep-token",
            "unknown-token",
        ];
        let hosts = [
            "api.github.com",
            "api.example.com",
            "builds.example.org",
            "evil.example.com",
        ];
        let methods = [
            HttpMethod::GET,
            HttpMethod::POST,
            HttpMethod::PUT,
            HttpMethod::PATCH,
            HttpMethod::DELETE,
            HttpMethod::HEAD,
            HttpMethod::OPTIONS,
        ];
        let paths = [
            "/repos/acme/backend/issues",
            "/repos/acme/backend/pulls",
            "/repos/acme/backend",
            "/repos/acme/backendX",
            "/repos/acme/backend/issues/deeper/still",
            "/health",
            "/",
            "/api/v1/deploy",
            "/api/v1/deploy/extra",
            "/admin/reset",
            "/repos/acme/other",
            "/repos/zeta/list",
        ];
        let environments = [None, Some("env_development"), Some("env_prod")];
        // Body-limit parity is covered exhaustively by the targeted
        // body-limit test below; keep this matrix to a single body size
        // so the cross-product stays fast (Cedar calls dominate).
        let bodies = [0u64];

        let mut checks = 0usize;
        let mut allows = 0usize;
        let mut explicit_denies = 0usize;
        for principal in principals {
            for credential in credentials {
                for host in hosts {
                    for method in methods {
                        for path in paths {
                            for environment in environments {
                                for body in bodies {
                                    let req = make_request(
                                        principal,
                                        credential,
                                        host,
                                        method,
                                        path,
                                        environment,
                                        body,
                                    );
                                    let n = native.authorize(&req);
                                    let c = cedar.authorize(&req);
                                    assert_decision_parity(&n, &c, &format!("{req:?}"));
                                    if matches!(n, AuthorizationDecision::Allow { .. }) {
                                        allows += 1;
                                    }
                                    if let AuthorizationDecision::Deny {
                                        reason: DenyReason::ExplicitDeny,
                                        ..
                                    } = n
                                    {
                                        explicit_denies += 1;
                                    }
                                    checks += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(checks, 6 * 5 * 4 * 7 * 12 * 3);
        assert!(allows > 0, "matrix must exercise the allow direction");
        assert!(explicit_denies > 0, "matrix must exercise explicit denials");
    }

    /// Property-style sweep: deterministically pseudo-random requests over
    /// the fixed representative corpus preserve allow/deny parity between
    /// the two engines. Requests are drawn from per-document "families"
    /// (plus a mismatched tail) so both engines see a healthy mix of
    /// allows and denies instead of a degenerate all-deny sample.
    #[test]
    fn randomized_requests_preserve_parity() {
        let documents = corpus();
        let native = crate::RuleEngine::from_documents(documents.clone()).unwrap();
        let cedar = CedarAuthorizer::from_documents(documents).unwrap();

        // Deterministic xorshift; reproducible runs without proptest state.
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut pick = |len: usize| -> usize {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            ((state >> 16) % len as u64) as usize
        };

        let methods = [
            HttpMethod::GET,
            HttpMethod::POST,
            HttpMethod::PUT,
            HttpMethod::PATCH,
            HttpMethod::DELETE,
            HttpMethod::HEAD,
            HttpMethod::OPTIONS,
        ];
        // Each family targets one corpus document's principal/credential/
        // host neighborhood so a large fraction of samples land in
        // decision-interesting regions.
        let families: [(&str, &str, &str, [&str; 7]); 5] = [
            (
                "agent:coding-agent",
                "github-work-token",
                "api.github.com",
                [
                    "/repos/acme/backend/issues",
                    "/repos/acme/backend/pulls",
                    "/repos/acme/backend",
                    "/repos/acme/backendX",
                    "/repos/acme/backend/issues/deeper",
                    "/health",
                    "/admin/reset",
                ],
            ),
            (
                "agent:release-bot",
                "deploy-token",
                "api.example.com",
                [
                    "/api/v1/deploy",
                    "/api/v1/rollback",
                    "/api/v1/deploy/extra",
                    "/admin/reset",
                    "",
                    "",
                    "",
                ],
            ),
            (
                "agent:wide-agent",
                "wide-token",
                "wide.example.com",
                ["/", "/anything", "/deep/path/here", "", "", "", ""],
            ),
            (
                "agent:deep-agent",
                "deep-token",
                "deep.example.com",
                [
                    "/repos/zeta/list",
                    "/repos/acme/list",
                    "/repos",
                    "/unrelated",
                    "",
                    "",
                    "",
                ],
            ),
            (
                "session:sess_abc123",
                "github-work-token",
                "api.github.com",
                ["/health", "/health/extra", "", "", "", "", ""],
            ),
        ];
        let environments = [
            None,
            Some("env_development"),
            Some("env_prod"),
            Some("env_staging"),
        ];
        let bodies = [0u64, 50u64, 99u64, 100u64, 262_144u64, u64::MAX];

        let mut allows = 0;
        let mut denies = 0;
        for _ in 0..2000 {
            let family = &families[pick(families.len())];
            let (principal, credential, host) = (family.0, family.1, family.2);
            let family_paths = &family.3;
            let mut path = family_paths[pick(family_paths.len())];
            if path.is_empty() {
                // Families with fewer paths than the fixed array width
                // fill the tail with sentinels; remap to a real path.
                path = family_paths[0];
            }
            let req = make_request(
                principal,
                credential,
                host,
                methods[pick(methods.len())],
                path,
                environments[pick(environments.len())],
                bodies[pick(bodies.len())],
            );
            let n = native.authorize(&req);
            let c = cedar.authorize(&req);
            assert_decision_parity(&n, &c, &format!("{req:?}"));
            if matches!(n, AuthorizationDecision::Allow { .. }) {
                allows += 1;
            } else {
                denies += 1;
            }
        }
        assert!(
            allows > 100 && denies > 100,
            "degenerate sample: {allows}/{denies}"
        );
    }
}
