//! Authorization trait, policy model, decision diagnostics, and policy
//! pack compilation target.
//!
//! # The `Authorizer` seam
//!
//! [`Authorizer`] is the single authorization boundary consumed by the
//! broker. **Cedar is the production policy evaluator behind this trait**;
//! this task ships only the seam plus a deterministic reference
//! implementation ([`RuleEngine`]) — Cedar itself is intentionally *not*
//! integrated yet. Callers wire against the trait so the evaluator can be
//! swapped without touching call sites.
//!
//! The model is deny-by-default: an engine with no policies denies every
//! request with [`DenyReason::NoMatchingPolicy`].
//!
//! # Broker mapping (plan §22)
//!
//! | Model concept | Broker meaning |
//! |---------------|----------------|
//! | [`Principal`] | agent/session identity |
//! | [`Action::HttpRequest`] | the proxied HTTP action |
//! | [`Resource`] | credential logical ID |
//! | [`AuthorizationContext`] | canonical host/method/path/query/body metadata and environment |
//!
//! # Canonicalization contract (caller obligations)
//!
//! Authorization sees **canonical values only**. The broker transport layer
//! must hand the engine an [`AuthorizationContext`] whose `path` is already
//! percent-decoded with dot segments (`.` / `..`) resolved and whose `host`
//! is already lowercased without port. The matcher is literal and
//! segment-based; non-canonical contexts are rejected outright (see
//! [`DenyReason::InvalidContext`]) rather than normalized, so upstream
//! normalization drift can never become a deny-evasion.

mod engine;
mod error;
mod loader;
mod matcher;
mod model;

pub use engine::{
    AuthorizationDecision, AuthorizationRequest, Authorizer, CandidateEvaluation, CandidateOutcome,
    CompiledPolicy, DenyReason, PolicyExplanation, RuleEngine,
};
pub use error::PolicyError;
pub use loader::{load_policy_file, parse_policy_yaml, validate_policy};
pub use matcher::{host_matches, path_matches, validate_pattern};
pub use model::{
    Action, AuthorizationContext, ContextError, EnvironmentRules, HttpMethod, HttpRules,
    MethodPathRule, PolicyDocument, Principal, RequestConstraints, Resource, ResponseConstraints,
    PRINCIPAL_AGENT_PREFIX, PRINCIPAL_MAX_LEN, PRINCIPAL_SESSION_PREFIX,
};
