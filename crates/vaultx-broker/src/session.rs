//! Agent session authentication (plan §25).
//!
//! A session binds an agent identity to an environment and is exercised
//! with a bearer-style token. Only the SHA-256 **verifier hash** of the
//! token is ever stored — the raw token exists exactly twice: returned
//! once by [`SessionStore::create`], and held in the caller's hands
//! afterwards. Validation compares verifier hashes in constant time
//! ([`subtle`]) so token guessing cannot be timed.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use vaultx_types::{AgentId, EnvironmentId, SessionId};

use crate::error::BrokerError;

/// Random bytes behind generated session ids (rendered as 32 hex chars).
const SESSION_ID_BYTES: usize = 16;
/// Random bytes behind generated raw session tokens.
const SESSION_TOKEN_BYTES: usize = 32;

fn random_hex(bytes: usize) -> Result<String, BrokerError> {
    let mut buffer = vec![0u8; bytes];
    getrandom::getrandom(&mut buffer).map_err(|e| BrokerError::Entropy(e.to_string()))?;
    Ok(hex::encode(buffer))
}

// ---------------------------------------------------------------------------
// TokenHash
// ---------------------------------------------------------------------------

/// SHA-256 verifier of a raw session bearer token. The plaintext token is
/// never persisted; only this digest is (plan §25: "Store only a
/// verifier/hash for bearer-style local session tokens").
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct TokenHash([u8; 32]);

impl TokenHash {
    /// Computes the verifier of a raw token string.
    #[must_use]
    pub fn from_token(token: &str) -> Self {
        Self(hash_token(token))
    }

    /// Constant-time equality against another verifier. Timing of this
    /// comparison does not depend on matching prefix length.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        bool::from(self.0.as_slice().ct_eq(other.0.as_slice()))
    }

    /// Raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Hashes the bytes of a raw session token with SHA-256.
#[must_use]
pub fn hash_token(token: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.finalize().into()
}

impl Serialize for TokenHash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for TokenHash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        let bytes = hex::decode(&raw)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .ok_or_else(|| D::Error::custom("token hash must be 64 hex characters"))?;
        Ok(Self(bytes))
    }
}

// ---------------------------------------------------------------------------
// Session record + store seam
// ---------------------------------------------------------------------------

/// Narrowing constraints attached to a delegated child session (plan §25).
///
/// Every field is an independent attenuation dimension; `None` (or an
/// empty pattern list) means *unrestricted along that dimension* relative
/// to what policy already allows. Constraints can only ever narrow:
/// delegation intersects them with the parent's own constraints, which is
/// what makes the plan's verification property — `child effective
/// authority ⊆ parent effective authority` — hold transitively across
/// chains.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConstraints {
    /// Allowed credential logical names; `None` = unrestricted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<BTreeSet<String>>,
    /// Allowed environments; `None` = unrestricted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environments: Option<BTreeSet<String>>,
    /// Allowed hosts (exact, case-insensitive); `None` = unrestricted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosts: Option<BTreeSet<String>>,
    /// Allowed HTTP methods (compared ASCII-case-insensitively);
    /// `None` = unrestricted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<BTreeSet<String>>,
    /// Allowed request paths as segment-oriented glob patterns
    /// ([`vaultx_policy::path_matches`] grammar). `None` = unrestricted;
    /// `Some(empty)` = nothing allowed along this dimension.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<String>>,
    /// Remaining request budget. Decremented atomically on each allowed
    /// brokered request; `Some(0)` denies everything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining_requests: Option<u64>,
}

impl SessionConstraints {
    /// True when this set narrows nothing at all. Such a delegation is
    /// rejected: it would grow the chain without reducing authority.
    #[must_use]
    pub fn is_unconstrained(&self) -> bool {
        self.credentials.is_none()
            && self.environments.is_none()
            && self.hosts.is_none()
            && self.methods.is_none()
            && self.paths.is_none()
            && self.remaining_requests.is_none()
    }

    /// Intersects `requested` into `self`, producing the constraints a
    /// child of a session carrying `self` would store. Set dimensions
    /// intersect literally, budgets take the minimum, and path globs keep
    /// only requested patterns fully subsumed by at least one existing
    /// pattern — so the result's accepted-request language is always a
    /// subset of both operands'.
    #[must_use]
    pub fn narrow(&self, requested: &Self) -> Self {
        Self {
            credentials: narrow_set(&self.credentials, &requested.credentials),
            environments: narrow_set(&self.environments, &requested.environments),
            hosts: narrow_set(&self.hosts, &requested.hosts),
            methods: narrow_set(&self.methods, &requested.methods),
            paths: narrow_paths(&self.paths, &requested.paths),
            remaining_requests: match (&self.remaining_requests, &requested.remaining_requests) {
                (Some(parent), Some(child)) => Some((*parent).min(*child)),
                (only, None) | (None, only) => *only,
            },
        }
    }

    /// Checks one canonical brokered request against this constraint set.
    ///
    /// Returns the name of the first violated dimension; the engine maps
    /// any violation to the same external denial (`outside_delegation`)
    /// so callers cannot probe which dimension tripped.
    ///
    /// The budget dimension is *not* consulted here — it is enforced by
    /// [`SessionStore::consume_budget`], whose decrement must be atomic
    /// with the decision.
    pub fn check_request(
        &self,
        credential: &str,
        environment: &str,
        host: &str,
        method: &str,
        path: &str,
    ) -> Result<(), &'static str> {
        if let Some(set) = &self.credentials {
            if !set.contains(credential) {
                return Err("credential");
            }
        }
        if let Some(set) = &self.environments {
            if !set.contains(environment) {
                return Err("environment");
            }
        }
        if let Some(set) = &self.hosts {
            // Same semantics as `vaultx_policy::host_matches` (exact match
            // after lowercasing both sides) without materializing a Vec.
            let lowered = host.to_ascii_lowercase();
            if !set
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(&lowered))
            {
                return Err("host");
            }
        }
        if let Some(set) = &self.methods {
            if !set
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(method))
            {
                return Err("method");
            }
        }
        if let Some(patterns) = &self.paths {
            if !patterns
                .iter()
                .any(|pattern| vaultx_policy::path_matches(pattern, path))
            {
                return Err("path");
            }
        }
        Ok(())
    }
}

fn narrow_set(
    parent: &Option<BTreeSet<String>>,
    requested: &Option<BTreeSet<String>>,
) -> Option<BTreeSet<String>> {
    match (parent, requested) {
        (Some(a), Some(b)) => Some(a.intersection(b).cloned().collect()),
        (only, None) | (None, only) => only.clone(),
    }
}

fn narrow_paths(
    parent: &Option<Vec<String>>,
    requested: &Option<Vec<String>>,
) -> Option<Vec<String>> {
    match (parent, requested) {
        (Some(kept), Some(wanted)) => Some(
            wanted
                .iter()
                .filter(|child| kept.iter().any(|pattern| glob_subsumes(pattern, child)))
                .cloned()
                .collect(),
        ),
        (only, None) | (None, only) => only.clone(),
    }
}

/// True when every path matched by `child_pattern` is also matched by
/// `parent_pattern`. Both must satisfy the segment-glob grammar
/// ([`vaultx_policy::validate_pattern`]); anything else conservatively
/// reports no subsumption so invalid input can never widen a chain.
fn glob_subsumes(parent: &str, child: &str) -> bool {
    fn split(pattern: &str) -> Option<(Vec<&str>, bool)> {
        vaultx_policy::validate_pattern(pattern).ok()?;
        let mut segments: Vec<&str> = pattern
            .strip_prefix('/')
            .unwrap_or(pattern)
            .split('/')
            .collect();
        let starred = segments.last() == Some(&"**");
        if starred {
            segments.pop();
        }
        Some((segments, starred))
    }
    let Some((p_segments, p_star)) = split(parent) else {
        return false;
    };
    let Some((c_segments, c_star)) = split(child) else {
        return false;
    };
    // "/**" accepts everything.
    if p_segments.is_empty() && p_star {
        return true;
    }
    // A bare "/**" child is only subsumed by "/**" (handled above).
    if c_segments.is_empty() && c_star {
        return false;
    }
    let covered_prefix = p_segments
        .iter()
        .zip(&c_segments)
        .all(|(p, c)| *p == "*" || p == c);
    match (p_star, c_star) {
        // Fixed-length on both sides: same length plus pairwise coverage.
        (false, false) => p_segments.len() == c_segments.len() && covered_prefix,
        // Parent open-ended: the child's prefix must extend it; deeper
        // child segments fall under the parent's trailing `**`.
        (true, _) => c_segments.len() >= p_segments.len() && covered_prefix,
        // Child open-ended under a fixed-length parent can overshoot.
        (false, true) => false,
    }
}

/// How a delegation locates its parent session.
///
/// The CLI surface is possession-gated and only ever uses
/// [`DelegationParent::Token`]; the id variant exists for in-crate
/// fixtures and store-internal lookups and is deliberately not part of
/// the documented API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DelegationParent<'a> {
    /// Look up the parent session by its stored id. Internal/test-only:
    /// an id alone proves no possession of the parent capability.
    #[doc(hidden)]
    Id(&'a SessionId),
    /// Resolve the parent through its raw capability token verifier.
    Token(&'a str),
}

/// Stored state of one agent session (plan §25). Mirrors the plan's
/// `AgentSession` shape: identity binding plus the token *verifier* and a
/// revocation flag.
///
/// Unknown fields are refused on deserialization so a hand-edited store
/// cannot smuggle in unvalidated state alongside the schema.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSessionRecord {
    /// Identifier of the session (`sess_...`).
    pub session_id: SessionId,
    /// Agent that owns the session.
    pub agent: AgentId,
    /// Environment the session operates in.
    pub environment: EnvironmentId,
    /// Verifier hash of the raw bearer token; the token itself is never
    /// retained.
    pub token_hash: TokenHash,
    /// Revocation flag; revoked sessions fail validation forever.
    pub revoked: bool,
    /// Optional unix-seconds expiry. Expired sessions validate as
    /// revoked; `None` means no expiry.
    #[serde(default)]
    pub expires_at_secs: Option<u64>,
    /// Parent session when this record was minted by delegation (plan
    /// §25). Revocation cascade is enforced at *validation* time by
    /// walking this link: revoking a parent never rewrites child rows,
    /// but every live validation re-checks the whole chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_session: Option<SessionId>,
    /// Delegation narrowing constraints; `None` for sessions minted
    /// directly (`agent session create`), always `Some` for delegated
    /// children.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraints: Option<SessionConstraints>,
}

/// Session authentication boundary used by the broker engine.
///
/// Implementations must be safe to share across threads. Raw tokens are
/// handed out exactly once at creation; afterwards only verifiers live in
/// storage.
pub trait SessionStore: Send + Sync {
    /// Creates a session for `agent` in `environment`, returning the new
    /// session id together with the **raw** bearer token. The token can
    /// never be recovered later.
    ///
    /// # Errors
    /// Implementation-defined (entropy failure, persistence failure).
    fn create(
        &self,
        agent: &AgentId,
        environment: &EnvironmentId,
    ) -> Result<(SessionId, String), BrokerError>;

    /// Creates a session bound to an optional time-to-live. Expired
    /// sessions validate exactly like revoked ones.
    ///
    /// # Errors
    /// Implementation-defined (entropy failure, persistence failure).
    fn create_expiring(
        &self,
        agent: &AgentId,
        environment: &EnvironmentId,
        ttl_secs: Option<u64>,
    ) -> Result<(SessionId, String), BrokerError>;

    /// Validates a presented raw token and returns the live session
    /// record it belongs to.
    ///
    /// # Errors
    /// Returns [`BrokerError::InvalidSession`] when no session matches or
    /// the verifier differs, and [`BrokerError::SessionRevoked`] when the
    /// matched session was revoked or has expired.
    fn validate(&self, raw_token: &str) -> Result<AgentSessionRecord, BrokerError>;

    /// Revokes a session by id. Revoked sessions stay stored (audit trail
    /// of the id binding) but validate as revoked forever.
    ///
    /// # Errors
    /// Returns [`BrokerError::InvalidSession`] when the id is unknown.
    fn revoke(&self, session_id: &SessionId) -> Result<(), BrokerError>;

    /// Lists stored sessions belonging to `agent`, oldest first. Only
    /// verifier hashes and metadata are returned — never raw tokens.
    ///
    /// # Errors
    /// Implementation-defined (persistence failure).
    fn list_for_agent(&self, agent: &AgentId) -> Result<Vec<AgentSessionRecord>, BrokerError>;

    /// Mints a delegated child session from a live parent (plan §25).
    ///
    /// The child inherits the parent's agent and environment; its stored
    /// constraints are the **intersection** of the parent's own
    /// constraints (if any) and `requested`, so delegation chains
    /// monotonically narrow and `child effective authority ⊆ parent
    /// effective authority` holds transitively. The raw child token is
    /// returned exactly once, like [`SessionStore::create`].
    ///
    /// # Errors
    /// Returns [`BrokerError::InvalidSession`] when the parent cannot be
    /// located, [`BrokerError::SessionRevoked`] when it is revoked or
    /// expired, and [`BrokerError::InvalidDelegation`] when the request
    /// narrows nothing or carries an invalid path pattern. Entropy and
    /// persistence failures propagate implementation-defined variants.
    fn delegate(
        &self,
        parent: DelegationParent<'_>,
        requested: &SessionConstraints,
    ) -> Result<(SessionId, String), BrokerError>;

    /// Atomically consumes one unit of the presented session's remaining
    /// request budget. Sessions without a budget always succeed without
    /// mutating anything; at zero the denial is returned instead of a
    /// wraparound decrement (plan §25 budget attenuation).
    ///
    /// # Errors
    /// Returns [`BrokerError::BudgetExhausted`] when the budget is spent
    /// and [`BrokerError::InvalidSession`] for unknown tokens;
    /// persistence failures propagate implementation-defined variants.
    fn consume_budget(&self, raw_token: &str) -> Result<(), BrokerError>;
}

/// True when `record` can no longer validate: revoked or past its expiry.
fn is_dead(record: &AgentSessionRecord, clock: &std::sync::atomic::AtomicU64) -> bool {
    record.revoked
        || record
            .expires_at_secs
            .is_some_and(|expiry| expiry <= now_secs(clock))
}

/// True when every ancestor of `record` still exists and is live. A
/// missing, revoked, or expired parent invalidates the child; cycles in a
/// (tampered) store fail closed instead of looping forever.
fn ancestors_live(
    state: &InMemoryState,
    record: &AgentSessionRecord,
    clock: &std::sync::atomic::AtomicU64,
) -> bool {
    let mut seen = BTreeSet::new();
    let mut cursor = record.parent_session.clone();
    while let Some(id) = cursor {
        if !seen.insert(id.clone()) {
            return false;
        }
        let Some(parent) = state.sessions.get(&id) else {
            return false;
        };
        if is_dead(parent, clock) {
            return false;
        }
        cursor = parent.parent_session.clone();
    }
    true
}

/// Reads the effective unix-seconds clock for one store instance.
fn now_secs(clock: &std::sync::atomic::AtomicU64) -> u64 {
    let overridden = clock.load(std::sync::atomic::Ordering::Relaxed);
    if overridden != 0 {
        return overridden;
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// In-memory implementation
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct InMemoryState {
    sessions: HashMap<SessionId, AgentSessionRecord>,
    /// Verifier → session id index so validation needs no secret-bearing
    /// scan over records.
    by_hash: HashMap<TokenHash, SessionId>,
}

/// Thread-safe in-memory [`SessionStore`] for tests and development until
/// the persistent vault integration lands.
///
/// Storage holds session ids, identity bindings, revocation flags, and
/// token *verifier hashes* only — never raw tokens.
#[derive(Debug, Default)]
pub struct InMemorySessionStore {
    state: Mutex<InMemoryState>,
    /// Test-only wall-clock override (unix seconds; `0` = use the real
    /// clock). Per-instance so parallel tests never race each other.
    clock_override: std::sync::atomic::AtomicU64,
}

impl InMemorySessionStore {
    /// Creates an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Test-only: pins the wall clock used for session-expiry decisions.
    #[doc(hidden)]
    pub fn set_clock_for_tests(&self, unix_secs: u64) {
        self.clock_override
            .store(unix_secs, std::sync::atomic::Ordering::Relaxed);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, InMemoryState> {
        // Poisoning carries no recoverable invariant here (plain maps);
        // mirror the workspace convention of unwrapping poisons.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl SessionStore for InMemorySessionStore {
    fn create(
        &self,
        agent: &AgentId,
        environment: &EnvironmentId,
    ) -> Result<(SessionId, String), BrokerError> {
        Self::create_impl(self, agent, environment, None)
    }

    fn create_expiring(
        &self,
        agent: &AgentId,
        environment: &EnvironmentId,
        ttl_secs: Option<u64>,
    ) -> Result<(SessionId, String), BrokerError> {
        Self::create_impl(self, agent, environment, ttl_secs)
    }

    fn validate(&self, raw_token: &str) -> Result<AgentSessionRecord, BrokerError> {
        let computed = TokenHash::from_token(raw_token);
        let state = self.lock();
        let session_id = state
            .by_hash
            .get(&computed)
            .cloned()
            .ok_or(BrokerError::InvalidSession)?;
        let record = state
            .sessions
            .get(&session_id)
            .cloned()
            .ok_or(BrokerError::InvalidSession)?;

        // Constant-time verification even though the index already
        // matched: the compare itself must not leak match length.
        if !record.token_hash.ct_eq(&computed) {
            return Err(BrokerError::InvalidSession);
        }
        // Expired sessions are indistinguishable from revoked ones — the
        // distinction would only help an attacker holding a stale token.
        if is_dead(&record, &self.clock_override) {
            return Err(BrokerError::SessionRevoked);
        }
        // Delegation chains stay live end-to-end: a revoked or expired
        // ancestor invalidates every descendant at validation time.
        if !ancestors_live(&state, &record, &self.clock_override) {
            return Err(BrokerError::SessionRevoked);
        }
        Ok(record)
    }

    fn revoke(&self, session_id: &SessionId) -> Result<(), BrokerError> {
        let mut state = self.lock();
        let record = state
            .sessions
            .get_mut(session_id)
            .ok_or(BrokerError::InvalidSession)?;
        record.revoked = true;
        Ok(())
    }

    fn list_for_agent(&self, agent: &AgentId) -> Result<Vec<AgentSessionRecord>, BrokerError> {
        let state = self.lock();
        let mut records: Vec<AgentSessionRecord> = state
            .sessions
            .values()
            .filter(|record| record.agent == *agent)
            .cloned()
            .collect();
        records.sort_by(|a, b| a.session_id.cmp(&b.session_id));
        Ok(records)
    }

    fn delegate(
        &self,
        parent: DelegationParent<'_>,
        requested: &SessionConstraints,
    ) -> Result<(SessionId, String), BrokerError> {
        self.delegate_inner(parent, requested)
    }

    fn consume_budget(&self, raw_token: &str) -> Result<(), BrokerError> {
        self.consume_budget_inner(raw_token).map(|_| ())
    }
}

impl InMemorySessionStore {
    /// Shared creation path for [`SessionStore::create`] and
    /// [`SessionStore::create_expiring`].
    fn create_impl(
        &self,
        agent: &AgentId,
        environment: &EnvironmentId,
        ttl_secs: Option<u64>,
    ) -> Result<(SessionId, String), BrokerError> {
        // Session id: `sess_` + 16 random bytes hex (fits the SessionId
        // grammar: lowercase hex content, well under the 64-char cap).
        let session_id = SessionId::parse(&format!("sess_{}", random_hex(SESSION_ID_BYTES)?))
            .map_err(|_| {
                BrokerError::Entropy("generated session id failed validation".to_owned())
            })?;
        // Raw token: 32 random bytes hex, independent of the id. Only its
        // SHA-256 verifier is stored.
        let raw_token = random_hex(SESSION_TOKEN_BYTES)?;
        let token_hash = TokenHash::from_token(&raw_token);
        let expires_at_secs =
            ttl_secs.map(|ttl| now_secs(&self.clock_override).saturating_add(ttl));

        let mut state = self.lock();
        if state.by_hash.contains_key(&token_hash) {
            // Astronomically unlikely collision; refuse rather than
            // silently shadowing an existing session.
            return Err(BrokerError::Entropy(
                "session token verifier collision".to_owned(),
            ));
        }
        state.sessions.insert(
            session_id.clone(),
            AgentSessionRecord {
                session_id: session_id.clone(),
                agent: agent.clone(),
                environment: environment.clone(),
                token_hash,
                revoked: false,
                expires_at_secs,
                parent_session: None,
                constraints: None,
            },
        );
        state.by_hash.insert(token_hash, session_id.clone());
        Ok((session_id, raw_token))
    }

    /// Shared delegation path (plan §25). Validates the parent, intersects
    /// constraints monotonically, and mints a fresh child token.
    fn delegate_inner(
        &self,
        parent: DelegationParent<'_>,
        requested: &SessionConstraints,
    ) -> Result<(SessionId, String), BrokerError> {
        for pattern in requested.paths.iter().flatten() {
            if vaultx_policy::validate_pattern(pattern).is_err() {
                return Err(BrokerError::InvalidDelegation(format!(
                    "invalid path pattern `{pattern}`"
                )));
            }
        }

        // One lock hold covers parent validation through child insertion:
        // a concurrent revocation can never interleave mid-delegation.
        let mut state = self.lock();
        let parent_record = match &parent {
            DelegationParent::Id(id) => state.sessions.get(*id),
            DelegationParent::Token(token) => state
                .by_hash
                .get(&TokenHash::from_token(token))
                .and_then(|id| state.sessions.get(id)),
        }
        .cloned()
        .ok_or(BrokerError::InvalidSession)?;

        if is_dead(&parent_record, &self.clock_override) {
            return Err(BrokerError::SessionRevoked);
        }
        let narrowed = match &parent_record.constraints {
            Some(parent_constraints) => parent_constraints.narrow(requested),
            None => requested.clone(),
        };
        if narrowed.is_unconstrained() {
            return Err(BrokerError::InvalidDelegation(
                "delegation narrows nothing; at least one constraint dimension is required"
                    .to_owned(),
            ));
        }

        let session_id = SessionId::parse(&format!("sess_{}", random_hex(SESSION_ID_BYTES)?))
            .map_err(|_| {
                BrokerError::Entropy("generated session id failed validation".to_owned())
            })?;
        let raw_token = random_hex(SESSION_TOKEN_BYTES)?;
        let token_hash = TokenHash::from_token(&raw_token);

        if state.by_hash.contains_key(&token_hash) {
            return Err(BrokerError::Entropy(
                "session token verifier collision".to_owned(),
            ));
        }
        state.sessions.insert(
            session_id.clone(),
            AgentSessionRecord {
                session_id: session_id.clone(),
                agent: parent_record.agent,
                environment: parent_record.environment,
                token_hash,
                revoked: false,
                // No independent expiry: the child dies with its parent
                // through the validation-time chain walk instead.
                expires_at_secs: None,
                parent_session: Some(parent_record.session_id),
                constraints: Some(narrowed),
            },
        );
        state.by_hash.insert(token_hash, session_id.clone());
        Ok((session_id, raw_token))
    }

    /// Budget decrement returning whether the store actually mutated, so
    /// the file-backed wrapper knows whether to persist. The check and
    /// decrement run under one lock hold — atomic per process, and the
    /// file store serializes processes behind its flock.
    fn consume_budget_inner(&self, raw_token: &str) -> Result<bool, BrokerError> {
        let computed = TokenHash::from_token(raw_token);
        let mut state = self.lock();
        let session_id = state
            .by_hash
            .get(&computed)
            .cloned()
            .ok_or(BrokerError::InvalidSession)?;
        // Liveness re-check in the same lock hold: a session revoked or
        // orphaned by a dead chain between authentication and this point
        // neither executes nor burns budget.
        {
            let record = state
                .sessions
                .get(&session_id)
                .ok_or(BrokerError::InvalidSession)?;
            if is_dead(record, &self.clock_override)
                || !ancestors_live(&state, record, &self.clock_override)
            {
                return Err(BrokerError::SessionRevoked);
            }
        }
        let record = state
            .sessions
            .get_mut(&session_id)
            .ok_or(BrokerError::InvalidSession)?;
        match record
            .constraints
            .as_mut()
            .and_then(|c| c.remaining_requests.as_mut())
        {
            None => Ok(false),
            Some(0) => Err(BrokerError::BudgetExhausted),
            Some(remaining) => {
                *remaining -= 1;
                Ok(true)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent() -> AgentId {
        AgentId::parse("agent_coding").unwrap()
    }

    fn environment() -> EnvironmentId {
        EnvironmentId::parse("env_development").unwrap()
    }

    #[test]
    fn create_then_validate_round_trips() {
        let store = InMemorySessionStore::new();
        let (session_id, raw_token) = store.create(&agent(), &environment()).unwrap();

        assert!(session_id.as_str().starts_with("sess_"));
        assert_eq!(session_id.as_str().len(), "sess_".len() + 32);
        assert!(session_id.as_str()["sess_".len()..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        // Raw token is 32 bytes of hex — distinct material from the id.
        assert_ne!(raw_token, session_id.as_str());
        assert_eq!(raw_token.len(), 64);

        let record = store.validate(&raw_token).unwrap();
        assert_eq!(record.session_id, session_id);
        assert_eq!(record.agent, agent());
        assert_eq!(record.environment, environment());
        assert!(!record.revoked);
    }

    #[test]
    fn wrong_token_is_rejected() {
        let store = InMemorySessionStore::new();
        store.create(&agent(), &environment()).unwrap();
        let (_id, real_token) = store.create(&agent(), &environment()).unwrap();

        let mut wrong = real_token.as_bytes().to_vec();
        wrong[0] ^= b'a' ^ b'b';
        let mutated = String::from_utf8(wrong).unwrap();
        assert!(mutated != real_token);
        assert!(matches!(
            store.validate(&mutated),
            Err(BrokerError::InvalidSession)
        ));
        // And a syntactically unrelated garbage token too.
        assert!(matches!(
            store.validate("not-a-token-at-all"),
            Err(BrokerError::InvalidSession)
        ));
    }

    #[test]
    fn revoked_session_is_rejected_with_dedicated_error() {
        let store = InMemorySessionStore::new();
        let (session_id, raw_token) = store.create(&agent(), &environment()).unwrap();
        assert!(store.validate(&raw_token).is_ok());

        store.revoke(&session_id).unwrap();
        assert!(matches!(
            store.validate(&raw_token),
            Err(BrokerError::SessionRevoked)
        ));

        // Revocation is permanent.
        assert!(matches!(
            store.validate(&raw_token),
            Err(BrokerError::SessionRevoked)
        ));
    }

    #[test]
    fn unknown_session_revoke_and_validation_fail() {
        let store = InMemorySessionStore::new();
        assert!(matches!(
            store.revoke(&SessionId::parse("sess_does_not_exist").unwrap()),
            Err(BrokerError::InvalidSession)
        ));
        assert!(matches!(
            store.validate("deadbeef"),
            Err(BrokerError::InvalidSession)
        ));
    }

    #[test]
    fn expired_session_validates_as_revoked() {
        let store = InMemorySessionStore::new();
        store.set_clock_for_tests(1_000);
        let (_, raw_token) = store
            .create_expiring(&agent(), &environment(), Some(60))
            .unwrap();
        assert!(store.validate(&raw_token).is_ok());

        // Past expiry: same dedicated error class as revocation.
        store.set_clock_for_tests(1_061);
        assert!(matches!(
            store.validate(&raw_token),
            Err(BrokerError::SessionRevoked)
        ));
    }

    #[test]
    fn list_for_agent_scopes_and_never_leaks_raw_tokens() {
        let store = InMemorySessionStore::new();
        let (first, token_one) = store.create(&agent(), &environment()).unwrap();
        let (second, _) = store
            .create(&AgentId::parse("agent_other").unwrap(), &environment())
            .unwrap();

        let mine = store.list_for_agent(&agent()).unwrap();
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].session_id, first);
        assert!(store
            .list_for_agent(&AgentId::parse("agent_other").unwrap())
            .is_ok());
        let _ = second;

        // Raw tokens never appear in listed records: every stored field is
        // the 32-byte verifier.
        for record in &mine {
            assert_ne!(hex::encode(record.token_hash.as_bytes()), token_one);
            assert_eq!(record.token_hash.as_bytes().len(), 32);
        }
    }

    #[test]
    fn raw_tokens_are_distinct_across_sessions_and_only_hashes_stored() {
        let store = InMemorySessionStore::new();
        let (_, first) = store.create(&agent(), &environment()).unwrap();
        let (_, second) = store.create(&agent(), &environment()).unwrap();
        assert_ne!(first, second);

        // The store keeps no field shaped like a raw token: every stored
        // record's token field is the 32-byte digest.
        let state = store.lock();
        for record in state.sessions.values() {
            assert_ne!(hex::encode(record.token_hash.as_bytes()), first);
            assert_ne!(hex::encode(record.token_hash.as_bytes()), second);
            assert_eq!(record.token_hash.as_bytes().len(), 32);
        }
    }

    #[test]
    fn token_hash_verifies_in_constant_time_api() {
        let a = TokenHash::from_token("token-one");
        let b = TokenHash::from_token("token-one");
        let c = TokenHash::from_token("token-two");
        assert!(a.ct_eq(&b));
        assert!(!a.ct_eq(&c));
        assert_ne!(
            a.as_bytes(),
            &[0u8; 32],
            "hash of a non-empty token is never all zeros"
        );
    }

    #[test]
    fn token_hash_serde_round_trips_and_validates_length() {
        let hash = TokenHash::from_token("some-session-token");
        let encoded = serde_json::to_string(&hash).unwrap();
        assert_eq!(encoded.len(), 64 + 2); // quoted 64 hex chars
        let decoded: TokenHash = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, hash);
        assert!(serde_json::from_str::<TokenHash>("\"zz\"").is_err());
        assert!(serde_json::from_str::<TokenHash>("\"00\"").is_err());
    }

    #[test]
    fn session_record_serde_round_trips() {
        let store = InMemorySessionStore::new();
        let (session_id, _) = store.create(&agent(), &environment()).unwrap();
        let state = store.lock();
        let record = state.sessions.get(&session_id).unwrap().clone();
        drop(state);

        let encoded = serde_json::to_string(&record).unwrap();
        let decoded: AgentSessionRecord = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, record);
        assert!(!encoded.contains("\"revoked\":true"));
    }

    // -- delegation (plan §25) --------------------------------------------------

    fn credential_set(names: &[&str]) -> Option<BTreeSet<String>> {
        Some(names.iter().map(|name| (*name).to_owned()).collect())
    }

    #[test]
    fn delegate_mints_constrained_child_inheriting_agent_and_environment() {
        let store = InMemorySessionStore::new();
        let (root_id, parent_token) = store.create(&agent(), &environment()).unwrap();
        let requested = SessionConstraints {
            credentials: credential_set(&["github-work-token"]),
            hosts: Some(BTreeSet::from(["api.github.com".to_owned()])),
            remaining_requests: Some(5),
            ..SessionConstraints::default()
        };
        let (_child_id, child_token) =
            SessionStore::delegate(&store, DelegationParent::Token(&parent_token), &requested)
                .unwrap();

        assert_ne!(child_token, parent_token);
        assert_eq!(child_token.len(), 64);
        let record = store.validate(&child_token).unwrap();
        assert_eq!(record.parent_session.as_ref(), Some(&root_id));
        assert_eq!(record.agent, agent());
        assert_eq!(record.environment, environment());
        let constraints = record
            .constraints
            .expect("delegated child carries constraints");
        assert_eq!(
            constraints.credentials,
            credential_set(&["github-work-token"])
        );
        assert_eq!(
            constraints.hosts,
            Some(BTreeSet::from(["api.github.com".to_owned()]))
        );
        assert_eq!(constraints.remaining_requests, Some(5));
    }

    #[test]
    fn delegate_resolves_parent_by_id_and_by_raw_token() {
        let store = InMemorySessionStore::new();
        let (parent_id, parent_token) = store.create(&agent(), &environment()).unwrap();
        let requested = SessionConstraints {
            methods: Some(BTreeSet::from(["GET".to_owned()])),
            ..SessionConstraints::default()
        };

        let by_id =
            SessionStore::delegate(&store, DelegationParent::Id(&parent_id), &requested).unwrap();
        let by_token =
            SessionStore::delegate(&store, DelegationParent::Token(&parent_token), &requested)
                .unwrap();

        for (_child_id, child_token) in [by_id, by_token] {
            let record = store.validate(&child_token).unwrap();
            assert_eq!(record.agent, agent());
            assert_eq!(record.parent_session.as_ref(), Some(&parent_id));
        }
    }

    #[test]
    fn delegate_rejects_unknown_revoked_and_expired_parents() {
        let store = InMemorySessionStore::new();
        let requested = SessionConstraints {
            paths: Some(vec!["/repos/**".to_owned()]),
            ..SessionConstraints::default()
        };

        // Unknown parent id and unknown token both fail closed.
        let unknown = SessionId::parse("sess_does_not_exist").unwrap();
        assert!(matches!(
            SessionStore::delegate(&store, DelegationParent::Id(&unknown), &requested),
            Err(BrokerError::InvalidSession)
        ));
        assert!(matches!(
            SessionStore::delegate(&store, DelegationParent::Token("nope"), &requested),
            Err(BrokerError::InvalidSession)
        ));

        // Revoked parent.
        let (revoked_id, revoked_token) = store.create(&agent(), &environment()).unwrap();
        store.revoke(&revoked_id).unwrap();
        assert!(matches!(
            SessionStore::delegate(&store, DelegationParent::Id(&revoked_id), &requested),
            Err(BrokerError::SessionRevoked)
        ));
        assert!(matches!(
            SessionStore::delegate(&store, DelegationParent::Token(&revoked_token), &requested),
            Err(BrokerError::SessionRevoked)
        ));

        // Expired parent behaves like a revoked one.
        store.set_clock_for_tests(1_000);
        let (expired_id, _) = store
            .create_expiring(&agent(), &environment(), Some(30))
            .unwrap();
        store.set_clock_for_tests(1_031);
        assert!(matches!(
            SessionStore::delegate(&store, DelegationParent::Id(&expired_id), &requested),
            Err(BrokerError::SessionRevoked)
        ));
    }

    #[test]
    fn delegation_that_narrows_nothing_is_rejected() {
        let store = InMemorySessionStore::new();
        let (_, token) = store.create(&agent(), &environment()).unwrap();
        let empty = SessionConstraints::default();
        assert!(matches!(
            SessionStore::delegate(&store, DelegationParent::Token(&token), &empty),
            Err(BrokerError::InvalidDelegation(_))
        ));
        // A constrained parent cannot mint an unconstrained child either:
        // the intersection keeps the parent's restrictions, so this only
        // rejects the truly pointless fully-unconstrained chain.
        assert!(matches!(
            SessionStore::delegate(&store, DelegationParent::Token(&token), &empty),
            Err(BrokerError::InvalidDelegation(_))
        ));
    }

    #[test]
    fn delegate_rejects_invalid_path_patterns() {
        let store = InMemorySessionStore::new();
        let (_, token) = store.create(&agent(), &environment()).unwrap();
        let requested = SessionConstraints {
            paths: Some(vec!["/repos/../escape".to_owned()]),
            ..SessionConstraints::default()
        };
        assert!(matches!(
            SessionStore::delegate(&store, DelegationParent::Token(&token), &requested),
            Err(BrokerError::InvalidDelegation(message))
                if message.contains("invalid path pattern")
        ));
    }

    #[test]
    fn grandchild_constraints_are_the_two_level_intersection() {
        let store = InMemorySessionStore::new();
        let (_, root_token) = store.create(&agent(), &environment()).unwrap();

        let level_one = SessionConstraints {
            credentials: credential_set(&["cred-a", "cred-b"]),
            hosts: Some(BTreeSet::from([
                "api.github.com".to_owned(),
                "files.example.com".to_owned(),
            ])),
            methods: Some(BTreeSet::from(["GET".to_owned(), "POST".to_owned()])),
            paths: Some(vec!["/repos/**".to_owned()]),
            remaining_requests: Some(10),
            environments: None,
        };
        let (child_id, _child_token) =
            SessionStore::delegate(&store, DelegationParent::Token(&root_token), &level_one)
                .unwrap();

        let level_two = SessionConstraints {
            credentials: credential_set(&["cred-b", "cred-c"]),
            hosts: Some(BTreeSet::from([
                "files.example.com".to_owned(),
                "evil.example.com".to_owned(),
            ])),
            methods: Some(BTreeSet::from(["DELETE".to_owned(), "POST".to_owned()])),
            paths: Some(vec!["/repos/acme/**".to_owned(), "/other/**".to_owned()]),
            remaining_requests: Some(4),
            environments: None,
        };
        let (_grandchild_id, grandchild_token) =
            SessionStore::delegate(&store, DelegationParent::Id(&child_id), &level_two).unwrap();

        let record = store.validate(&grandchild_token).unwrap();
        let constraints = record.constraints.unwrap();
        assert_eq!(
            constraints.credentials,
            credential_set(&["cred-b"]),
            "credentials intersect"
        );
        assert_eq!(
            constraints.hosts,
            Some(BTreeSet::from(["files.example.com".to_owned()])),
            "hosts intersect"
        );
        assert_eq!(
            constraints.methods,
            Some(BTreeSet::from(["POST".to_owned()])),
            "methods intersect"
        );
        assert_eq!(
            constraints.paths,
            Some(vec!["/repos/acme/**".to_owned()]),
            "only patterns subsumed by the parent's globs survive; /other/** is dropped"
        );
        assert_eq!(constraints.remaining_requests, Some(4), "budgets take min");
    }

    #[test]
    fn path_intersection_of_disjoint_globs_allows_nothing() {
        // Parent allows /a/**; requesting only /b/** must NOT degrade to
        // unrestricted — `Some(empty)` means nothing matches.
        let store = InMemorySessionStore::new();
        let (_, root_token) = store.create(&agent(), &environment()).unwrap();
        let parent_level = SessionConstraints {
            paths: Some(vec!["/a/**".to_owned()]),
            ..SessionConstraints::default()
        };
        let (child_id, _) =
            SessionStore::delegate(&store, DelegationParent::Token(&root_token), &parent_level)
                .unwrap();
        let requested = SessionConstraints {
            paths: Some(vec!["/b/**".to_owned()]),
            ..SessionConstraints::default()
        };
        let (_, grandchild_token) =
            SessionStore::delegate(&store, DelegationParent::Id(&child_id), &requested).unwrap();
        let record = store.validate(&grandchild_token).unwrap();
        let constraints = record.constraints.unwrap();
        assert_eq!(constraints.paths, Some(Vec::new()));
        assert!(constraints
            .check_request("c", "env_development", "h.test", "GET", "/a/x")
            .is_err());
    }

    #[test]
    fn revoked_parent_invalidates_child_at_validation_time() {
        let store = InMemorySessionStore::new();
        let (root_id, _) = store.create(&agent(), &environment()).unwrap();
        let requested = SessionConstraints {
            paths: Some(vec!["/**".to_owned()]),
            ..SessionConstraints::default()
        };
        let (_, child_token) =
            SessionStore::delegate(&store, DelegationParent::Id(&root_id), &requested).unwrap();
        assert!(store.validate(&child_token).is_ok());

        // Revoking the parent does not rewrite the child row, yet the
        // child stops validating immediately (chain walk).
        store.revoke(&root_id).unwrap();
        assert!(matches!(
            store.validate(&child_token),
            Err(BrokerError::SessionRevoked)
        ));
    }

    #[test]
    fn expired_parent_invalidates_child_at_validation_time() {
        let store = InMemorySessionStore::new();
        store.set_clock_for_tests(2_000);
        let (root_id, _) = store
            .create_expiring(&agent(), &environment(), Some(60))
            .unwrap();
        let requested = SessionConstraints {
            methods: Some(BTreeSet::from(["GET".to_owned()])),
            ..SessionConstraints::default()
        };
        let (_, child_token) =
            SessionStore::delegate(&store, DelegationParent::Id(&root_id), &requested).unwrap();
        assert!(store.validate(&child_token).is_ok());

        store.set_clock_for_tests(2_061);
        assert!(matches!(
            store.validate(&child_token),
            Err(BrokerError::SessionRevoked)
        ));
    }

    #[test]
    fn budget_decrements_only_on_consumption_and_exhausts_atomically() {
        let store = InMemorySessionStore::new();
        let (_, root_token) = store.create(&agent(), &environment()).unwrap();
        let requested = SessionConstraints {
            remaining_requests: Some(2),
            ..SessionConstraints::default()
        };
        let (_, child_token) =
            SessionStore::delegate(&store, DelegationParent::Token(&root_token), &requested)
                .unwrap();

        assert!(store.consume_budget(&child_token).is_ok());
        assert!(store.consume_budget(&child_token).is_ok());
        assert!(matches!(
            store.consume_budget(&child_token),
            Err(BrokerError::BudgetExhausted)
        ));
        // Exhaustion is sticky; nothing wrapped around.
        assert!(matches!(
            store.consume_budget(&child_token),
            Err(BrokerError::BudgetExhausted)
        ));

        // Unbudgeted sessions never mutate and always succeed; unknown
        // tokens are invalid sessions.
        assert!(store.consume_budget(&root_token).is_ok());
        assert!(matches!(
            store.consume_budget("unknown-token"),
            Err(BrokerError::InvalidSession)
        ));
    }

    #[test]
    fn legacy_records_without_delegation_fields_still_load() {
        // Backward compatibility: stores written before plan §25 carry no
        // parent/constraints keys; serde defaults must fill them in.
        let legacy = format!(
            "{{\"session_id\":\"sess_legacy\",\"agent\":\"{}\",\"environment\":\"{}\",\"token_hash\":\"{}\",\"revoked\":false,\"expires_at_secs\":null}}",
            agent(),
            environment(),
            hex::encode(TokenHash::from_token("legacy-token").as_bytes()),
        );
        let decoded: AgentSessionRecord = serde_json::from_str(&legacy).unwrap();
        assert_eq!(decoded.parent_session, None);
        assert_eq!(decoded.constraints, None);

        // And the full new shape round trips losslessly.
        let full = AgentSessionRecord {
            parent_session: Some(SessionId::parse("sess_parent").unwrap()),
            constraints: Some(SessionConstraints {
                paths: Some(vec!["/x/**".to_owned()]),
                ..SessionConstraints::default()
            }),
            ..decoded.clone()
        };
        let encoded = serde_json::to_string(&full).unwrap();
        assert_eq!(
            serde_json::from_str::<AgentSessionRecord>(&encoded).unwrap(),
            full
        );
    }

    #[test]
    fn check_request_enforces_every_dimension() {
        let constraints = SessionConstraints {
            credentials: credential_set(&["cred-a"]),
            environments: Some(BTreeSet::from(["env_dev".to_owned()])),
            hosts: Some(BTreeSet::from(["API.GitHub.com".to_owned()])),
            methods: Some(BTreeSet::from(["get".to_owned()])),
            paths: Some(vec!["/repos/*/issues".to_owned()]),
            remaining_requests: Some(1),
        };
        assert!(constraints
            .check_request(
                "cred-a",
                "env_dev",
                "api.github.com",
                "GET",
                "/repos/acme/issues"
            )
            .is_ok());

        for (credential, environment, host, method, path, dimension) in [
            (
                "cred-b",
                "env_dev",
                "api.github.com",
                "GET",
                "/repos/acme/issues",
                "credential",
            ),
            (
                "cred-a",
                "env_prod",
                "api.github.com",
                "GET",
                "/repos/acme/issues",
                "environment",
            ),
            (
                "cred-a",
                "env_dev",
                "evil.github.com",
                "GET",
                "/repos/acme/issues",
                "host",
            ),
            (
                "cred-a",
                "env_dev",
                "api.github.com",
                "POST",
                "/repos/acme/issues",
                "method",
            ),
            (
                "cred-a",
                "env_dev",
                "api.github.com",
                "GET",
                "/repos/acme/web/issues",
                "path",
            ),
            (
                "cred-a",
                "env_dev",
                "api.github.com",
                "GET",
                "/repos",
                "path",
            ),
        ] {
            assert_eq!(
                constraints.check_request(credential, environment, host, method, path),
                Err(dimension),
                "{dimension} violation must be reported"
            );
        }
    }

    #[test]
    fn glob_subsumption_covers_the_segment_grammar() {
        let subsumes = glob_subsumes;
        assert!(subsumes("/**", "/anything/at/all"));
        assert!(subsumes("/repos/**", "/repos/acme/backend/pulls"));
        assert!(!subsumes("/other/**", "/repos/acme"));

        assert!(subsumes("/repos/*", "/repos/acme"), "* covers one segment");
        assert!(!subsumes("/repos/*", "/repos/acme/deep"));
        assert!(
            !subsumes("/repos/acme", "/repos/*"),
            "wildcard child can widen"
        );
        assert!(subsumes("/repos/*", "/repos/acme"));

        assert!(
            subsumes("/a/**", "/a/**"),
            "identical open-ended globs survive intersection"
        );
        assert!(
            subsumes("/repos/acme/**", "/repos/acme/**"),
            "identical nested globs survive intersection"
        );

        // Unicode literal segments behave like any other literal.
        assert!(subsumes("/café/**", "/café/münchen"));
        assert!(!subsumes("/café/münchen", "/café/other"));
        assert!(
            !subsumes("/caf*", "/café/x"),
            "* covers whole segments only"
        );

        assert!(subsumes("/a/b/**", "/a/b/c/**"), "open-ended prefixes nest");
        assert!(
            !subsumes("/a/**/z", "/a/z"),
            "invalid patterns never subsume"
        );

        assert!(
            !subsumes("/a/b", "/a/**"),
            "open child overshoots fixed parent"
        );
        assert!(!subsumes("not-a-pattern", "/a"));
        assert!(!subsumes("/a", "also-bad"));
    }

    #[test]
    fn narrow_produces_subset_language_for_sets_budgets_and_paths() {
        let parent = SessionConstraints {
            credentials: credential_set(&["cred-a", "cred-b"]),
            hosts: Some(BTreeSet::from(["a.test".to_owned()])),
            methods: Some(BTreeSet::from(["GET".to_owned()])),
            paths: Some(vec!["/repos/**".to_owned()]),
            remaining_requests: Some(7),
            environments: None,
        };
        // A *broader* request cannot widen anything.
        let broader = SessionConstraints {
            credentials: credential_set(&["cred-c"]),
            hosts: Some(BTreeSet::from(["b.test".to_owned()])),
            methods: Some(BTreeSet::from(["DELETE".to_owned()])),
            paths: Some(vec!["/**".to_owned()]),
            remaining_requests: Some(99),
            environments: None,
        };
        let narrowed = parent.narrow(&broader);
        assert_eq!(narrowed.credentials, credential_set(&[]));
        assert_eq!(narrowed.hosts, Some(BTreeSet::from([])));
        assert_eq!(narrowed.methods, Some(BTreeSet::from([])));
        assert_eq!(
            narrowed.paths,
            Some(vec![]),
            "no /** pattern survives under /repos/**"
        );
        assert_eq!(narrowed.remaining_requests, Some(7));
    }
}

// ---------------------------------------------------------------------------
// File-backed store (cross-process sessions)
// ---------------------------------------------------------------------------

/// Persistent [`SessionStore`] backed by a single JSON file holding
/// verifier hashes and identity metadata only — raw tokens are returned
/// exactly once at creation and never written.
///
/// # Cross-process coherence
///
/// The CLI (`agent session create/revoke`) and a serving broker open this
/// store independently, so naive in-memory snapshots would let one side
/// resurrect what the other revoked. Every operation therefore runs
/// inside an exclusive `flock` on `<path>.lock` **and** reloads the
/// on-disk state first, making each call read-modify-write against the
/// freshest snapshot. Revocation is durable against concurrent writers;
/// the residual cost is one file read per operation (negligible at
/// session-store scale).
///
/// The file is created with `0600` permissions; loading refuses files
/// whose mode grants group/other access rather than silently reading a
/// leaked store. Mutations persist atomically via a unique tempfile +
/// fsync + rename within the same directory.
///
/// # Store trust model
///
/// The file protects **token secrecy** (only SHA-256 verifiers are ever
/// written) and **revocation durability**; it is not assumed to be
/// tamper-proof — it is ordinary owner-writable config, editable by
/// anything that already runs as the user. Delegation containment is
/// therefore made *self-verifying* instead of trusted: on every load
/// (`open` and each locked operation), every delegated record is re-checked
/// against its parent — stored constraints must equal the intersection of
/// the parent's constraints with themselves, parents must exist, and the
/// parent/constraints pair must be complete. Any widened link, dangling
/// ancestor, half-written delegation, or unknown field fails the load
/// closed with a `tampered delegation constraints` error, so a hand-edited
/// child can never gain authority beyond what minting proved.
pub struct FileSessionStore {
    path: PathBuf,
    lock_path: PathBuf,
    /// Test-only wall-clock pin (unix seconds; 0 = real clock), applied
    /// to every freshly-loaded in-memory snapshot.
    clock_override: std::sync::atomic::AtomicU64,
}

impl std::fmt::Debug for FileSessionStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileSessionStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

/// RAII holder releasing the advisory lock on drop.
struct FileLock {
    #[cfg(unix)]
    fd: std::os::fd::RawFd,
}

impl Drop for FileLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            libc::flock(self.fd, libc::LOCK_UN);
            libc::close(self.fd);
        }
    }
}

impl FileSessionStore {
    /// Opens (or creates) the store at `path`.
    ///
    /// # Errors
    /// Propagates I/O failures, JSON corruption (including unknown
    /// fields), tampered delegation chains, and permission-refusal
    /// ([`BrokerError::TransportFailure`]) when the existing file is
    /// readable by group/other.
    pub fn open(path: PathBuf) -> Result<Self, BrokerError> {
        Self::sweep_stale_tmp_files(&path);
        if path.exists() {
            Self::check_mode(&path)?;
            // Corruption and delegation tampering are surfaced eagerly so
            // operators learn about them before the first mutation would
            // clobber context.
            let records = Self::parse_store(&path)?;
            Self::verify_delegation_chains(&records, &path)?;
        }
        let mut lock_name = path.clone().into_os_string();
        lock_name.push(".lock");
        Ok(Self {
            path,
            lock_path: PathBuf::from(lock_name),
            clock_override: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Best-effort removal of stale writer debris (`<name>.tmp.<pid>.<seq>`)
    /// left behind by processes that crashed mid-persist. Files modified
    /// within the last few minutes are spared: a concurrently-opening peer
    /// must never destroy another writer's in-flight temp.
    fn sweep_stale_tmp_files(path: &Path) {
        let Some(name) = path.file_name().map(|n| n.to_string_lossy().into_owned()) else {
            return;
        };
        let Some(parent) = path.parent() else {
            return;
        };
        let Ok(entries) = std::fs::read_dir(parent) else {
            return;
        };
        let prefix = format!("{name}.tmp.");
        let Some(cutoff) =
            std::time::SystemTime::now().checked_sub(std::time::Duration::from_secs(300))
        else {
            return;
        };
        for entry in entries.flatten() {
            if !entry.file_name().to_string_lossy().starts_with(&prefix) {
                continue;
            }
            let fresh = entry
                .metadata()
                .and_then(|meta| meta.modified())
                .map(|modified| modified > cutoff)
                .unwrap_or(true);
            if !fresh {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    /// Reads and deserializes the store, mapping any parse failure
    /// (including [`deny_unknown_fields`] rejections) to a corrupt-store
    /// error naming the file.
    fn parse_store(path: &Path) -> Result<Vec<AgentSessionRecord>, BrokerError> {
        let text = std::fs::read_to_string(path).map_err(|err| {
            BrokerError::TransportFailure(format!("cannot read session store: {err}"))
        })?;
        serde_json::from_str(&text)
            .map_err(|err| BrokerError::TransportFailure(format!("corrupt session store: {err}")))
    }

    /// Re-derives every delegated record's constraints from its parent:
    /// the stored set must be exactly what minting would have produced
    /// (`stored == parent.constraints ∩ stored`), parents must exist, and
    /// a delegation link must always carry both halves. Anything else
    /// fails closed — see the [store trust model](Self) above.
    fn verify_delegation_chains(
        records: &[AgentSessionRecord],
        path: &Path,
    ) -> Result<(), BrokerError> {
        let fail = |detail: String| {
            BrokerError::TransportFailure(format!(
                "tampered delegation constraints in {}: {}",
                path.display(),
                detail
            ))
        };
        let by_id: HashMap<&SessionId, &AgentSessionRecord> =
            records.iter().map(|r| (&r.session_id, r)).collect();
        for record in records {
            match (&record.parent_session, &record.constraints) {
                (None, None) => {}
                (Some(parent_id), Some(child_constraints)) => {
                    let parent = by_id.get(parent_id).ok_or_else(|| {
                        fail(format!(
                            "session {} delegates from missing session {parent_id}",
                            record.session_id
                        ))
                    })?;
                    let narrowed = parent
                        .constraints
                        .as_ref()
                        .map(|parent_constraints| parent_constraints.narrow(child_constraints))
                        .unwrap_or_else(|| child_constraints.clone());
                    if &narrowed != child_constraints {
                        return Err(fail(format!(
                            "session {} stores constraints wider than its parent allows",
                            record.session_id
                        )));
                    }
                }
                _ => {
                    return Err(fail(format!(
                        "session {} has a half-written delegation link",
                        record.session_id
                    )))
                }
            }
        }
        Ok(())
    }

    /// Test-only: pins the wall clock used for expiry decisions across
    /// all subsequent locked operations.
    #[doc(hidden)]
    pub fn set_clock_for_tests(&self, unix_secs: u64) {
        self.clock_override
            .store(unix_secs, std::sync::atomic::Ordering::Relaxed);
    }

    /// Refuses stores whose unix mode grants group/other any access.
    fn check_mode(path: &Path) -> Result<(), BrokerError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(path)
                .map_err(|err| {
                    BrokerError::TransportFailure(format!("cannot stat session store: {err}"))
                })?
                .permissions()
                .mode();
            if mode & 0o077 != 0 {
                return Err(BrokerError::TransportFailure(
                    "session store permissions are too open; refusing to load".to_owned(),
                ));
            }
        }
        #[cfg(not(unix))]
        {
            let _ = path;
        }
        Ok(())
    }

    /// Acquires the exclusive cross-process lock, creating the lock file
    /// with restrictive permissions on first use.
    fn acquire_lock(&self) -> Result<FileLock, BrokerError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
            if let Some(parent) = self.lock_path.parent() {
                std::fs::create_dir_all(parent).map_err(|err| {
                    BrokerError::TransportFailure(format!("cannot create session dir: {err}"))
                })?;
                // create_dir_all applies the umask; tighten to owner-only
                // so directory listings stay private too.
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).map_err(
                    |err| BrokerError::TransportFailure(format!("cannot chmod session dir: {err}")),
                )?;
            }
            use std::os::unix::io::IntoRawFd as _;
            let fd = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .mode(0o600)
                .open(&self.lock_path)
                .map_err(|err| {
                    BrokerError::TransportFailure(format!("cannot open session lock: {err}"))
                })?
                .into_raw_fd();
            // Blocking acquire: contention windows are single-digit
            // milliseconds (one small JSON rewrite).
            let rc = unsafe { libc::flock(fd, libc::LOCK_EX) };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                unsafe {
                    libc::close(fd);
                }
                return Err(BrokerError::TransportFailure(format!(
                    "cannot lock session store: {err}"
                )));
            }
            Ok(FileLock { fd })
        }
        #[cfg(not(unix))]
        {
            // Non-unix platforms are single-user in v1; documented rather
            // than faked coherence.
            Ok(FileLock { fd: 0 })
        }
    }

    /// Loads the current on-disk records under an already-held lock.
    ///
    /// Delegation chains are re-verified here (not just in [`Self::open`])
    /// so every operation runs against freshly-proven containment: a store
    /// widened between open and now fails the operation instead of leaking
    /// authority.
    fn load_records(&self) -> Result<Vec<AgentSessionRecord>, BrokerError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        Self::check_mode(&self.path)?;
        let records = Self::parse_store(&self.path)?;
        Self::verify_delegation_chains(&records, &self.path)?;
        Ok(records)
    }

    /// Runs `body` against a freshly-loaded in-memory store under the
    /// exclusive lock, persisting when the body reports a mutation.
    fn with_locked<T>(
        &self,
        body: impl FnOnce(&InMemorySessionStore) -> Result<(T, bool), BrokerError>,
    ) -> Result<T, BrokerError> {
        let _guard = self.acquire_lock()?;
        let records = self.load_records()?;
        let inner = InMemorySessionStore::new();
        inner.set_clock_for_tests(
            self.clock_override
                .load(std::sync::atomic::Ordering::Relaxed),
        );
        {
            let mut state = inner.lock();
            for record in records {
                state
                    .by_hash
                    .insert(record.token_hash, record.session_id.clone());
                state.sessions.insert(record.session_id.clone(), record);
            }
        }
        let (value, mutated) = body(&inner)?;
        if mutated {
            self.persist_locked(&inner)?;
        }
        Ok(value)
    }

    /// Persists records; caller must hold the lock.
    fn persist_locked(&self, inner: &InMemorySessionStore) -> Result<(), BrokerError> {
        let guard = inner.lock();
        let mut records: Vec<AgentSessionRecord> = guard.sessions.values().cloned().collect();
        drop(guard);
        records.sort_by(|a, b| a.session_id.cmp(&b.session_id));
        let text = serde_json::to_string_pretty(&records)
            .map_err(|err| BrokerError::Serialization(err.to_string()))?;

        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| {
                BrokerError::TransportFailure(format!("cannot create session dir: {err}"))
            })?;
        }
        // Unique temp name: two processes never collide mid-rename, and
        // a crashed writer leaves identifiable debris instead of corrupt
        // live state.
        static TMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = TMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tmp = self
            .path
            .with_extension(format!("json.tmp.{}.{seq}", std::process::id()));
        {
            #[cfg(unix)]
            use std::os::unix::fs::OpenOptionsExt as _;
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            options.mode(0o600);
            let mut file = options.open(&tmp).map_err(|err| {
                BrokerError::TransportFailure(format!("cannot write session store: {err}"))
            })?;
            std::io::Write::write_all(&mut file, text.as_bytes()).map_err(|err| {
                BrokerError::TransportFailure(format!("cannot write session store: {err}"))
            })?;
            // Durability before rename: a crash cannot publish an empty
            // or torn store under the live name.
            file.sync_all().map_err(|err| {
                BrokerError::TransportFailure(format!("cannot flush session store: {err}"))
            })?;
        }
        std::fs::rename(&tmp, &self.path).map_err(|err| {
            BrokerError::TransportFailure(format!("cannot finalize session store: {err}"))
        })?;
        Ok(())
    }
}

impl SessionStore for FileSessionStore {
    fn create(
        &self,
        agent: &AgentId,
        environment: &EnvironmentId,
    ) -> Result<(SessionId, String), BrokerError> {
        self.with_locked(|inner| {
            let created = inner.create(agent, environment)?;
            Ok((created, true))
        })
    }

    fn create_expiring(
        &self,
        agent: &AgentId,
        environment: &EnvironmentId,
        ttl_secs: Option<u64>,
    ) -> Result<(SessionId, String), BrokerError> {
        self.with_locked(|inner| {
            let created = inner.create_expiring(agent, environment, ttl_secs)?;
            Ok((created, true))
        })
    }

    fn validate(&self, raw_token: &str) -> Result<AgentSessionRecord, BrokerError> {
        // Reload under lock: a revocation written by another process
        // after our last touch must be visible here, or revoked tokens
        // stay valid until restart.
        self.with_locked(|inner| Ok((inner.validate(raw_token)?, false)))
    }

    fn revoke(&self, session_id: &SessionId) -> Result<(), BrokerError> {
        self.with_locked(|inner| {
            inner.revoke(session_id)?;
            Ok(((), true))
        })
    }

    fn list_for_agent(&self, agent: &AgentId) -> Result<Vec<AgentSessionRecord>, BrokerError> {
        self.with_locked(|inner| Ok((inner.list_for_agent(agent)?, false)))
    }

    fn delegate(
        &self,
        parent: DelegationParent<'_>,
        requested: &SessionConstraints,
    ) -> Result<(SessionId, String), BrokerError> {
        self.with_locked(|inner| {
            let created = inner.delegate(parent, requested)?;
            Ok((created, true))
        })
    }

    fn consume_budget(&self, raw_token: &str) -> Result<(), BrokerError> {
        // Budget decrements persist immediately: a crash between an
        // allowed request and the next must not reset the counter.
        self.with_locked(|inner| {
            let consumed = inner.consume_budget_inner(raw_token)?;
            Ok(((), consumed))
        })
    }
}

#[cfg(test)]
mod file_store_tests {
    use super::*;

    fn agent() -> AgentId {
        AgentId::parse("agent_coding").unwrap()
    }

    fn environment() -> EnvironmentId {
        EnvironmentId::parse("env_development").unwrap()
    }

    #[test]
    fn file_store_round_trips_across_instances() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.json");

        let store = FileSessionStore::open(path.clone()).unwrap();
        let (session_id, raw_token) = store.create(&agent(), &environment()).unwrap();
        drop(store);

        let reopened = FileSessionStore::open(path).unwrap();
        let record = reopened.validate(&raw_token).unwrap();
        assert_eq!(record.session_id, session_id);
        assert_eq!(record.agent, agent());

        reopened.revoke(&session_id).unwrap();
        assert!(matches!(
            reopened.validate(&raw_token),
            Err(BrokerError::SessionRevoked)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn file_store_is_owner_only_and_refuses_loose_modes() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.json");
        FileSessionStore::open(path.clone())
            .unwrap()
            .create(&agent(), &environment())
            .unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        // A loosened store must be refused on next open.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = FileSessionStore::open(path).unwrap_err();
        assert!(err.to_string().contains("too open"), "{err}");
    }

    #[test]
    fn file_store_lists_by_agent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.json");
        let store = FileSessionStore::open(path).unwrap();
        let (mine, _) = store.create(&agent(), &environment()).unwrap();
        store
            .create(&AgentId::parse("agent_other").unwrap(), &environment())
            .unwrap();
        let listed = store.list_for_agent(&agent()).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].session_id, mine);
    }

    #[test]
    fn revocation_by_second_instance_is_visible_immediately() {
        // The CLI-vs-broker coherence contract: instance B must observe
        // instance A's revocation on its very next validate, and B's own
        // later create must not resurrect A's revoked session.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.json");

        let cli_side = FileSessionStore::open(path.clone()).unwrap();
        let (session_id, token) = cli_side.create(&agent(), &environment()).unwrap();

        let broker_side = FileSessionStore::open(path.clone()).unwrap();
        assert!(broker_side.validate(&token).is_ok());

        cli_side.revoke(&session_id).unwrap();
        assert!(matches!(
            broker_side.validate(&token),
            Err(BrokerError::SessionRevoked)
        ));

        // The resurrection vector: broker-side mutation reloads disk
        // first, so its write carries the revoked flag forward.
        let (_, _fresh) = broker_side
            .create(&AgentId::parse("agent_other").unwrap(), &environment())
            .unwrap();
        assert!(
            matches!(
                broker_side.validate(&token),
                Err(BrokerError::SessionRevoked)
            ),
            "broker-side create must not un-revoke"
        );
    }

    #[test]
    fn file_store_supports_ttl_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.json");
        let store = FileSessionStore::open(path).unwrap();
        store.set_clock_for_tests(5_000);
        let (_, token) = store
            .create_expiring(&agent(), &environment(), Some(30))
            .unwrap();
        store.set_clock_for_tests(5_031);
        assert!(matches!(
            store.validate(&token),
            Err(BrokerError::SessionRevoked)
        ));
    }

    /// Seeds a two-level delegation chain (root → scoped child → deeper
    /// grandchild) through the real store API and returns the raw JSON.
    fn seeded_chain_json(path: &Path) -> String {
        let store = FileSessionStore::open(path.to_path_buf()).unwrap();
        let (_, root_token) = store.create(&agent(), &environment()).unwrap();
        let level_one = SessionConstraints {
            paths: Some(vec!["/repos/**".to_owned()]),
            remaining_requests: Some(5),
            ..SessionConstraints::default()
        };
        let (_, child_token) =
            SessionStore::delegate(&store, DelegationParent::Token(&root_token), &level_one)
                .unwrap();
        drop(store);
        let reopened = FileSessionStore::open(path.to_path_buf()).unwrap();
        let level_two = SessionConstraints {
            paths: Some(vec!["/repos/acme/**".to_owned()]),
            remaining_requests: Some(2),
            ..SessionConstraints::default()
        };
        let (_grandchild_id, _) =
            SessionStore::delegate(&reopened, DelegationParent::Token(&child_token), &level_two)
                .unwrap();
        std::fs::read_to_string(path).expect("store readable")
    }

    #[test]
    fn load_refuses_child_constraints_wider_than_their_parent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.json");
        let json = seeded_chain_json(&path);

        // Hand-edit the grandchild's budget beyond what its parent allows:
        // the stored set no longer equals parent ∩ stored ⇒ tampered.
        let widened = json.replace("\"remaining_requests\": 2", "\"remaining_requests\": 999");
        assert_ne!(json, widened, "fixture edit must apply");
        std::fs::write(&path, widened).unwrap();

        let err = FileSessionStore::open(path.clone()).unwrap_err();
        assert!(
            err.to_string().contains("tampered delegation constraints")
                && err.to_string().contains("sessions.json"),
            "{err}"
        );
        // Eager verification means the widened store can never be opened
        // again — every entry point (open and each locked operation) runs
        // the same containment proof.
        assert!(matches!(
            FileSessionStore::open(path),
            Err(BrokerError::TransportFailure(_))
        ));
    }

    #[test]
    fn load_refuses_dangling_delegation_ancestors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.json");
        let json = seeded_chain_json(&path);

        // Drop the root record while keeping both children: every child's
        // ancestor chain now points at a missing session.
        let mut parsed: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        let before = parsed.len();
        parsed.retain(|record| record.get("parent_session").is_some());
        assert_eq!(before - parsed.len(), 1, "removed the root only");
        std::fs::write(&path, serde_json::to_string_pretty(&parsed).unwrap()).unwrap();
        let err = FileSessionStore::open(path).unwrap_err();
        assert!(
            err.to_string().contains("delegates from missing session"),
            "{err}"
        );
    }

    #[test]
    fn load_refuses_unknown_fields_on_records_and_constraints() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.json");
        let store = FileSessionStore::open(path.clone()).unwrap();
        store.create(&agent(), &environment()).unwrap();
        drop(store);

        // Unknown field on a session record.
        let json = std::fs::read_to_string(&path).unwrap();
        let poisoned = json.replace(
            "\"revoked\": false",
            "\"revoked\": false,\"bogus_field\": 1",
        );
        assert_ne!(json, poisoned);
        std::fs::write(&path, &poisoned).unwrap();
        let err = FileSessionStore::open(path.clone()).unwrap_err();
        assert!(err.to_string().contains("corrupt session store"), "{err}");

        // Unknown field inside a constraints object (needs a delegated
        // child first).
        let fresh = dir.path().join("chain.json");
        let chain = seeded_chain_json(&fresh);
        let poisoned_constraints = chain.replace(
            "\"remaining_requests\": 2",
            "\"extra\": true,\"remaining_requests\": 2",
        );
        assert_ne!(chain, poisoned_constraints);
        std::fs::write(&fresh, poisoned_constraints).unwrap();
        let err = FileSessionStore::open(fresh).unwrap_err();
        assert!(err.to_string().contains("corrupt session store"), "{err}");
    }

    #[test]
    fn consume_budget_refuses_dead_sessions_without_burning_budget() {
        let store = InMemorySessionStore::new();
        store.set_clock_for_tests(3_000);
        let (root_id, _) = store
            .create_expiring(&agent(), &environment(), Some(60))
            .unwrap();
        let requested = SessionConstraints {
            remaining_requests: Some(2),
            ..SessionConstraints::default()
        };
        let (child_id, child_token) =
            SessionStore::delegate(&store, DelegationParent::Id(&root_id), &requested).unwrap();
        assert!(store.consume_budget(&child_token).is_ok());

        // Revoked root: consumption is refused outright...
        store.revoke(&root_id).unwrap();
        assert!(matches!(
            store.consume_budget(&child_token),
            Err(BrokerError::SessionRevoked)
        ));

        // ...and the stored budget was not touched by the refused call.
        let records = store.list_for_agent(&agent()).unwrap();
        let child = records
            .iter()
            .find(|record| record.session_id == child_id)
            .unwrap();
        assert_eq!(
            child.constraints.as_ref().unwrap().remaining_requests,
            Some(1)
        );

        // Expired ancestors behave identically.
        store.set_clock_for_tests(3_061);
        assert!(matches!(
            store.consume_budget(&child_token),
            Err(BrokerError::SessionRevoked)
        ));
    }

    #[test]
    fn budget_decrements_persist_across_store_instances() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.json");

        let first = FileSessionStore::open(path.clone()).unwrap();
        let (_, root_token) = first.create(&agent(), &environment()).unwrap();
        let requested = SessionConstraints {
            remaining_requests: Some(2),
            ..SessionConstraints::default()
        };
        let (_, child_token) =
            SessionStore::delegate(&first, DelegationParent::Token(&root_token), &requested)
                .unwrap();
        first.consume_budget(&child_token).unwrap();
        drop(first);

        // A freshly-opened instance sees exactly one unit consumed — and
        // exhaustion is durable too.
        let second = FileSessionStore::open(path.clone()).unwrap();
        let records = second.list_for_agent(&agent()).unwrap();
        let child = records
            .iter()
            .find(|record| record.constraints.is_some())
            .unwrap();
        assert_eq!(
            child.constraints.as_ref().unwrap().remaining_requests,
            Some(1)
        );
        second.consume_budget(&child_token).unwrap();
        assert!(matches!(
            second.consume_budget(&child_token),
            Err(BrokerError::BudgetExhausted)
        ));
        drop(second);

        let third = FileSessionStore::open(path).unwrap();
        let records = third.list_for_agent(&agent()).unwrap();
        let child = records
            .iter()
            .find(|record| record.constraints.is_some())
            .unwrap();
        assert_eq!(
            child.constraints.as_ref().unwrap().remaining_requests,
            Some(0)
        );
    }
}
