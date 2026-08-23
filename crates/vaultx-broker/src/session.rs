//! Agent session authentication (plan §25).
//!
//! A session binds an agent identity to an environment and is exercised
//! with a bearer-style token. Only the SHA-256 **verifier hash** of the
//! token is ever stored — the raw token exists exactly twice: returned
//! once by [`SessionStore::create`], and held in the caller's hands
//! afterwards. Validation compares verifier hashes in constant time
//! ([`subtle`]) so token guessing cannot be timed.

use std::collections::HashMap;
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

/// Stored state of one agent session (plan §25). Mirrors the plan's
/// `AgentSession` shape: identity binding plus the token *verifier* and a
/// revocation flag.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
}

/// True when `record` can no longer validate: revoked or past its expiry.
fn is_dead(record: &AgentSessionRecord, clock: &std::sync::atomic::AtomicU64) -> bool {
    record.revoked
        || record
            .expires_at_secs
            .is_some_and(|expiry| expiry <= now_secs(clock))
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
            },
        );
        state.by_hash.insert(token_hash, session_id.clone());
        Ok((session_id, raw_token))
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
    /// Propagates I/O failures, JSON corruption, and permission-refusal
    /// ([`BrokerError::TransportFailure`]) when the existing file is
    /// readable by group/other.
    pub fn open(path: PathBuf) -> Result<Self, BrokerError> {
        if path.exists() {
            Self::check_mode(&path)?;
            // Corruption is surfaced eagerly so operators learn about it
            // before the first mutation would clobber context.
            let text = std::fs::read_to_string(&path).map_err(|err| {
                BrokerError::TransportFailure(format!("cannot read session store: {err}"))
            })?;
            let _: Vec<AgentSessionRecord> = serde_json::from_str(&text).map_err(|err| {
                BrokerError::TransportFailure(format!("corrupt session store: {err}"))
            })?;
        }
        let mut lock_name = path.clone().into_os_string();
        lock_name.push(".lock");
        Ok(Self {
            path,
            lock_path: PathBuf::from(lock_name),
            clock_override: std::sync::atomic::AtomicU64::new(0),
        })
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
            use std::os::unix::fs::OpenOptionsExt as _;
            if let Some(parent) = self.lock_path.parent() {
                std::fs::create_dir_all(parent).map_err(|err| {
                    BrokerError::TransportFailure(format!("cannot create session dir: {err}"))
                })?;
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
    fn load_records(&self) -> Result<Vec<AgentSessionRecord>, BrokerError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        Self::check_mode(&self.path)?;
        let text = std::fs::read_to_string(&self.path).map_err(|err| {
            BrokerError::TransportFailure(format!("cannot read session store: {err}"))
        })?;
        serde_json::from_str(&text)
            .map_err(|err| BrokerError::TransportFailure(format!("corrupt session store: {err}")))
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
}
