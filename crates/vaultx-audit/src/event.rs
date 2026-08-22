//! Structured audit event schema plus hash-chain integrity (plan §27).
//!
//! # Redaction guarantees
//!
//! Audit events must capture decisions without becoming a secret
//! exfiltration surface. The guarantee here is structural:
//!
//! - No field exists anywhere in the schema for credential plaintext,
//!   `Authorization`-style header values, unfiltered request bodies,
//!   unfiltered provider responses, or session bearer tokens.
//! - [`SafeDestinationSummary`] carries host/port/path only; the query
//!   component of a URL is excluded by construction because query strings
//!   routinely carry credential material (`?token=...`).
//! - [`SafeAuditMetadata`] rejects keys naming sensitive material and
//!   bounds every value to a small byte budget.
//!
//! Integrity uses chained SHA-256 hashes: every stored event links to its
//! predecessor through [`AuditEvent::prev_hash`] and exposes its own
//! digest through [`AuditEvent::hash`].

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use vaultx_policy::Principal;
use vaultx_types::{AuditEventId, CredentialRef, EnvironmentId, PolicyId, ProjectId};

use crate::error::AuditError;

/// Number of random bytes behind generated identifiers (rendered as 32
/// hex characters).
const RANDOM_ID_BYTES: usize = 16;

fn random_hex(bytes: usize) -> Result<String, AuditError> {
    let mut buffer = vec![0u8; bytes];
    getrandom::getrandom(&mut buffer).map_err(|e| AuditError::Entropy(e.to_string()))?;
    Ok(hex::encode(buffer))
}

// ---------------------------------------------------------------------------
// CorrelationId
// ---------------------------------------------------------------------------

/// Maximum length of a correlation id.
pub const CORRELATION_ID_MAX_LEN: usize = 64;

/// Trace identifier shared by every audit event belonging to one logical
/// operation.
///
/// Non-empty, at most 64 characters from `[a-z0-9_-]`.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct CorrelationId(String);

impl CorrelationId {
    /// Maximum accepted length.
    pub const MAX_LEN: usize = CORRELATION_ID_MAX_LEN;

    /// Parses and validates a correlation id.
    ///
    /// # Errors
    /// Returns [`AuditError::InvalidMetadata`] when the value is empty,
    /// too long, or contains characters outside `[a-z0-9_-]`.
    pub fn parse(value: &str) -> Result<Self, AuditError> {
        let invalid = |reason: String| AuditError::InvalidMetadata {
            key: "correlation_id".to_owned(),
            reason,
        };
        if value.is_empty() {
            return Err(invalid("must not be empty".to_owned()));
        }
        if value.chars().count() > Self::MAX_LEN {
            return Err(invalid(format!(
                "must be at most {} characters",
                Self::MAX_LEN
            )));
        }
        if !value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
        {
            return Err(invalid(
                "must contain only lowercase alphanumerics, `-` and `_`".to_owned(),
            ));
        }
        Ok(Self(value.to_owned()))
    }

    /// Generates a fresh random correlation id (32 hex characters).
    ///
    /// # Errors
    /// Returns [`AuditError::Entropy`] when secure randomness is
    /// unavailable.
    pub fn generate() -> Result<Self, AuditError> {
        Self::parse(&random_hex(RANDOM_ID_BYTES)?)
    }

    /// Returns the canonical string form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for CorrelationId {
    type Err = AuditError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for CorrelationId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for CorrelationId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(D::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// CapabilityName
// ---------------------------------------------------------------------------

/// Maximum length of a capability name.
pub const CAPABILITY_NAME_MAX_LEN: usize = 128;

/// Dotted capability identifier such as `github.pull_request.create`.
///
/// Non-empty, at most 128 characters from `[a-z0-9._-]`, with every
/// dot-separated segment non-empty.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct CapabilityName(String);

impl CapabilityName {
    /// Maximum accepted length.
    pub const MAX_LEN: usize = CAPABILITY_NAME_MAX_LEN;

    /// Parses and validates a capability name.
    ///
    /// # Errors
    /// Returns [`AuditError::InvalidMetadata`] when the value is empty,
    /// too long, contains characters outside `[a-z0-9._-]`, or has an
    /// empty dot-separated segment.
    pub fn parse(value: &str) -> Result<Self, AuditError> {
        let invalid = |reason: String| AuditError::InvalidMetadata {
            key: "capability_name".to_owned(),
            reason,
        };
        if value.is_empty() {
            return Err(invalid("must not be empty".to_owned()));
        }
        if value.chars().count() > Self::MAX_LEN {
            return Err(invalid(format!(
                "must be at most {} characters",
                Self::MAX_LEN
            )));
        }
        if !value.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-' || c == '_'
        }) {
            return Err(invalid(
                "must contain only lowercase alphanumerics, `.`, `-` and `_`".to_owned(),
            ));
        }
        if value.split('.').any(str::is_empty) {
            return Err(invalid(
                "dot-separated segments must be non-empty".to_owned(),
            ));
        }
        Ok(Self(value.to_owned()))
    }

    /// Returns the canonical string form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CapabilityName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for CapabilityName {
    type Err = AuditError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for CapabilityName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for CapabilityName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(D::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Action / decision
// ---------------------------------------------------------------------------

/// The operation an audit event records.
///
/// Serialized in kebab-case (`http-request`, `secret-rotate`, ...).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditAction {
    /// An HTTP request proxied through the broker.
    HttpRequest,
    /// An agent session was created.
    SessionCreated,
    /// An agent session was revoked.
    SessionRevoked,
    /// A secret value was set.
    SecretSet,
    /// A secret revision was rotated.
    SecretRotate,
    /// A secret entry was destroyed.
    SecretDestroy,
    /// A configuration commit landed.
    ConfigCommitted,
    /// A policy document changed.
    PolicyUpdated,
}

/// Authorization outcome recorded for an audit event.
///
/// Externally tagged kebab-case serialization: `Allow` renders as
/// `"allow"` and `Deny { reason }` as `{"deny":{"reason":"..."}}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditDecision {
    /// The operation was permitted.
    Allow,
    /// The operation was refused; `reason` is a policy-authored denial
    /// category, never request content.
    Deny {
        /// Why the operation was denied.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// SafeDestinationSummary
// ---------------------------------------------------------------------------

/// Destination summary recorded for proxied requests: host, port, path —
/// **never** the query string.
///
/// Query components are deliberately excluded by construction because
/// they routinely carry credential material (`?token=...`,
/// `?api_key=...`, OAuth codes). Since no field exists to hold them, they
/// cannot leak into audit storage through any API this crate offers.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize)]
pub struct SafeDestinationSummary {
    host: String,
    port: u16,
    path: String,
}

impl SafeDestinationSummary {
    /// Maximum accepted host length (DNS name limit).
    pub const HOST_MAX_LEN: usize = 253;

    /// Validates and constructs a destination summary.
    ///
    /// # Errors
    /// Returns [`AuditError::InvalidMetadata`] when `host` is empty or
    /// not lowercase hostname-shaped, or when `path` does not start with
    /// `/`.
    pub fn new(host: &str, port: u16, path: &str) -> Result<Self, AuditError> {
        validate_destination_host(host)?;
        validate_destination_path(path)?;
        Ok(Self {
            host: host.to_owned(),
            port,
            path: path.to_owned(),
        })
    }

    /// Lowercased destination host.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Destination port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Request path starting with `/`; the query string is structurally
    /// absent.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
}

fn validate_destination_host(host: &str) -> Result<(), AuditError> {
    let reject = |reason: String| AuditError::InvalidMetadata {
        key: "destination.host".to_owned(),
        reason,
    };
    if host.is_empty() {
        return Err(reject("must not be empty".to_owned()));
    }
    if host.len() > SafeDestinationSummary::HOST_MAX_LEN {
        return Err(reject(format!(
            "must be at most {} bytes",
            SafeDestinationSummary::HOST_MAX_LEN
        )));
    }
    if !host
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
    {
        return Err(reject(
            "must contain only lowercase letters, digits, dots and hyphens".to_owned(),
        ));
    }
    if host.split('.').any(|label| {
        label.is_empty()
            || !label.starts_with(|c: char| c.is_ascii_alphanumeric())
            || !label.ends_with(|c: char| c.is_ascii_alphanumeric())
    }) {
        return Err(reject(
            "dotted labels must be non-empty and start/end with an alphanumeric".to_owned(),
        ));
    }
    Ok(())
}

fn validate_destination_path(path: &str) -> Result<(), AuditError> {
    let reject = |reason: String| AuditError::InvalidMetadata {
        key: "destination.path".to_owned(),
        reason,
    };
    if !path.starts_with('/') {
        return Err(reject("must start with `/`".to_owned()));
    }
    if path.chars().any(char::is_control) {
        return Err(reject("must not contain control characters".to_owned()));
    }
    Ok(())
}

impl<'de> Deserialize<'de> for SafeDestinationSummary {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            host: String,
            port: u16,
            path: String,
        }
        let raw = Raw::deserialize(deserializer)?;
        Self::new(&raw.host, raw.port, &raw.path).map_err(D::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// SafeAuditMetadata
// ---------------------------------------------------------------------------

/// Maximum number of metadata entries per event.
pub const MAX_METADATA_ENTRIES: usize = 64;

/// Maximum byte length of a single metadata value.
pub const MAX_METADATA_VALUE_BYTES: usize = 512;

/// Key terms that mark a metadata key as sensitive. Matching is
/// case-insensitive substring containment so variants like
/// `X-Custom-Token` are also rejected (fail-closed).
#[rustfmt::skip]
const SENSITIVE_KEY_TERMS: [&str; 11] = [
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "secret", "token", "password", "api-key", "x-api-key",
    "private-key", "session-token",
];

/// Bounded, redaction-checked free-form metadata attached to an event.
///
/// Values may be arbitrary caller-supplied strings up to 512 bytes; the
/// redaction guarantee lives in the *key* filter (no key naming credential
/// or authentication material can be stored) and in the structural absence
/// of dedicated secret fields elsewhere in the schema. Keys must be
/// lowercase token characters (`a-z`, digits, `_`, `-`, `.`), and the map
/// holds at most 64 entries.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct SafeAuditMetadata(BTreeMap<String, String>);

impl SafeAuditMetadata {
    /// Inserts a validated entry, replacing any previous value for the
    /// same key.
    ///
    /// # Errors
    /// Returns [`AuditError::InvalidMetadata`] when the key names
    /// sensitive material, uses invalid characters, exceeds the value
    /// byte budget, or when inserting a new key beyond the entry cap.
    pub fn try_insert(&mut self, key: &str, value: &str) -> Result<(), AuditError> {
        validate_metadata_pair(key, value)?;
        if !self.0.contains_key(key) && self.0.len() >= MAX_METADATA_ENTRIES {
            return Err(AuditError::InvalidMetadata {
                key: key.to_owned(),
                reason: format!(
                    "metadata already holds the maximum of {MAX_METADATA_ENTRIES} entries"
                ),
            });
        }
        self.0.insert(key.to_owned(), value.to_owned());
        Ok(())
    }

    /// Builds metadata from key/value pairs, failing on the first
    /// rejected pair.
    ///
    /// # Errors
    /// Propagates [`AuditError::InvalidMetadata`] from [`Self::try_insert`].
    pub fn from_pairs<K: AsRef<str>, V: AsRef<str>>(
        pairs: impl IntoIterator<Item = (K, V)>,
    ) -> Result<Self, AuditError> {
        let mut metadata = Self(BTreeMap::new());
        for (key, value) in pairs {
            metadata.try_insert(key.as_ref(), value.as_ref())?;
        }
        Ok(metadata)
    }

    /// Iterates entries in sorted key order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> + '_ {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Looks up an entry by exact key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when there are no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

fn validate_metadata_pair(key: &str, value: &str) -> Result<(), AuditError> {
    let rejected = |reason: String| AuditError::InvalidMetadata {
        key: key.to_owned(),
        reason,
    };
    // Redaction check first: even a mixed-case sensitive key gets the
    // precise diagnostic instead of the charset one.
    let lowered = key.to_ascii_lowercase();
    if SENSITIVE_KEY_TERMS
        .iter()
        .any(|term| lowered.contains(term))
    {
        return Err(rejected(
            "names credential or authentication material and cannot enter audit metadata"
                .to_owned(),
        ));
    }
    if key.is_empty() {
        return Err(rejected("key must not be empty".to_owned()));
    }
    if !key.bytes().all(|b| {
        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-' || b == b'.'
    }) {
        return Err(rejected(
            "key must contain only lowercase token characters (`a-z`, digits, `_`, `-`, `.`)"
                .to_owned(),
        ));
    }
    if value.len() > MAX_METADATA_VALUE_BYTES {
        return Err(rejected(format!(
            "value exceeds maximum of {MAX_METADATA_VALUE_BYTES} bytes"
        )));
    }
    Ok(())
}

impl Serialize for SafeAuditMetadata {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_map(self.0.iter())
    }
}

impl<'de> Deserialize<'de> for SafeAuditMetadata {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = BTreeMap::<String, String>::deserialize(deserializer)?;
        Self::from_pairs(raw).map_err(D::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Event payloads
// ---------------------------------------------------------------------------

/// Input payload for a new audit event.
///
/// Carries no identity or chain fields: the store generates the event id,
/// assigns the sequence number, and links the hash chain on append.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewAuditEvent {
    /// Trace id shared with related events.
    pub correlation_id: CorrelationId,
    /// Agent/session identity that performed the action.
    pub actor: Principal,
    /// Project the action belongs to.
    pub project: ProjectId,
    /// Optional environment the action targeted.
    pub environment: Option<EnvironmentId>,
    /// Operation being audited.
    pub action: AuditAction,
    /// Authorization outcome.
    pub decision: AuditDecision,
    /// Logical reference to the credential involved, if any.
    pub credential: Option<CredentialRef>,
    /// Safe host/port/path summary of the destination, if any.
    pub destination: Option<SafeDestinationSummary>,
    /// Dotted capability exercised, if any.
    pub capability: Option<CapabilityName>,
    /// Policies that participated in the decision.
    pub policy_ids: Vec<PolicyId>,
    /// Bounded, redaction-checked metadata.
    pub metadata: SafeAuditMetadata,
}

/// Stored audit record (plan §27) extended with hash-chain fields.
///
/// `sequence` numbers events contiguously from zero inside one store and
/// `prev_hash` carries the SHA-256 digest of the preceding event's
/// canonical form (`None` for the genesis event).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Store-generated identifier (`aud_...`).
    pub id: AuditEventId,
    /// Trace id shared with related events.
    pub correlation_id: CorrelationId,
    /// Contiguous position within the store (genesis = 0).
    pub sequence: u64,
    /// Hex SHA-256 of the previous event's canonical form; `None` for the
    /// genesis event.
    pub prev_hash: Option<String>,
    /// Agent/session identity that performed the action.
    pub actor: Principal,
    /// Project the action belongs to.
    pub project: ProjectId,
    /// Optional environment the action targeted.
    pub environment: Option<EnvironmentId>,
    /// Operation being audited.
    pub action: AuditAction,
    /// Authorization outcome.
    pub decision: AuditDecision,
    /// Logical reference to the credential involved, if any.
    pub credential: Option<CredentialRef>,
    /// Safe host/port/path summary of the destination, if any.
    pub destination: Option<SafeDestinationSummary>,
    /// Dotted capability exercised, if any.
    pub capability: Option<CapabilityName>,
    /// Policies that participated in the decision.
    pub policy_ids: Vec<PolicyId>,
    /// Bounded, redaction-checked metadata.
    pub metadata: SafeAuditMetadata,
}

impl AuditEvent {
    /// Computes this event's chain digest: hex-encoded SHA-256 over the
    /// canonical JSON serialization of the entire event (every field,
    /// including `sequence` and `prev_hash`; nothing excluded).
    ///
    /// Canonicality follows the workspace convention: serde_json output
    /// with struct fields in declaration order and map keys sorted
    /// ([`SafeAuditMetadata`] is a `BTreeMap`). The digest itself is
    /// derived, never stored — a consequence being that chain linkage can
    /// only detect tampering of an event through a *later* event's
    /// `prev_hash`, so the most recent event's bytes are not covered by
    /// [`crate::store::AppendStore::verify_chain`] alone; head signatures
    /// (plan §27 "where configured") close that gap.
    ///
    /// # Errors
    /// Returns [`AuditError::Serialization`] only if JSON encoding fails,
    /// which cannot happen for the types used by this schema.
    pub fn hash(&self) -> Result<String, AuditError> {
        let canonical =
            serde_json::to_vec(self).map_err(|e| AuditError::Serialization(e.to_string()))?;
        Ok(hex::encode(Sha256::digest(canonical)))
    }
}

/// Generates a fresh random audit event id (`aud_<32 hex>`).
///
/// # Errors
/// Returns [`AuditError::Entropy`] when secure randomness is unavailable.
pub fn generate_audit_event_id() -> Result<AuditEventId, AuditError> {
    let suffix = random_hex(RANDOM_ID_BYTES)?;
    AuditEventId::parse(&format!("aud_{suffix}"))
        .map_err(|e| AuditError::Serialization(format!("generated id rejected: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_actor() -> Principal {
        Principal::parse("agent:test-agent").expect("valid principal")
    }

    fn sample_project() -> ProjectId {
        ProjectId::parse("proj_core").expect("valid project")
    }

    fn sample_metadata() -> SafeAuditMetadata {
        SafeAuditMetadata::from_pairs([("http.method", "GET")]).expect("valid metadata")
    }

    fn sample_new_event() -> NewAuditEvent {
        NewAuditEvent {
            correlation_id: CorrelationId::parse("corr-sample").expect("valid correlation"),
            actor: sample_actor(),
            project: sample_project(),
            environment: None,
            action: AuditAction::HttpRequest,
            decision: AuditDecision::Allow,
            credential: None,
            destination: None,
            capability: None,
            policy_ids: Vec::new(),
            metadata: sample_metadata(),
        }
    }

    fn stored_event(
        sequence: u64,
        prev_hash: Option<String>,
        new_event: NewAuditEvent,
    ) -> AuditEvent {
        AuditEvent {
            id: generate_audit_event_id().expect("generated id"),
            correlation_id: new_event.correlation_id,
            sequence,
            prev_hash,
            actor: new_event.actor,
            project: new_event.project,
            environment: new_event.environment,
            action: new_event.action,
            decision: new_event.decision,
            credential: new_event.credential,
            destination: new_event.destination,
            capability: new_event.capability,
            policy_ids: new_event.policy_ids,
            metadata: new_event.metadata,
        }
    }

    #[test]
    fn correlation_id_validation_matrix() {
        for ok in ["corr-1", "a_b-c", "0123456789"] {
            assert!(CorrelationId::parse(ok).is_ok(), "{ok} should parse");
        }
        assert_eq!("corr".parse::<CorrelationId>().unwrap().as_str(), "corr");
        for bad in [
            "",
            "Corr-1",
            "has space",
            "with.dot",
            "slash/ed",
            "unicode-é",
        ] {
            assert!(
                matches!(
                    CorrelationId::parse(bad),
                    Err(AuditError::InvalidMetadata { .. })
                ),
                "{bad:?} should be rejected"
            );
        }
        let long = "a".repeat(CorrelationId::MAX_LEN + 1);
        assert!(matches!(
            CorrelationId::parse(&long),
            Err(AuditError::InvalidMetadata { .. })
        ));
        assert!(CorrelationId::parse(&"a".repeat(CorrelationId::MAX_LEN)).is_ok());
    }

    #[test]
    fn correlation_id_generate_produces_valid_ids() {
        let first = CorrelationId::generate().expect("generation works");
        let second = CorrelationId::generate().expect("generation works");
        assert_eq!(first.as_str().len(), 32);
        assert_ne!(first, second);
    }

    #[test]
    fn capability_name_validation() {
        assert!(CapabilityName::parse("github.pull_request.create").is_ok());
        assert_eq!(
            "github.pull_request.create"
                .parse::<CapabilityName>()
                .unwrap()
                .as_str(),
            "github.pull_request.create"
        );
        for bad in [
            "",
            ".github.push",
            "github.push.",
            "github..push",
            "GitHub.push",
            "github/push",
            "has space",
        ] {
            assert!(
                matches!(
                    CapabilityName::parse(bad),
                    Err(AuditError::InvalidMetadata { .. })
                ),
                "{bad:?} should be rejected"
            );
        }
        assert!(CapabilityName::parse(&"a".repeat(CapabilityName::MAX_LEN)).is_ok());
        assert!(matches!(
            CapabilityName::parse(&"a".repeat(CapabilityName::MAX_LEN + 1)),
            Err(AuditError::InvalidMetadata { .. })
        ));
    }

    #[test]
    fn audit_action_serde_uses_kebab_case() {
        let cases: [(AuditAction, &str); 8] = [
            (AuditAction::HttpRequest, "\"http-request\""),
            (AuditAction::SessionCreated, "\"session-created\""),
            (AuditAction::SessionRevoked, "\"session-revoked\""),
            (AuditAction::SecretSet, "\"secret-set\""),
            (AuditAction::SecretRotate, "\"secret-rotate\""),
            (AuditAction::SecretDestroy, "\"secret-destroy\""),
            (AuditAction::ConfigCommitted, "\"config-committed\""),
            (AuditAction::PolicyUpdated, "\"policy-updated\""),
        ];
        for (action, json) in cases {
            assert_eq!(serde_json::to_string(&action).unwrap(), json);
            assert_eq!(serde_json::from_str::<AuditAction>(json).unwrap(), action);
        }
    }

    #[test]
    fn audit_decision_serde_is_externally_tagged_kebab_case() {
        let allow_json = serde_json::to_string(&AuditDecision::Allow).unwrap();
        assert_eq!(allow_json, "\"allow\"");
        let deny = AuditDecision::Deny {
            reason: "no matching policy".to_owned(),
        };
        let deny_json = serde_json::to_string(&deny).unwrap();
        assert_eq!(deny_json, "{\"deny\":{\"reason\":\"no matching policy\"}}");
        let decoded: AuditDecision = serde_json::from_str(&deny_json).unwrap();
        assert_eq!(decoded, deny);
    }

    #[test]
    fn destination_summary_validates_host_and_path() {
        let good = SafeDestinationSummary::new("api.github.com", 443, "/repos/vaultx").unwrap();
        assert_eq!(good.host(), "api.github.com");
        assert_eq!(good.port(), 443);
        assert_eq!(good.path(), "/repos/vaultx");
        assert!(SafeDestinationSummary::new("localhost", 8080, "/").is_ok());

        for bad_host in [
            "",
            "API.example.com",
            "host..com",
            "-lead.example.com",
            "trail-.example.com",
            "example.com.",
            "ho st.com",
            "example.com/path",
        ] {
            assert!(
                matches!(
                    SafeDestinationSummary::new(bad_host, 443, "/"),
                    Err(AuditError::InvalidMetadata { .. })
                ),
                "host {bad_host:?} should be rejected"
            );
        }
        for bad_path in ["", "no-slash", "relative/path"] {
            assert!(
                matches!(
                    SafeDestinationSummary::new("example.com", 443, bad_path),
                    Err(AuditError::InvalidMetadata { .. })
                ),
                "path {bad_path:?} should be rejected"
            );
        }
        assert!(
            matches!(
                SafeDestinationSummary::new("example.com", 443, "/bad\u{7f}char"),
                Err(AuditError::InvalidMetadata { .. })
            ),
            "control characters should be rejected"
        );
    }

    #[test]
    fn destination_summary_excludes_query_by_construction() {
        let summary = SafeDestinationSummary::new("api.github.com", 443, "/user/repos").unwrap();
        let json = serde_json::to_value(&summary).unwrap();
        let object = json.as_object().unwrap();
        let mut keys: Vec<_> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["host", "path", "port"]);
        // No field exists to carry a query string; round trip keeps it out.
        let decoded: SafeDestinationSummary = serde_json::from_value(json).unwrap();
        assert_eq!(decoded, summary);
    }

    #[test]
    fn metadata_rejects_sensitive_keys_case_insensitively() {
        let sensitive = [
            "Authorization",
            "AUTHORIZATION",
            "authorization",
            "Proxy-Authorization",
            "Cookie",
            "SET-COOKIE",
            "set-cookie",
            "Secret",
            "TOKEN",
            "token",
            "Password",
            "API-Key",
            "X-API-KEY",
            "x-api-key",
            "Private-Key",
            "Session-Token",
            // Substring variants must fail closed too.
            "x-custom-token",
            "my-secret-value",
            "rotated-password-note",
        ];
        for key in sensitive {
            let mut metadata = SafeAuditMetadata::default();
            assert!(
                matches!(
                    metadata.try_insert(key, "irrelevant"),
                    Err(AuditError::InvalidMetadata { .. })
                ),
                "{key} should be rejected"
            );
            assert!(metadata.is_empty(), "rejected keys must not be stored");
        }
        // Error display names the key but never echoes the value.
        let err = SafeAuditMetadata::default()
            .try_insert("authorization", "SUPER_SECRET_BEARER_VALUE")
            .unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("authorization"));
        assert!(!rendered.contains("SUPER_SECRET_BEARER_VALUE"));
    }

    #[test]
    fn metadata_accepts_benign_keys_and_enforces_key_charset() {
        let mut metadata = SafeAuditMetadata::default();
        metadata.try_insert("http.method", "GET").unwrap();
        metadata.try_insert("request_bytes", "1024").unwrap();
        metadata.try_insert("policy-count", "3").unwrap();
        assert_eq!(metadata.get("http.method"), Some("GET"));

        for bad_key in ["", "Upper-Case", "has space", "slash/ed"] {
            let mut candidate = SafeAuditMetadata::default();
            assert!(candidate.try_insert(bad_key, "x").is_err(), "{bad_key:?}");
        }
    }

    #[test]
    fn metadata_enforces_value_byte_cap() {
        let mut metadata = SafeAuditMetadata::default();
        let exactly_cap = "a".repeat(MAX_METADATA_VALUE_BYTES);
        metadata.try_insert("note", &exactly_cap).unwrap();
        let over_cap = "a".repeat(MAX_METADATA_VALUE_BYTES + 1);
        assert!(metadata.try_insert("other", &over_cap).is_err());
    }

    #[test]
    fn metadata_enforces_entry_cap() {
        let mut metadata = SafeAuditMetadata::default();
        for index in 0..MAX_METADATA_ENTRIES {
            metadata
                .try_insert(&format!("key-{index:02}"), "v")
                .expect("within cap");
        }
        assert!(metadata.try_insert("one-too-many", "v").is_err());
        // Replacing an existing key stays allowed at cap.
        metadata.try_insert("key-00", "updated").unwrap();
        assert_eq!(metadata.get("key-00"), Some("updated"));
    }

    #[test]
    fn metadata_serde_round_trips_as_plain_map_and_rejects_hostile_keys() {
        let metadata =
            SafeAuditMetadata::from_pairs([("http.method", "GET"), ("status", "200")]).unwrap();
        let json = serde_json::to_string(&metadata).unwrap();
        assert_eq!(json, "{\"http.method\":\"GET\",\"status\":\"200\"}");
        let decoded: SafeAuditMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, metadata);

        let hostile = r#"{"Authorization":"Bearer leaked-value"}"#;
        assert!(serde_json::from_str::<SafeAuditMetadata>(hostile).is_err());

        let from_pairs_err = SafeAuditMetadata::from_pairs([("ok", "1"), ("token", "nope")]);
        assert!(matches!(
            from_pairs_err,
            Err(AuditError::InvalidMetadata { .. })
        ));
    }

    #[test]
    fn full_event_serde_round_trip_preserves_hash() {
        let new_event = NewAuditEvent {
            destination: Some(
                SafeDestinationSummary::new("api.github.com", 443, "/user/repos").unwrap(),
            ),
            capability: Some(CapabilityName::parse("github.pull_request.create").unwrap()),
            credential: Some(CredentialRef::parse("deploy_token-1").unwrap()),
            environment: Some(vaultx_types::EnvironmentId::parse("env_prod").unwrap()),
            policy_ids: vec![vaultx_types::PolicyId::parse("pol_least_privilege").unwrap()],
            decision: AuditDecision::Deny {
                reason: "path not allowed".to_owned(),
            },
            ..sample_new_event()
        };
        let event = stored_event(3, Some("deadbeef".to_owned()), new_event);
        let expected_hash = event.hash().unwrap();

        let line = serde_json::to_string(&event).unwrap();
        let decoded: AuditEvent = serde_json::from_str(&line).unwrap();
        assert_eq!(decoded, event);
        assert_eq!(decoded.hash().unwrap(), expected_hash);
    }

    #[test]
    fn hash_is_sensitive_to_content_changes() {
        let base = stored_event(0, None, sample_new_event());
        let mutated = AuditEvent {
            metadata: SafeAuditMetadata::from_pairs([("http.method", "POST")]).unwrap(),
            ..base.clone()
        };
        assert_ne!(base.hash().unwrap(), mutated.hash().unwrap());

        let relinked = AuditEvent {
            prev_hash: Some("ff00".to_owned()),
            ..base.clone()
        };
        assert_ne!(base.hash().unwrap(), relinked.hash().unwrap());

        let resequenced = AuditEvent {
            sequence: 1,
            ..base.clone()
        };
        assert_ne!(base.hash().unwrap(), resequenced.hash().unwrap());
    }

    #[test]
    fn generated_audit_event_ids_are_wellformed() {
        let id = generate_audit_event_id().unwrap();
        assert!(id.as_str().starts_with("aud_"));
        assert_eq!(id.as_str().len(), "aud_".len() + 32);
        assert_ne!(
            generate_audit_event_id().unwrap(),
            generate_audit_event_id().unwrap()
        );
    }

    #[test]
    fn genesis_event_carries_none_prev_hash_in_json() {
        let event = stored_event(0, None, sample_new_event());
        let line = serde_json::to_string(&event).unwrap();
        assert!(line.contains("\"prev_hash\":null"));
    }
}
