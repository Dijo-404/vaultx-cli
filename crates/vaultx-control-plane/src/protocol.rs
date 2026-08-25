//! Wire DTOs for the REST route surface (plan §39) and the sync protocol
//! (plan §28). Shared verbatim with `vaultx-sync-client` so both ends
//! serialize identically.

use serde::{Deserialize, Serialize};
use vaultx_types::{AgentId, AuditEventId, CommitId, ObjectId, PolicyName, ProjectId, WorkspaceId};

pub use crate::model::{PolicyDocument, RefNamespace, RefState};

/// Protection metadata for a named environment ref.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EnvironmentMetadata {
    /// Environment ref name.
    pub name: String,
    /// Whether updates require explicit authorization.
    pub protected: bool,
}

/// A registered device public key with its fingerprint, served so sync
/// clients can check commit signatures against team device identities.
///
/// # Trust model
///
/// These keys are trusted-by-server advisory pinning material: the control
/// plane decides which keys to register and serve, so a compromised
/// control plane can register and serve its own key. Verification against
/// this material gives clients tamper-evidence in transit, not protection
/// against a fully hostile server; unsigned commit content remains
/// accepted for back-compat.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceKeyFingerprint {
    /// Raw 32-byte Ed25519 public key, lowercase hex.
    pub public_key_hex: String,
    /// Lowercase-hex SHA-256 over the raw key bytes of `public_key_hex`.
    pub fingerprint: String,
}

/// Session creation request (plan §29): either a direct login or a
/// federated/OIDC identity exchange for CI/workload contexts.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionRequest {
    /// Direct credential login.
    Password {
        /// User login.
        username: String,
        /// Credential checked against the stored verifier.
        password: String,
    },
    /// Federated/OIDC exchange; no permanent master token is issued.
    OidcExchange {
        /// Identity provider slug (`[a-z0-9-]`, max 32 chars).
        provider: String,
        /// Opaque provider assertion. Never logged or echoed.
        assertion: String,
    },
}

/// Session creation response.
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionResponse {
    /// Bearer token to present on subsequent calls.
    pub token: String,
    /// Token class string (`control_session` | `workload_exchange`).
    pub token_class: String,
}

/// Workspace view returned by the workspace routes.
#[derive(Debug, Serialize, Deserialize)]
pub struct WorkspaceView {
    /// Typed workspace id.
    pub id: WorkspaceId,
    /// Workspace name.
    pub name: String,
}

/// Project view returned by the project route.
#[derive(Debug, Serialize)]
pub struct ProjectView {
    /// Typed project id.
    pub id: ProjectId,
    /// Owning workspace id.
    pub workspace: WorkspaceId,
    /// Project name.
    pub name: String,
}

/// One encrypted object crossing the wire. `envelope_json` is the exact
/// canonical JSON of a repository `ObjectEnvelope`;
/// `content_hash` is the lowercase hex SHA-256 over those bytes and must
/// equal the digest embedded in `id`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectEntryWire {
    /// Content-derived object id (`obj_<64 hex>`).
    pub id: ObjectId,
    /// Lowercase hex SHA-256 of `envelope_json`.
    pub content_hash: String,
    /// Canonical envelope JSON bytes as a string.
    pub envelope_json: String,
}

/// Request body of `POST /projects/{id}/objects/batch`.
#[derive(Debug, Serialize, Deserialize)]
pub struct BatchObjectsRequest {
    /// Objects to store; each is hash-validated before persistence.
    pub entries: Vec<ObjectEntryWire>,
}

/// Response of `POST /projects/{id}/objects/batch`.
#[derive(Debug, Serialize, Deserialize)]
pub struct BatchObjectsResponse {
    /// Newly stored objects (duplicates are idempotent no-ops).
    pub stored: usize,
    /// Objects already present remotely.
    pub duplicates: usize,
}

/// Signed device identity attached to a sync query (plan §28).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceIdentity {
    /// 32-byte Ed25519 public key, lowercase hex.
    pub public_key_hex: String,
    /// Hex signature over [`device_attestation_message`].
    pub signature_hex: String,
}

/// Request body of `POST /projects/{id}/objects/query-missing`.
///
/// The client declares what it already has; the server answers with what
/// it is missing plus remote metadata. The client independently verifies
/// every returned object's content hash before applying it.
#[derive(Debug, Serialize, Deserialize)]
pub struct QueryMissingRequest {
    /// Object ids the client already holds locally.
    pub known_object_ids: Vec<ObjectId>,
    /// Refs the client currently knows about.
    pub known_refs: Vec<RefState>,
    /// Requested project context (echoed for signature coverage).
    pub project: ProjectId,
    /// Signed device identity.
    pub device: DeviceIdentity,
}

/// Response of `POST /projects/{id}/objects/query-missing` (plan §28:
/// missing encrypted objects, remote refs, policy metadata, environment
/// metadata, signature/public-key material).
#[derive(Debug, Serialize, Deserialize)]
pub struct QueryMissingResponse {
    /// Encrypted objects the client is missing, capped per response at the
    /// server's limit.
    pub missing_objects: Vec<ObjectEntryWire>,
    /// True when more missing objects exist than fit in one response;
    /// clients must re-query (their known set has advanced) until false.
    #[serde(default)]
    pub missing_objects_truncated: bool,
    /// Every ref currently recorded server-side.
    pub remote_refs: Vec<RefState>,
    /// All object ids the server holds (lets push compute its upload set).
    pub remote_object_ids: Vec<ObjectId>,
    /// Policy documents bound to the project.
    pub policies: Vec<PolicyDocument>,
    /// Environment protection metadata.
    pub environments: Vec<EnvironmentMetadata>,
    /// Registered device public keys of the project's principals: raw
    /// Ed25519 bytes plus fingerprint. Trusted-by-server advisory pinning
    /// material — a compromised control plane can register and serve its
    /// own key; unsigned commit content is still accepted (see
    /// [`DeviceKeyFingerprint`]).
    pub server_key_fingerprints: Vec<DeviceKeyFingerprint>,
}

/// Request body of `PUT /projects/{id}/refs/{name}`.
#[derive(Debug, Serialize, Deserialize)]
pub struct PutRefRequest {
    /// Namespace of the target ref.
    pub namespace: RefNamespace,
    /// New commit for the ref.
    pub commit: CommitId,
    /// Optimistic-concurrency base: reject unless the current remote value
    /// equals this commit (`None` requires the ref to not exist yet).
    #[serde(default)]
    pub base_commit: Option<CommitId>,
    /// Explicit authorization acknowledgment required to move protected
    /// environment refs.
    #[serde(default)]
    pub authorized: bool,
}

/// Response body of a successful ref update.
#[derive(Debug, Serialize, Deserialize)]
pub struct PutRefResponse {
    /// Commit now recorded remotely.
    pub commit: CommitId,
}

/// Agent registration request of `POST /projects/{id}/agents`.
#[derive(Debug, Deserialize)]
pub struct CreateAgentRequest {
    /// Human-readable agent label.
    pub display_name: String,
    /// Stored agent policy binding (subordination requirement, plan §29).
    pub policy_name: PolicyName,
}

/// Agent registration response.
#[derive(Debug, Serialize, Deserialize)]
pub struct CreatedAgentResponse {
    /// Typed agent identity.
    pub agent_id: AgentId,
    /// Bound policy name.
    pub policy_name: PolicyName,
    /// Freshly minted subordinate agent session bearer token (`vxa_…`).
    pub session_token: String,
}

/// Agent view returned by `GET /projects/{id}/agents`. Tokens never echo.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentView {
    /// Typed agent identity.
    pub agent_id: AgentId,
    /// Display label.
    pub display_name: String,
    /// Bound policy name.
    pub policy_name: PolicyName,
    /// Whether the identity has been revoked.
    pub revoked: bool,
}

/// Audit event view returned by `GET /projects/{id}/audit`.
///
/// Every stored event — whether recorded internally by a route or
/// accepted through `POST /projects/{id}/audit` — participates in one
/// per-project hash chain: `sequence` numbers events contiguously from
/// zero and `prev_hash` carries the hex SHA-256 over the canonical JSON
/// serialization of the preceding event (`None` for the project's
/// genesis event).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuditEventView {
    /// Typed audit event id.
    pub event_id: AuditEventId,
    /// Acting principal.
    pub actor: String,
    /// Action code (e.g. `ref.update`).
    pub action: String,
    /// Secret-free structured detail.
    pub detail: serde_json::Value,
    /// Unix seconds at ingestion.
    pub occurred_at_unix: u64,
    /// Contiguous per-project position (genesis = 0).
    #[serde(default)]
    pub sequence: u64,
    /// Hex SHA-256 over the preceding event's canonical form; `None` for
    /// the genesis event.
    #[serde(default)]
    pub prev_hash: Option<String>,
}

/// One client-supplied audit event of `POST /projects/{id}/audit`.
///
/// Server-assigned identity fields (`event_id`, `sequence`, `prev_hash`,
/// `occurred_at_unix`) are deliberately absent: the server mints them at
/// ingestion so the chain it anchors is the chain it vouches for.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IngestEvent {
    /// Acting principal; must be non-empty.
    pub actor: String,
    /// Action code (e.g. `secret-rotate`); must be non-empty.
    pub action: String,
    /// Secret-free structured detail; defaults to an empty object when
    /// omitted.
    #[serde(default = "empty_audit_detail")]
    pub detail: serde_json::Value,
}

fn empty_audit_detail() -> serde_json::Value {
    serde_json::json!({})
}

/// Request body of `POST /projects/{id}/audit`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuditIngestRequest {
    /// Events to ingest; individually validated so valid entries are
    /// accepted even when siblings are rejected.
    pub events: Vec<IngestEvent>,
}

/// Why one ingested event was refused, reported by input position.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditIngestRejection {
    /// Position of the offending event inside the request's `events`
    /// array.
    pub index: usize,
    /// Static, secret-free refusal reason.
    pub reason: String,
}

/// Response body of `POST /projects/{id}/audit`. A 200 status reports
/// partial acceptance; only a malformed envelope is rejected outright
/// with 400.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditIngestResult {
    /// Events appended to the project's audit chain.
    pub accepted: usize,
    /// Refused events with their request positions and reasons.
    #[serde(default)]
    pub rejected: Vec<AuditIngestRejection>,
}

/// Deterministic message covered by the device attestation signature for
/// `project` under the device key with compressed form `public_key_hex`.
///
/// Both protocol peers call this so the signed bytes cannot drift.
#[must_use]
pub fn device_attestation_message(project: &ProjectId, public_key_hex: &str) -> Vec<u8> {
    format!("vaultx-device-attestation-v1\nproject:{project}\npublic-key:{public_key_hex}\n")
        .into_bytes()
}
