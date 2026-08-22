//! Storage interfaces for audit events: local append-only stores and the
//! remote ingestion seam (plan §5).

use vaultx_policy::Principal;
use vaultx_types::{CredentialRef, ProjectId};

use crate::error::AuditError;
use crate::event::{AuditAction, AuditEvent, CorrelationId, NewAuditEvent};

/// Filter selecting audit events in [`AppendStore::query`].
///
/// Every set field must match; unset fields are wildcards. `limit` stops
/// matching after that many events.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuditFilter {
    /// Match events by exact principal.
    pub actor: Option<Principal>,
    /// Match events by exact project.
    pub project: Option<ProjectId>,
    /// Match events by action type.
    pub action: Option<AuditAction>,
    /// `Some(true)` matches allows, `Some(false)` matches denies,
    /// `None` matches both.
    pub decision_allow: Option<bool>,
    /// Match events referencing this credential.
    pub credential: Option<CredentialRef>,
    /// Match events sharing this correlation id.
    pub correlation_id: Option<CorrelationId>,
    /// Maximum number of matched events returned.
    pub limit: Option<usize>,
}

/// Local append-only audit storage.
///
/// Implementations assign identity (`id`, `sequence`, `prev_hash`) on
/// append and expose hash-chain verification. All methods are callable
/// through a shared reference; implementations are responsible for
/// serializing concurrent appends within one process (cross-process
/// single-writer semantics are assumed).
pub trait AppendStore: Send + Sync {
    /// Appends an event, assigning its id, sequence number, and
    /// predecessor link; returns the stored event.
    ///
    /// # Errors
    /// Returns [`AuditError`] when identity generation fails, the
    /// underlying store is unreadable or corrupt, or the write fails.
    fn append(&self, event: NewAuditEvent) -> Result<AuditEvent, AuditError>;

    /// Returns the chain hash of the most recent stored event, or `None`
    /// when the store is empty.
    ///
    /// # Errors
    /// Returns [`AuditError`] when the store cannot be read or contains
    /// corrupt records.
    fn latest_hash(&self) -> Result<Option<String>, AuditError>;

    /// Recomputes every stored event's hash and verifies contiguous
    /// sequencing plus predecessor linkage.
    ///
    /// # Errors
    /// Returns [`AuditError::ChainBroken`] naming the first event whose
    /// sequence number or linkage does not hold, and
    /// [`AuditError::CorruptRecord`] when any record cannot be parsed.
    fn verify_chain(&self) -> Result<(), AuditError>;

    /// Streams stored events applying `filter`, stopping once the filter's
    /// limit is reached.
    ///
    /// # Errors
    /// Returns [`AuditError`] when the store cannot be read or contains
    /// corrupt records.
    fn query(&self, filter: &AuditFilter) -> Result<Vec<AuditEvent>, AuditError>;
}

/// Remote ingestion seam for forwarding audit events to a control plane.
///
/// Deliberately minimal: batches of already-stored events are pushed
/// verbatim so remote consumers can re-verify the same hash chain.
#[allow(clippy::module_name_repetitions)]
pub trait RemoteIngest: Send + Sync {
    /// Pushes a batch of events to the remote sink.
    ///
    /// # Errors
    /// Implementation-defined; the placeholder never fails.
    fn ingest_batch(&self, events: Vec<AuditEvent>) -> Result<(), AuditError>;
}

/// Placeholder [`RemoteIngest`] that discards batches.
///
/// Control-plane integration lands later; wiring code can depend on the
/// trait today and swap in a real implementation without call-site churn.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopRemoteIngest;

impl RemoteIngest for NoopRemoteIngest {
    fn ingest_batch(&self, _events: Vec<AuditEvent>) -> Result<(), AuditError> {
        Ok(())
    }
}
