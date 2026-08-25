//! Workspace auth, object exchange, ref synchronization, signature
//! verification, conflict detection (plan §28/§29/§45).
//!
//! The client speaks the control-plane sync protocol over a pluggable
//! [`transport::ControlPlaneTransport`] and enforces every integrity rule
//! independently: returned objects are re-canonicalized, hashed, and only
//! then applied to the local repository; refs reconcile strictly by
//! ancestry (fast-forward or explicit conflict — never an automatic pick);
//! protected environment refs refuse updates without explicit
//! authorization.
//!
//! # Device identity
//!
//! Ed25519 device keys reuse [`vaultx_crypto::signature::SigningKeyPair`]
//! and persist their 32-byte seed through the
//! [`vaultx_keyring::WrappingKeyProvider`] seam so production backends swap
//! in behind identical signatures while tests inject memory stores.
//!
//! # Async traits
//!
//! The workspace has no existing `async_trait` usage; both traits here use
//! native `async fn` (stable since 1.75) to keep dependencies minimal.

pub mod client;
pub mod device;
pub mod error;
pub mod local;
pub mod transport;

use vaultx_types::CommitId;
use vaultx_types::ProjectId;

pub use client::{ControlPlaneSyncClient, SyncOptions};
pub use device::DeviceKeySource;
pub use error::SyncError;
pub use local::{FsWorkspace, LocalWorkspace, RefApplyOutcome};
pub use transport::{ControlPlaneTransport, TransportRequest, TransportResponse};

/// Which ref namespace a synchronized ref belongs to. Re-exported from the
/// control-plane protocol so both wire ends share one type.
pub use vaultx_control_plane::protocol::RefNamespace;

/// Outcome of one completed push or pull (plan §45).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncResult {
    /// Objects newly stored on the remote during this operation.
    pub uploaded: usize,
    /// Objects newly stored locally after independent hash verification.
    pub downloaded: usize,
    /// Ref disagreements surfaced for explicit merge/reconciliation; sync
    /// never silently chooses between competing revisions.
    pub conflicts: Vec<RefConflict>,
}

impl SyncResult {
    /// A clean result with no transfers and no conflicts.
    #[must_use]
    pub fn clean() -> Self {
        Self {
            uploaded: 0,
            downloaded: 0,
            conflicts: Vec::new(),
        }
    }

    /// True when every ref reconciled without disagreement.
    #[must_use]
    pub fn is_converged(&self) -> bool {
        self.conflicts.is_empty()
    }
}

/// Why a ref could not be reconciled automatically.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConflictReason {
    /// Both sides advanced from a common ancestor; an explicit merge is
    /// required.
    Diverged,
    /// A protected environment ref rejected the update because the client
    /// did not assert authorization.
    ProtectedEnvironment,
    /// The remote refused the update outright with this HTTP status.
    Rejected {
        /// HTTP status returned by the control plane.
        status: u16,
    },
    /// The remote ref points at history the local repository cannot
    /// resolve even after downloading everything offered, so ancestry —
    /// and therefore safety — cannot be established.
    UnverifiableHistory,
}

impl std::fmt::Display for ConflictReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Diverged => f.write_str("diverged"),
            Self::ProtectedEnvironment => f.write_str("protected environment ref"),
            Self::Rejected { status } => write!(f, "rejected with status {status}"),
            Self::UnverifiableHistory => f.write_str("unverifiable local history"),
        }
    }
}

/// A ref disagreement that requires explicit merge/reconciliation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefConflict {
    /// Namespace of the disputed ref.
    pub namespace: RefNamespace,
    /// Name of the disputed ref.
    pub name: String,
    /// Commit currently recorded locally (`None` when absent).
    pub local_commit: Option<CommitId>,
    /// Commit currently recorded remotely (`None` when absent).
    pub remote_commit: Option<CommitId>,
    /// Why automatic reconciliation was refused.
    pub reason: ConflictReason,
}

/// Synchronization service contract (plan §45). Native async-fn trait:
/// object-safe dyn dispatch is intentionally not part of the contract.
pub trait SyncService {
    /// Uploads objects and refs the remote lacks under the same
    /// verification and protection rules as pull.
    ///
    /// # Errors
    /// [`SyncError`] for transport, protocol, verification, or storage
    /// failures; ref-level disagreements are reported inside
    /// [`SyncResult::conflicts`] instead of failing the call.
    fn push(
        &self,
        project: ProjectId,
    ) -> impl std::future::Future<Output = Result<SyncResult, SyncError>> + Send;

    /// Downloads missing objects after independent content-hash
    /// verification and reconciles remote refs by ancestry.
    ///
    /// # Errors
    /// [`SyncError`] for transport, protocol, verification, or storage
    /// failures; ref-level disagreements are reported inside
    /// [`SyncResult::conflicts`] instead of failing the call.
    fn pull(
        &self,
        project: ProjectId,
    ) -> impl std::future::Future<Output = Result<SyncResult, SyncError>> + Send;
}
