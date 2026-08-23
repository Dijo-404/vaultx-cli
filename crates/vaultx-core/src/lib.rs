//! Application services shared by the vaultx CLI and TUI (plan §5).
//!
//! This crate wires the repository, crypto, policy, and audit layers into
//! coherent service objects with a clean API surface:
//!
//! - `error`: [`CoreError`], the single error type every service
//!   returns (via [`CoreResult`]).
//! - `project`: [`ProjectContext`] — init/open a project and reach its
//!   paths and underlying [`Repository`](vaultx_repository::Repository).
//! - `config`: set/get/unset/list non-secret config values plus the
//!   conservative `.env` import classifier.
//! - `staging`: idempotent add/confirm, restore, and status reporting.
//! - `history`: commits, log/show, staged and commit diffs, branch
//!   operations, head-signature verification.
//! - `envs`: environment creation, protection, promotion (with local
//!   audit events), and listing.
//! - `agents`: agent identity files — create, enable/disable, policy
//!   attachment, inspection.
//! - `policies`: YAML persistence, engine building, per-file validation,
//!   dry-run authorization checks.
//! - `secrets`: encrypted secret-value storage under the
//!   `root → project → DEK` envelope hierarchy, kept outside the
//!   content-addressed object store (see the module docs for the
//!   invariant list).
//! - `services`: [`VaultxServices`], the facade CLI/TUI construct.
//!
//! # Synchronous v1 (async deferred)
//!
//! All services are **synchronous**. The plan's `VaultService` async
//! trait surface is intentionally not defined here: it arrives together
//! with the IPC/server tasks as a thin tokio wrapper over these same
//! structs. Signatures map 1:1; no service logic will move.
//!
//! # Deferred: broker wiring
//!
//! Agent identities and policy engines are managed locally here, but
//! nothing dispatches to the broker: session issuance, token minting, and
//! engine binding are part of the IPC/server tasks.
//!
//! # Deferred: sync
//!
//! Remote sync (`vaultx-sync-client` / control plane) has no integration
//! point yet; history and refs remain purely local.

mod agents;
mod config;
mod doctor;
mod envs;
mod error;
mod history;
mod policies;
mod project;
mod secrets;
mod services;
mod staging;

pub use agents::{AgentIdentityFile, AgentLifecycleService, AgentSummary};
pub use config::{ConfigService, ImportReport};
pub use doctor::{render_checks, CheckOutcome, CheckStatus, DoctorService};
pub use envs::{EnvironmentService, EnvironmentSummary};
pub use error::{CoreError, CoreResult};
pub use history::{
    CommitDetail, CommitSummary, ConfigValueConflict, EntrySummary, HistoryService,
    MergeConflictSet, MergeOutcome, RollbackReport, SecretRevisionConflict,
};
pub use policies::PolicyOpsService;
pub use project::ProjectContext;
pub use secrets::{
    BrokeredBinding, EncryptedSecretRevision, SecretListEntry, SecretMetadata, SecretRevisionAad,
    SecretRevisionInfo, SecretRevisionState, SecretService,
};
pub use services::{version, VaultxServices};
pub use staging::{StagedChangeKind, StagingService, StatusReport};

/// Re-exported so consumers can name diff entries without depending on
/// `vaultx-repository` directly.
pub use vaultx_repository::DiffEntry;

/// Re-exported so CLI/TUI surfaces can pass merge strategies without
/// depending on `vaultx-repository` directly.
pub use vaultx_repository::MergeStrategy;

/// Re-exported so CLI/TUI surfaces handle secret values without depending
/// on `vaultx-crypto` directly.
pub use vaultx_crypto::secret::SecretString;

#[cfg(test)]
mod tests {
    #[test]
    fn public_api_surface_smoke() {
        // The facade plus one representative type from each module stay
        // importable as documented.
        assert!(!crate::version().is_empty());

        let dir = tempfile::tempdir().unwrap();
        let services = crate::VaultxServices::init(dir.path()).unwrap();
        services.config().set_config("SMOKE_VAR", "ok").unwrap();
        assert_eq!(services.config().get_config("SMOKE_VAR").unwrap(), "ok");
    }
}
