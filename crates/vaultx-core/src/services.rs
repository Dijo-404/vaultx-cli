//! [`VaultxServices`]: the single entry point CLI and TUI construct
//! services through.
//!
//! Services are lazily-constructed thin views over the shared
//! [`ProjectContext`] — plain constructors, no DI framework. Each returns
//! a borrow-bound struct, so calls stay cheap and cannot outlive the
//! facade.
//!
//! # Sync v1
//!
//! Everything here is **synchronous**: the repository, crypto, policy, and
//! audit layers beneath are sync, and local file operations do not justify
//! an async runtime yet. The plan's `async trait VaultService` surface is
//! deliberately deferred — it arrives together with the IPC/server tasks,
//! which will wrap these same services behind tokio (the wrappers will be
//! thin; signatures map 1:1).

use std::path::Path;

use crate::agents::AgentLifecycleService;
use crate::config::ConfigService;
use crate::envs::EnvironmentService;
use crate::error::CoreResult;
use crate::history::HistoryService;
use crate::policies::PolicyOpsService;
use crate::project::ProjectContext;
use crate::staging::StagingService;

/// Semantic version of the vaultx-core crate.
///
/// Exposed for CLI/TUI banners and diagnostics without reaching into
/// build metadata themselves.
#[must_use]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Facade over one opened project exposing every application service.
#[derive(Debug)]
pub struct VaultxServices {
    ctx: ProjectContext,
}

impl VaultxServices {
    /// Initializes a fresh project and wraps it (see
    /// [`ProjectContext::init`]).
    ///
    /// # Errors
    /// * See [`ProjectContext::init`].
    pub fn init(root: &Path) -> CoreResult<Self> {
        Ok(Self {
            ctx: ProjectContext::init(root)?,
        })
    }

    /// Opens an existing project and wraps it (see
    /// [`ProjectContext::open`]).
    ///
    /// # Errors
    /// * See [`ProjectContext::open`].
    pub fn open(root: &Path) -> CoreResult<Self> {
        Ok(Self {
            ctx: ProjectContext::open(root)?,
        })
    }

    /// Wraps an already-constructed context.
    #[must_use]
    pub const fn new(ctx: ProjectContext) -> Self {
        Self { ctx }
    }

    /// The underlying project context.
    #[must_use]
    pub const fn context(&self) -> &ProjectContext {
        &self.ctx
    }

    /// Consumes the facade, returning the owned context.
    #[must_use]
    pub fn into_context(self) -> ProjectContext {
        self.ctx
    }

    /// Configuration operations.
    #[must_use]
    pub const fn config(&self) -> ConfigService<'_> {
        ConfigService::new(&self.ctx)
    }

    /// Staging operations.
    #[must_use]
    pub const fn staging(&self) -> StagingService<'_> {
        StagingService::new(&self.ctx)
    }

    /// History operations.
    #[must_use]
    pub const fn history(&self) -> HistoryService<'_> {
        HistoryService::new(&self.ctx)
    }

    /// Environment operations.
    #[must_use]
    pub const fn environments(&self) -> EnvironmentService<'_> {
        EnvironmentService::new(&self.ctx)
    }

    /// Agent lifecycle operations.
    #[must_use]
    pub const fn agents(&self) -> AgentLifecycleService<'_> {
        AgentLifecycleService::new(&self.ctx)
    }

    /// Policy operations.
    #[must_use]
    pub const fn policies(&self) -> PolicyOpsService<'_> {
        PolicyOpsService::new(&self.ctx)
    }

    /// Encrypted secret-value operations.
    #[must_use]
    pub fn secrets(&self) -> crate::secrets::SecretService<'_> {
        crate::secrets::SecretService::new(&self.ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_the_crate_version() {
        assert_eq!(version(), env!("CARGO_PKG_VERSION"));
        assert!(!version().is_empty());
    }

    #[test]
    fn facade_constructs_every_service_and_round_trips_init_open() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        let services = VaultxServices::init(root).expect("init");
        // Every accessor must be callable against the same facade.
        let _ = services.config();
        let _ = services.staging();
        let _ = services.history();
        let _ = services.environments();
        let _ = services.agents();
        let _ = services.policies();
        let _ = services.secrets();
        assert_eq!(services.context().root(), root);
        drop(services);

        let reopened = VaultxServices::open(root).expect("reopen");
        assert_eq!(reopened.context().root(), root);

        assert!(VaultxServices::init(root).is_err());
        let empty = tempfile::tempdir().unwrap();
        assert!(VaultxServices::open(empty.path()).is_err());

        let ctx = reopened.into_context();
        assert_eq!(ctx.root(), root);
    }
}
