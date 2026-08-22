//! [`StagingService`]: the intent-to-change index surfaced for CLI/TUI
//! consumption.
//!
//! Because [`crate::config::ConfigService`] stages changes immediately,
//! `add` exists as the idempotent "promote / confirm" operation (the
//! `vaultx add <name>` surface): it succeeds when the name is staged or
//! bound at HEAD, and fails only when nothing is known about it.

use vaultx_repository::{StagedChange, StagingIndex};
use vaultx_types::{CommitId, VariableName};

use crate::error::{CoreError, CoreResult};
use crate::project::ProjectContext;

/// Display-oriented classification of one staged change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StagedChangeKind {
    /// The variable will be set/replaced.
    Set,
    /// The variable will be removed.
    Remove,
}

impl std::fmt::Display for StagedChangeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Set => "set",
            Self::Remove => "remove",
        })
    }
}

impl From<&StagedChange> for StagedChangeKind {
    fn from(change: &StagedChange) -> Self {
        match change {
            StagedChange::Set(_) => Self::Set,
            StagedChange::Remove => Self::Remove,
        }
    }
}

/// Snapshot of branch, head, and pending staged changes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusReport {
    /// Current branch name (`None` when HEAD is detached).
    pub branch: Option<String>,
    /// Resolved head commit (`None` before the first commit).
    pub head_commit: Option<CommitId>,
    /// Pending staged changes sorted by variable name.
    pub staged_changes: Vec<(VariableName, StagedChangeKind)>,
}

/// Staging operations: add / restore / status.
#[derive(Clone, Copy, Debug)]
pub struct StagingService<'a> {
    ctx: &'a ProjectContext,
}

impl<'a> StagingService<'a> {
    /// Builds a service operating on `ctx`.
    #[must_use]
    pub const fn new(ctx: &'a ProjectContext) -> Self {
        Self { ctx }
    }

    /// Idempotently confirms `name` is part of the next commit.
    ///
    /// Succeeds when the name already carries a staged intent **or** is
    /// bound in the working (HEAD) manifest; fails only when the name is
    /// entirely unknown. Since config operations stage directly, this is
    /// mostly a validation/confirmation step — matching the plan decision
    /// that the staging index *is* the add mechanism.
    ///
    /// # Errors
    /// * [`CoreError::InvalidVariableName`] on malformed names.
    /// * [`CoreError::VariableNotFound`] when neither the staging index nor
    ///   HEAD knows the name.
    pub fn add(&self, name: &str) -> CoreResult<()> {
        let parsed = VariableName::parse(name)
            .map_err(|_| CoreError::InvalidVariableName(name.to_owned()))?;
        let staged = StagingIndex::load(self.ctx.vault_dir())?;
        if staged.entries().contains_key(&parsed) {
            return Ok(());
        }
        if self
            .ctx
            .repository()
            .working_manifest()?
            .get(&parsed)
            .is_some()
        {
            return Ok(());
        }
        Err(CoreError::VariableNotFound(name.to_owned()))
    }

    /// Drops any staged intent for `name`; returns whether one existed.
    ///
    /// # Errors
    /// * [`CoreError::InvalidVariableName`] on malformed names.
    /// * Propagates staging persistence failures.
    pub fn restore(&self, name: &str) -> CoreResult<bool> {
        let parsed = VariableName::parse(name)
            .map_err(|_| CoreError::InvalidVariableName(name.to_owned()))?;
        Ok(self.ctx.repository().restore(&parsed)?)
    }

    /// Snapshot of branch/head plus pending changes.
    ///
    /// # Errors
    /// * Propagates ref/staging failures.
    pub fn status(&self) -> CoreResult<StatusReport> {
        let report = self.ctx.repository().status()?;
        Ok(StatusReport {
            branch: report.branch,
            head_commit: report.head,
            staged_changes: report
                .staged
                .into_iter()
                .map(|(name, change)| (name, StagedChangeKind::from(&change)))
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConfigService;

    #[test]
    fn add_restore_status_flow() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ProjectContext::init(dir.path()).unwrap();
        let staging = StagingService::new(&ctx);
        let config = ConfigService::new(&ctx);

        // Unknown names cannot be added.
        assert!(matches!(
            staging.add("DB_HOST"),
            Err(CoreError::VariableNotFound(_))
        ));

        config.set_config("DB_HOST", "v1").unwrap();
        // Already staged by set_config; add is an idempotent confirmation.
        staging.add("DB_HOST").unwrap();

        let status = staging.status().unwrap();
        assert_eq!(status.branch.as_deref(), Some("main"));
        assert_eq!(status.head_commit, None);
        assert_eq!(
            status.staged_changes,
            vec![(
                VariableName::parse("DB_HOST").unwrap(),
                StagedChangeKind::Set
            )]
        );

        assert!(staging.restore("DB_HOST").unwrap());
        assert!(!staging.restore("DB_HOST").unwrap());
        assert!(staging.status().unwrap().staged_changes.is_empty());

        // Bound-at-HEAD names confirm via add without staging anything.
        config.set_config("DB_HOST", "v2").unwrap();
        crate::history::HistoryService::new(&ctx)
            .commit("base", "user:t")
            .unwrap();
        staging.add("DB_HOST").unwrap();
        assert!(staging.status().unwrap().staged_changes.is_empty());

        // Malformed names fail loudly.
        assert!(matches!(
            staging.add("bad name"),
            Err(CoreError::InvalidVariableName(_))
        ));
        assert!(matches!(
            staging.restore("bad name"),
            Err(CoreError::InvalidVariableName(_))
        ));
    }
}
