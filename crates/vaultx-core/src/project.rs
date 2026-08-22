//! [`ProjectContext`]: an opened vaultx project binding the on-disk
//! repository layout to the application services.
//!
//! A project root looks like:
//!
//! ```text
//! <root>/.vaultx/                  repository metadata (see vaultx-repository)
//! <root>/.vaultx/audit/            local append-only audit log directory
//! <root>/.vaultx/policies/         human-editable policy YAML documents
//! <root>/.vaultx/agents/<name>.json  agent identity files
//! ```

use std::path::{Path, PathBuf};

use vaultx_repository::RepoError;

use crate::error::{CoreError, CoreResult};

/// Directory holding policy YAML documents.
pub(crate) const POLICIES_DIR_NAME: &str = "policies";
/// Directory holding the local audit log.
pub(crate) const AUDIT_DIR_NAME: &str = "audit";
/// File name of the local JSONL audit store inside the audit directory.
pub(crate) const AUDIT_STORE_FILE: &str = "events.jsonl";

/// An opened vaultx project: the working-directory anchor every service
/// operates against.
///
/// The context owns the [`Repository`] facade and exposes the derived
/// paths (`policies_dir`, audit store). Services are constructed against
/// `&ProjectContext`; see [`crate::VaultxServices`] for the facade.
#[derive(Debug)]
pub struct ProjectContext {
    root: PathBuf,
    repository: vaultx_repository::Repository,
    /// Lazily-initialized per-process signing identity; see
    /// [`crate::history`] for the dev-mode key-management contract.
    pub(crate) device_pair_slot:
        std::sync::Mutex<Option<std::sync::Arc<vaultx_crypto::signature::SigningKeyPair>>>,
}

impl ProjectContext {
    /// Initializes a fresh project at `root`, creating the `.vaultx`
    /// repository layout plus the `policies` and `audit` directories.
    ///
    /// # Errors
    /// * [`CoreError::AlreadyInitialized`] when `root` already holds a
    ///   project.
    /// * Propagates filesystem failures from layout creation.
    pub fn init(root: &Path) -> CoreResult<ProjectContext> {
        let repository = match vaultx_repository::Repository::init(root) {
            Ok(repository) => repository,
            Err(RepoError::RefAlreadyExists(_)) => {
                return Err(CoreError::AlreadyInitialized(root.to_path_buf()));
            }
            Err(err) => return Err(err.into()),
        };
        let ctx = Self {
            root: root.to_path_buf(),
            repository,
            device_pair_slot: std::sync::Mutex::new(None),
        };
        ctx.ensure_service_dirs()?;
        Ok(ctx)
    }

    /// Opens an existing project at `root`.
    ///
    /// # Errors
    /// * [`CoreError::NotARepository`] when the directory does not hold an
    ///   initialized repository (missing `.vaultx/HEAD`).
    /// * Propagates ref-store corruption and filesystem failures.
    pub fn open(root: &Path) -> CoreResult<ProjectContext> {
        let repository = match vaultx_repository::Repository::open(root) {
            Ok(repository) => repository,
            Err(RepoError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => {
                return Err(CoreError::NotARepository(root.to_path_buf()));
            }
            Err(err) => return Err(err.into()),
        };
        let ctx = Self {
            root: root.to_path_buf(),
            repository,
            device_pair_slot: std::sync::Mutex::new(None),
        };
        // Self-healing for projects created before the service directories
        // existed; missing directories are recreated rather than fatal.
        ctx.ensure_service_dirs()?;
        Ok(ctx)
    }

    fn ensure_service_dirs(&self) -> CoreResult<()> {
        std::fs::create_dir_all(self.vault_dir().join(POLICIES_DIR_NAME))?;
        std::fs::create_dir_all(self.vault_dir().join(AUDIT_DIR_NAME))?;
        Ok(())
    }

    /// The project root directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The `.vaultx` metadata directory.
    #[must_use]
    pub fn vault_dir(&self) -> &Path {
        self.repository.vault_dir()
    }

    /// Read-only handle to the underlying repository facade.
    #[must_use]
    pub const fn repository(&self) -> &vaultx_repository::Repository {
        &self.repository
    }

    /// Directory holding human-editable policy YAML documents:
    /// `<root>/.vaultx/policies`.
    #[must_use]
    pub fn policies_dir(&self) -> PathBuf {
        self.vault_dir().join(POLICIES_DIR_NAME)
    }

    /// Path of the local append-only JSONL audit store:
    /// `<root>/.vaultx/audit/events.jsonl`. The backing file is created by
    /// the first appended event; the parent directory always exists after
    /// [`ProjectContext::init`] / [`ProjectContext::open`].
    #[must_use]
    pub fn audit_path(&self) -> PathBuf {
        self.vault_dir().join(AUDIT_DIR_NAME).join(AUDIT_STORE_FILE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_open_round_trip_and_error_paths() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        let ctx = ProjectContext::init(root).expect("init succeeds");
        assert_eq!(ctx.root(), root);
        assert!(ctx.policies_dir().is_dir());
        assert!(ctx.audit_path().parent().expect("audit dir").is_dir());

        let reopened = ProjectContext::open(root).expect("reopen succeeds");
        assert_eq!(reopened.root(), ctx.root());
        assert_eq!(
            reopened.audit_path(),
            root.join(".vaultx").join("audit").join("events.jsonl")
        );

        assert!(matches!(
            ProjectContext::init(root),
            Err(CoreError::AlreadyInitialized(path)) if path == root
        ));

        let empty = tempfile::tempdir().unwrap();
        assert!(matches!(
            ProjectContext::open(empty.path()),
            Err(CoreError::NotARepository(path)) if path == empty.path()
        ));
    }

    #[test]
    fn open_self_heals_missing_service_directories() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        ProjectContext::init(root).unwrap();

        // Simulate a legacy layout lacking the service directories.
        std::fs::remove_dir_all(root.join(".vaultx").join("policies")).unwrap();
        std::fs::remove_dir_all(root.join(".vaultx").join("audit")).unwrap();

        let ctx = ProjectContext::open(root).expect("open heals");
        assert!(ctx.policies_dir().is_dir());
        assert!(ctx.audit_path().parent().expect("audit dir").is_dir());
    }
}
