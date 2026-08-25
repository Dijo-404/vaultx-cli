//! Branch and environment refs, plus the symbolic `HEAD`.
//!
//! Layout under the repository's `.vaultx` directory:
//!
//! ```text
//! .vaultx/HEAD                              -> "ref: heads/main" or "commit: cmt_..."
//! .vaultx/refs/heads/<name>                 -> commit id (one line)
//! .vaultx/refs/environments/<name>          -> commit id (one line)
//! .vaultx/refs/environments/<name>.protection -> {"protected":true|false}
//! ```
//!
//! Environment refs are not unrestricted branches: each carries protection
//! metadata in a sidecar file (v1: a single `protected` boolean). Moving or
//! deleting a protected ref requires an explicit force flag, so environment
//! state cannot silently weaken through ordinary ref writes.

use serde::{Deserialize, Serialize};
use vaultx_types::{BranchRef, CommitId};

use crate::error::RepoError;

/// Which ref namespace an operation targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RefNamespace {
    /// Regular branches (`refs/heads/<name>`).
    Heads,
    /// Deployable environments (`refs/environments/<name>`), protected by
    /// sidecar metadata.
    Environments,
}

impl RefNamespace {
    const fn dir_name(self) -> &'static str {
        match self {
            Self::Heads => "heads",
            Self::Environments => "environments",
        }
    }

    /// Human-readable label matching the on-disk layout
    /// (`heads` / `environments`).
    #[must_use]
    pub const fn label(self) -> &'static str {
        self.dir_name()
    }
}

/// What `HEAD` points at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeadTarget {
    /// Symbolic reference to a branch under `refs/heads/`.
    Branch {
        /// Branch name (validated like any other ref name).
        name: String,
    },
    /// Detached checkout pinned directly to a commit.
    Detached {
        /// The pinned commit.
        commit: CommitId,
    },
}

impl HeadTarget {
    fn encode(&self) -> String {
        match self {
            Self::Branch { name } => format!("ref: heads/{name}"),
            Self::Detached { commit } => format!("commit: {commit}"),
        }
    }

    fn decode(line: &str) -> Result<Self, RepoError> {
        if let Some(name) = line.strip_prefix("ref: heads/") {
            BranchRef::parse(name)?;
            return Ok(Self::Branch {
                name: name.to_owned(),
            });
        }
        if let Some(id) = line.strip_prefix("commit: ") {
            return Ok(Self::Detached {
                commit: CommitId::parse(id)?,
            });
        }
        Err(RepoError::InvalidRef(format!(
            "unrecognized HEAD content `{line}`"
        )))
    }
}

/// Protection metadata carried alongside every environment ref.
///
/// Stored as JSON in `<name>.protection`; missing sidecar means
/// unprotected (freshly created env refs default to unprotected until a
/// policy explicitly protects them).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentProtection {
    /// When true, the ref refuses non-forced moves and deletes.
    #[serde(default)]
    pub protected: bool,
}

/// Store for branches, environment refs, and the symbolic `HEAD` file.
#[derive(Clone, Debug)]
pub struct RefStore {
    vault_dir: std::path::PathBuf,
}

impl RefStore {
    /// Builds a ref store rooted at the repository's `.vaultx` directory;
    /// refs live under `<vault_dir>/refs`, HEAD at `<vault_dir>/HEAD`.
    #[must_use]
    pub fn new(vault_dir: impl Into<std::path::PathBuf>) -> Self {
        Self {
            vault_dir: vault_dir.into(),
        }
    }

    fn refs_dir(&self) -> std::path::PathBuf {
        self.vault_dir.join("refs")
    }

    fn namespace_dir(&self, namespace: RefNamespace) -> std::path::PathBuf {
        self.refs_dir().join(namespace.dir_name())
    }

    fn head_file(&self) -> std::path::PathBuf {
        self.vault_dir.join("HEAD")
    }

    fn ref_path(
        &self,
        namespace: RefNamespace,
        name: &str,
    ) -> Result<std::path::PathBuf, RepoError> {
        // Reuse BranchRef validation: rejects empty, traversal (".."),
        // double slashes, control characters, and over-long names.
        BranchRef::parse(name).map_err(|_| RepoError::InvalidRef(name.to_owned()))?;
        // Refs are filesystem entries too: whitespace and separators have
        // no business in a refname even where BranchRef tolerates them.
        if name
            .chars()
            .any(|c| c.is_whitespace() || c == '\\' || c == '\0')
        {
            return Err(RepoError::InvalidRef(name.to_owned()));
        }
        let path = self.namespace_dir(namespace).join(name);
        // Defense in depth: after join, the canonical prefix check catches
        // anything that would escape the refs directory.
        if !path.starts_with(self.vault_dir.join("refs")) {
            return Err(RepoError::InvalidRef(name.to_owned()));
        }
        Ok(path)
    }

    fn write_atomically(path: &std::path::Path, contents: &str) -> Result<(), RepoError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let temp_path = path.with_file_name(format!(
            ".tmp-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        {
            use std::io::Write;
            let mut file = std::fs::File::create(&temp_path)?;
            file.write_all(contents.as_bytes())?;
            // Durability matches the object store: bytes reach disk before
            // the rename publishes them.
            file.sync_all()?;
        }
        std::fs::rename(&temp_path, path)?;
        Ok(())
    }

    fn read_trimmed(path: &std::path::Path) -> Option<String> {
        std::fs::read_to_string(path)
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
    }

    /// Reads the commit a ref points at; `None` when the ref does not
    /// exist.
    ///
    /// # Errors
    /// [`RepoError::CorruptObject`]-style [`RepoError`] when the ref file
    /// holds something that is not a valid commit ID.
    pub fn read_ref(
        &self,
        namespace: RefNamespace,
        name: &str,
    ) -> Result<Option<CommitId>, RepoError> {
        let path = self.ref_path(namespace, name)?;
        Ok(match Self::read_trimmed(&path) {
            None => None,
            Some(content) => Some(CommitId::parse(&content)?),
        })
    }

    /// Creates or moves a **branch** ref (`heads/<name>`) to `commit`.
    ///
    /// Environment refs are deliberately rejected here: they carry
    /// protection metadata that only [`RefStore::write_env_ref`] enforces,
    /// so routing them through this generic API would bypass that check.
    ///
    /// # Errors
    /// * [`RepoError::InvalidRef`] for malformed names and for any attempt
    ///   to target the [`RefNamespace::Environments`] namespace.
    /// * [`RepoError::Io`] on filesystem failures.
    pub fn write_ref(
        &self,
        namespace: RefNamespace,
        name: &str,
        commit: &CommitId,
    ) -> Result<(), RepoError> {
        if namespace == RefNamespace::Environments {
            return Err(RepoError::InvalidRef(
                "environment refs must go through write_env_ref (protection-aware)".to_owned(),
            ));
        }
        self.write_ref_at(namespace, name, commit)
    }

    /// Raw, protection-agnostic ref write shared by [`RefStore::write_ref`]
    /// and [`RefStore::write_env_ref`] so both produce byte-identical files.
    fn write_ref_at(
        &self,
        namespace: RefNamespace,
        name: &str,
        commit: &CommitId,
    ) -> Result<(), RepoError> {
        let path = self.ref_path(namespace, name)?;
        Self::write_atomically(&path, &format!("{commit}\n"))
    }

    /// Raw ref removal shared by [`RefStore::delete_ref`] and
    /// [`RefStore::delete_env_ref`].
    fn remove_ref_file(&self, namespace: RefNamespace, name: &str) -> Result<(), RepoError> {
        let path = self.ref_path(namespace, name)?;
        if !path.exists() {
            return Err(RepoError::RefNotFound(format!(
                "{}/{name}",
                namespace.dir_name()
            )));
        }
        std::fs::remove_file(&path)?;
        Ok(())
    }

    /// Removes a branch ref.
    ///
    /// Deleting the branch `HEAD` currently symbolically references is
    /// refused unless `force` is set — otherwise a successful delete would
    /// leave HEAD dangling on a missing ref. Environment refs must be
    /// deleted via [`RefStore::delete_env_ref`].
    ///
    /// # Errors
    /// * [`RepoError::RefNotFound`] when the ref is absent.
    /// * [`RepoError::ProtectedRef`] when deleting the checked-out branch
    ///   without force.
    /// * [`RepoError::InvalidRef`] when targeting environment refs.
    pub fn delete_ref(
        &self,
        namespace: RefNamespace,
        name: &str,
        force: bool,
    ) -> Result<(), RepoError> {
        match namespace {
            RefNamespace::Environments => {
                return Err(RepoError::InvalidRef(
                    "environment refs must be deleted via delete_env_ref".to_owned(),
                ));
            }
            RefNamespace::Heads => {
                let checked_out = match self.read_head()? {
                    Some(HeadTarget::Branch { name: current }) => current == name,
                    _ => false,
                };
                if checked_out && !force {
                    return Err(RepoError::ProtectedRef(format!(
                        "branch heads/{name} is checked out by HEAD; pass force"
                    )));
                }
            }
        }
        self.remove_ref_file(namespace, name)
    }

    /// Lists all refs in a namespace as `(name, commit)` pairs sorted by
    /// name. Nested names (`feature/x`) are flattened with `/` separators;
    /// protection sidecars and temp files are excluded.
    ///
    /// # Errors
    /// Propagates I/O and parse failures.
    pub fn list_refs(&self, namespace: RefNamespace) -> Result<Vec<(String, CommitId)>, RepoError> {
        let mut refs = Vec::new();
        Self::collect_refs(&self.namespace_dir(namespace), "", &mut refs)?;
        refs.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(refs)
    }

    fn collect_refs(
        dir: &std::path::Path,
        prefix: &str,
        out: &mut Vec<(String, CommitId)>,
    ) -> Result<(), RepoError> {
        if !dir.exists() {
            return Ok(());
        }
        let mut entries: Vec<_> = std::fs::read_dir(dir)?.filter_map(|e| e.ok()).collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let raw_name = entry.file_name().to_string_lossy().into_owned();
            let path = entry.path();
            let full_name = if prefix.is_empty() {
                raw_name.clone()
            } else {
                format!("{prefix}/{raw_name}")
            };
            if raw_name.ends_with(".protection") || raw_name.starts_with(".tmp-") {
                continue;
            }
            if path.is_dir() {
                Self::collect_refs(&path, &full_name, out)?;
            } else if let Some(commit) = Self::read_trimmed(&path) {
                out.push((full_name, CommitId::parse(&commit)?));
            }
        }
        Ok(())
    }

    fn protection_path(&self, name: &str) -> Result<std::path::PathBuf, RepoError> {
        let base = self.ref_path(RefNamespace::Environments, name)?;
        let mut file_name = base
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| RepoError::InvalidRef(name.to_owned()))?
            .to_owned();
        file_name.push_str(".protection");
        Ok(base.with_file_name(file_name))
    }

    /// Reads an environment ref's protection metadata; defaults to
    /// unprotected when no sidecar exists yet.
    ///
    /// # Errors
    /// Propagates I/O / JSON failures.
    pub fn read_env_protection(&self, name: &str) -> Result<EnvironmentProtection, RepoError> {
        let path = self.protection_path(name)?;
        match Self::read_trimmed(&path) {
            None => Ok(EnvironmentProtection::default()),
            Some(content) => Ok(serde_json::from_str::<EnvironmentProtection>(&content)?),
        }
    }

    /// Persists an environment ref's protection metadata.
    ///
    /// # Errors
    /// Propagates I/O / JSON failures.
    pub fn write_env_protection(
        &self,
        name: &str,
        protection: &EnvironmentProtection,
    ) -> Result<(), RepoError> {
        let path = self.protection_path(name)?;
        Self::write_atomically(&path, &serde_json::to_string(protection)?)
    }

    /// Writes an environment ref, enforcing protection metadata: moving an
    /// existing *protected* ref to a different commit requires
    /// `force = true`.
    ///
    /// Writing the same commit again is always allowed (idempotent), as is
    /// creating a brand-new ref.
    ///
    /// # Errors
    /// [`RepoError::ProtectedRef`] when refusing a protected move without
    /// force.
    pub fn write_env_ref(
        &self,
        name: &str,
        commit: &CommitId,
        force: bool,
    ) -> Result<(), RepoError> {
        let current = self.read_ref(RefNamespace::Environments, name)?;
        if let Some(current_commit) = current {
            if current_commit != *commit && self.read_env_protection(name)?.protected && !force {
                return Err(RepoError::ProtectedRef(name.to_owned()));
            }
        }
        self.write_ref_at(RefNamespace::Environments, name, commit)
    }

    /// Deletes an environment ref, honoring protection unless forced.
    ///
    /// # Errors
    /// [`RepoError::ProtectedRef`] when protected and unforced;
    /// [`RepoError::RefNotFound`] when absent.
    pub fn delete_env_ref(&self, name: &str, force: bool) -> Result<(), RepoError> {
        if self.read_ref(RefNamespace::Environments, name)?.is_some()
            && self.read_env_protection(name)?.protected
            && !force
        {
            return Err(RepoError::ProtectedRef(name.to_owned()));
        }
        self.remove_ref_file(RefNamespace::Environments, name)?;
        // Best-effort cleanup of now-stale protection metadata.
        let _ = std::fs::remove_file(self.protection_path(name)?);
        Ok(())
    }

    /// Reads `HEAD`; `None` before the first init.
    ///
    /// # Errors
    /// [`RepoError::InvalidRef`] for unrecognized content.
    pub fn read_head(&self) -> Result<Option<HeadTarget>, RepoError> {
        match Self::read_trimmed(&self.head_file()) {
            None => Ok(None),
            Some(line) => HeadTarget::decode(&line).map(Some),
        }
    }

    /// Points `HEAD` at a new target.
    ///
    /// # Errors
    /// Propagates validation/I/O failures.
    pub fn write_head(&self, target: &HeadTarget) -> Result<(), RepoError> {
        Self::write_atomically(&self.head_file(), &format!("{}\n", target.encode()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_refs() -> (tempfile::TempDir, RefStore) {
        let dir = tempfile::tempdir().unwrap();
        let vault_dir = dir.path().to_path_buf();
        (dir, RefStore::new(vault_dir))
    }

    #[test]
    fn branch_refs_round_trip_and_list_sorted() {
        let (_guard, refs) = temp_refs();

        assert!(refs
            .read_ref(RefNamespace::Heads, "main")
            .unwrap()
            .is_none());

        let c1 = CommitId::parse("cmt_one").unwrap();
        let c2 = CommitId::parse("cmt_two").unwrap();
        refs.write_ref(RefNamespace::Heads, "feature/x", &c2)
            .unwrap();
        refs.write_ref(RefNamespace::Heads, "main", &c1).unwrap();

        assert_eq!(
            refs.read_ref(RefNamespace::Heads, "main").unwrap(),
            Some(c1)
        );
        assert_eq!(
            refs.read_ref(RefNamespace::Heads, "feature/x").unwrap(),
            Some(c2)
        );

        let listed = refs.list_refs(RefNamespace::Heads).unwrap();
        assert_eq!(
            listed.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
            vec!["feature/x", "main"],
            "listing must be sorted"
        );

        refs.delete_ref(RefNamespace::Heads, "feature/x", false)
            .unwrap();
        assert!(matches!(
            refs.delete_ref(RefNamespace::Heads, "feature/x", false),
            Err(RepoError::RefNotFound(_))
        ));
    }

    #[test]
    fn generic_ref_api_refuses_environment_namespace() {
        let (_guard, refs) = temp_refs();
        let c = CommitId::parse("cmt_guarded").unwrap();

        // Writing env refs through the generic API would bypass protection
        // metadata, so it is rejected outright...
        assert!(matches!(
            refs.write_ref(RefNamespace::Environments, "production", &c),
            Err(RepoError::InvalidRef(msg)) if msg.contains("write_env_ref"),
        ));
        assert!(refs
            .read_ref(RefNamespace::Environments, "production")
            .unwrap()
            .is_none());

        // ...and so is deleting through it.
        refs.write_env_ref("production", &c, false).unwrap();
        assert!(matches!(
            refs.delete_ref(RefNamespace::Environments, "production", false),
            Err(RepoError::InvalidRef(msg)) if msg.contains("delete_env_ref"),
        ));
        // The protection-aware path still works.
        refs.delete_env_ref("production", false).unwrap();
    }

    #[test]
    fn deleting_checked_out_branch_requires_force() {
        let (_guard, refs) = temp_refs();
        let c = CommitId::parse("cmt_on_main").unwrap();
        refs.write_ref(RefNamespace::Heads, "main", &c).unwrap();

        // HEAD points at main.
        refs.write_head(&HeadTarget::Branch {
            name: "main".to_owned(),
        })
        .unwrap();

        // Refusal without force; HEAD and the ref both remain intact.
        match refs.delete_ref(RefNamespace::Heads, "main", false) {
            Err(RepoError::ProtectedRef(msg)) => {
                assert!(msg.contains("checked out by HEAD"), "message was: {msg}");
            }
            other => panic!("expected protected-branch refusal, got {other:?}"),
        }
        assert_eq!(
            refs.read_ref(RefNamespace::Heads, "main").unwrap(),
            Some(c.clone())
        );
        assert_eq!(
            refs.read_head().unwrap(),
            Some(HeadTarget::Branch {
                name: "main".to_owned()
            })
        );

        // A non-checked-out branch deletes freely.
        refs.write_head(&HeadTarget::Branch {
            name: "other".to_owned(),
        })
        .unwrap();
        refs.delete_ref(RefNamespace::Heads, "main", false).unwrap();
        assert!(refs
            .read_ref(RefNamespace::Heads, "main")
            .unwrap()
            .is_none());

        // Force overrides the guard even when checked out.
        refs.write_head(&HeadTarget::Detached { commit: c })
            .unwrap();
        let c2 = CommitId::parse("cmt_detached_target").unwrap();
        refs.write_ref(RefNamespace::Heads, "pinned", &c2).unwrap();
        refs.write_head(&HeadTarget::Branch {
            name: "pinned".to_owned(),
        })
        .unwrap();
        refs.delete_ref(RefNamespace::Heads, "pinned", true)
            .unwrap();
        assert!(refs
            .read_ref(RefNamespace::Heads, "pinned")
            .unwrap()
            .is_none());
    }

    #[test]
    fn invalid_ref_names_are_rejected() {
        let (_guard, refs) = temp_refs();
        let c = CommitId::parse("cmt_ok").unwrap();
        for bad in ["../escape", "a//b", "", "/lead", "trail/", "has space"] {
            assert!(
                matches!(
                    refs.write_ref(RefNamespace::Heads, bad, &c),
                    Err(RepoError::InvalidRef(_)) | Err(RepoError::Io(_))
                ),
                "`{bad}` should be rejected"
            );
        }
        // Traversal specifically must never escape the refs dir.
        assert!(
            !refs
                .namespace_dir(RefNamespace::Heads)
                .join("../escape")
                .exists(),
            "traversal name must not have created a file"
        );
    }

    #[test]
    fn env_ref_defaults_unprotected_then_enforces_protection() {
        let (_guard, refs) = temp_refs();
        let c1 = CommitId::parse("cmt_dev_1").unwrap();
        let c2 = CommitId::parse("cmt_dev_2").unwrap();

        // Fresh env ref starts unprotected.
        assert_eq!(
            refs.read_env_protection("development").unwrap(),
            EnvironmentProtection { protected: false }
        );
        refs.write_env_ref("development", &c1, false).unwrap();

        // Unprotected: free to move.
        refs.write_env_ref("development", &c2, false).unwrap();
        assert_eq!(
            refs.read_ref(RefNamespace::Environments, "development")
                .unwrap(),
            Some(c2.clone())
        );

        // Protect it.
        refs.write_env_protection("development", &EnvironmentProtection { protected: true })
            .unwrap();

        // Same-commit rewrite stays legal even when protected.
        refs.write_env_ref("development", &c2, false).unwrap();

        // Move without force is refused...
        assert!(matches!(
            refs.write_env_ref("development", &c1, false),
            Err(RepoError::ProtectedRef(_))
        ));
        // ...but force overrides.
        refs.write_env_ref("development", &c1, true).unwrap();
        assert_eq!(
            refs.read_ref(RefNamespace::Environments, "development")
                .unwrap(),
            Some(c1)
        );

        // Delete honors protection too.
        refs.write_env_ref("development", &c2, true).unwrap();
        assert!(matches!(
            refs.delete_env_ref("development", false),
            Err(RepoError::ProtectedRef(_))
        ));
        refs.delete_env_ref("development", true).unwrap();
        assert!(refs
            .read_ref(RefNamespace::Environments, "development")
            .unwrap()
            .is_none());
        // Stale protection sidecar cleaned up.
        assert_eq!(
            refs.read_env_protection("development").unwrap(),
            EnvironmentProtection { protected: false }
        );
    }

    #[test]
    fn protection_sidecars_are_hidden_from_listings() {
        let (_guard, refs) = temp_refs();
        let c = CommitId::parse("cmt_prod").unwrap();
        refs.write_env_ref("production", &c, false).unwrap();
        refs.write_env_protection("production", &EnvironmentProtection { protected: true })
            .unwrap();

        let listed = refs.list_refs(RefNamespace::Environments).unwrap();
        assert_eq!(listed, vec![("production".to_owned(), c)]);
    }

    #[test]
    fn head_supports_symbolic_branches_and_detached_commits() {
        let (_guard, refs) = temp_refs();
        assert!(refs.read_head().unwrap().is_none());

        refs.write_head(&HeadTarget::Branch {
            name: "main".to_owned(),
        })
        .unwrap();
        assert_eq!(
            refs.read_head().unwrap(),
            Some(HeadTarget::Branch {
                name: "main".to_owned()
            })
        );
        // Raw file content follows git convention.
        let raw = std::fs::read_to_string(refs.head_file()).unwrap();
        assert_eq!(raw.trim(), "ref: heads/main");

        let detached = CommitId::parse("cmt_deadbeef01").unwrap();
        refs.write_head(&HeadTarget::Detached {
            commit: detached.clone(),
        })
        .unwrap();
        assert_eq!(
            refs.read_head().unwrap(),
            Some(HeadTarget::Detached { commit: detached })
        );

        // Garbage content is rejected rather than misinterpreted.
        std::fs::write(refs.head_file(), "something else\n").unwrap();
        assert!(matches!(refs.read_head(), Err(RepoError::InvalidRef(_))));
    }
}
