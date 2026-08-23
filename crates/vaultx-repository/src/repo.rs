//! The [`Repository`] facade binding object store, refs, staging, and
//! history into one coherent unit.
//!
//! Layout under the repository root:
//!
//! ```text
//! <root>/.vaultx/HEAD              symbolic/detached head pointer
//! <root>/.vaultx/index.json        staging index
//! <root>/.vaultx/objects/sha256/.. content-addressed objects
//! <root>/.vaultx/refs/heads/..     branch refs
//! <root>/.vaultx/refs/environments/.. env refs (+ .protection sidecars)
//! ```

use std::path::{Path, PathBuf};

use vaultx_crypto::signature::SigningKeyPair;
use vaultx_types::{CommitId, IdentityRef, ObjectId, VariableName};

use crate::commit::commit_envelope;
use crate::commit::Commit;
use crate::diff;
use crate::error::RepoError;
use crate::history::History;
use crate::manifest::Manifest;
use crate::merge;
use crate::object::{ObjectEnvelope, ObjectType};
use crate::refs::{HeadTarget, RefNamespace, RefStore};
use crate::staging::{StagedChange, StagingIndex};
use crate::store::FileSystemObjectStore;

/// Summary produced by [`Repository::status`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusReport {
    /// Current branch name (`None` when HEAD is detached).
    pub branch: Option<String>,
    /// Resolved head commit (`None` before the first commit).
    pub head: Option<CommitId>,
    /// Pending staged changes, sorted by variable name.
    pub staged: Vec<(VariableName, StagedChange)>,
}

/// A content-addressed variable repository rooted at a directory.
///
/// # Concurrency model (v1)
///
/// This repository assumes **single-process, single-writer access**: one
/// owner performs all mutations (`stage_change`, `create_commit`, branch
/// and environment ref writes) at any given time. There is no locking.
/// Two concurrent writers can both resolve the same head commit and race
/// on the final ref write — last write wins, and the loser's commit
/// becomes unreachable from the branch tip (its objects remain intact in
/// the content-addressed store). Concurrent **readers** alongside one
/// writer are safe: every file is published atomically and reads verify
/// integrity. Multi-writer support (ref locks, CAS ref updates) is future
/// work; do not run concurrent writers against the same `.vaultx`.
#[derive(Clone, Debug)]
pub struct Repository {
    root: PathBuf,
    vault_dir: PathBuf,
    store: FileSystemObjectStore,
    refs: RefStore,
}

impl Repository {
    /// Directory containing the `.vaultx` metadata.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The `.vaultx` directory itself.
    #[must_use]
    pub fn vault_dir(&self) -> &Path {
        &self.vault_dir
    }

    /// Read-only handle to the object store.
    #[must_use]
    pub fn objects(&self) -> &FileSystemObjectStore {
        &self.store
    }

    /// Read-only handle to the ref store.
    #[must_use]
    pub fn refs(&self) -> &RefStore {
        &self.refs
    }

    fn new(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref().to_path_buf();
        let vault_dir = root.join(".vaultx");
        Self {
            store: FileSystemObjectStore::new(vault_dir.join("objects")),
            refs: RefStore::new(&vault_dir),
            root,
            vault_dir,
        }
    }

    /// Initializes a fresh repository, pointing `HEAD` at a new
    /// `refs/heads/main`.
    ///
    /// # Errors
    /// * [`RepoError::RefAlreadyExists`] when the directory already holds
    ///   an initialized repository.
    /// * Propagates filesystem failures.
    pub fn init(root: impl AsRef<Path>) -> Result<Self, RepoError> {
        let repo = Self::new(root);
        let head_file = repo.vault_dir.join("HEAD");
        if head_file.exists() {
            return Err(RepoError::RefAlreadyExists(head_file.display().to_string()));
        }
        std::fs::create_dir_all(repo.store.root())?;
        repo.refs.write_head(&HeadTarget::Branch {
            name: "main".to_owned(),
        })?;
        Ok(repo)
    }

    /// Opens an existing repository, validating its structure.
    ///
    /// # Errors
    /// * [`RepoError::Io`] when `.vaultx` or `HEAD` are missing/corrupt.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, RepoError> {
        let repo = Self::new(root);
        let head_file = repo.vault_dir.join("HEAD");
        if !repo.vault_dir.is_dir() || !head_file.is_file() {
            return Err(RepoError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("not a vaultx repository: {} missing", head_file.display()),
            )));
        }
        repo.refs.read_head()?;
        Ok(repo)
    }

    /// Raw `HEAD` target.
    ///
    /// # Errors
    /// Propagates ref-store failures.
    pub fn head_target(&self) -> Result<Option<HeadTarget>, RepoError> {
        self.refs.read_head()
    }

    /// Commit currently checked out, if any.
    ///
    /// # Errors
    /// [`RepoError::RefNotFound`] when HEAD names a branch without a ref.
    pub fn current_head(&self) -> Result<Option<CommitId>, RepoError> {
        match self.refs.read_head()? {
            None => Ok(None),
            Some(HeadTarget::Detached { commit }) => Ok(Some(commit)),
            Some(HeadTarget::Branch { name }) => self.refs.read_ref(RefNamespace::Heads, &name),
        }
    }

    /// Loads the manifest captured by `id`.
    ///
    /// # Errors
    /// Missing commit/manifest objects, wrong types, decode failures.
    pub fn manifest_at(&self, id: &CommitId) -> Result<Manifest, RepoError> {
        let commit = History::new(&self.store).find_commit(id)?;
        self.load_manifest_object(&commit.manifest)
    }

    fn load_manifest_object(&self, object_id: &ObjectId) -> Result<Manifest, RepoError> {
        let envelope = self.store.get(object_id)?;
        if envelope.object_type != ObjectType::Manifest {
            return Err(RepoError::CorruptObject {
                id: object_id.clone(),
                reason: format!(
                    "expected a manifest object, found {:?}",
                    envelope.object_type
                ),
            });
        }
        envelope.decode_payload::<Manifest>()
    }

    /// Manifest of the current head (empty before the first commit).
    ///
    /// # Errors
    /// Propagates lookup failures.
    pub fn working_manifest(&self) -> Result<Manifest, RepoError> {
        match self.current_head()? {
            None => Ok(Manifest::default()),
            Some(head) => self.manifest_at(&head),
        }
    }

    /// Stages one intended change for the next commit.
    ///
    /// # Errors
    /// Propagates staging-index persistence failures.
    pub fn stage_change(&self, name: VariableName, change: StagedChange) -> Result<(), RepoError> {
        let mut index = StagingIndex::load(&self.vault_dir)?;
        index.stage(name, change);
        index.save(&self.vault_dir)
    }

    /// Convenience wrapper staging a `Set` intent.
    ///
    /// # Errors
    /// See [`Repository::stage_change`].
    pub fn add(
        &self,
        name: VariableName,
        entry: crate::manifest::ManifestEntry,
    ) -> Result<(), RepoError> {
        self.stage_change(name, StagedChange::Set(entry))
    }

    /// Drops any staged intent for `name` (git-style `restore`); returns
    /// whether an intent existed.
    ///
    /// # Errors
    /// Propagates staging-index persistence failures.
    pub fn restore(&self, name: &VariableName) -> Result<bool, RepoError> {
        let mut index = StagingIndex::load(&self.vault_dir)?;
        let removed = index.unstage(name);
        if removed {
            index.save(&self.vault_dir)?;
        }
        Ok(removed)
    }

    /// Clears every staged intent.
    ///
    /// # Errors
    /// Propagates staging-index persistence failures.
    pub fn clear_staging(&self) -> Result<(), RepoError> {
        let mut index = StagingIndex::load(&self.vault_dir)?;
        index.clear();
        index.save(&self.vault_dir)
    }

    /// Snapshot of branch/head plus pending changes.
    ///
    /// # Errors
    /// Propagates ref/staging failures.
    pub fn status(&self) -> Result<StatusReport, RepoError> {
        let branch = match self.refs.read_head()? {
            Some(HeadTarget::Branch { name }) => Some(name),
            _ => None,
        };
        Ok(StatusReport {
            branch,
            head: self.current_head()?,
            staged: StagingIndex::load(&self.vault_dir)?
                .list()
                .into_iter()
                .map(|(name, change)| (name.clone(), change.clone()))
                .collect(),
        })
    }

    /// Creates a signed commit from the staged index applied onto the head
    /// manifest, advancing the current branch (or detached HEAD).
    ///
    /// Parent existence is validated before anything is written; the
    /// staging index clears only after full success.
    ///
    /// # Errors
    /// * [`RepoError::StagingEmpty`] with nothing staged.
    /// * [`RepoError::ParentNotFound`] for dangling ancestry.
    /// * Propagates storage/ref failures.
    pub fn create_commit(
        &self,
        message: &str,
        author: IdentityRef,
        keypair: &SigningKeyPair,
    ) -> Result<CommitId, RepoError> {
        let index = StagingIndex::load(&self.vault_dir)?;
        if index.is_empty() {
            return Err(RepoError::StagingEmpty);
        }

        let head = self.current_head()?;
        let base = match &head {
            Some(id) => self.manifest_at(id)?,
            None => Manifest::default(),
        };
        let next_manifest = index.apply_onto(&base);
        let parents: Vec<CommitId> = head.iter().cloned().collect();
        let commit_id =
            self.store_signed_commit(&parents, &next_manifest, message, author, keypair)?;
        self.advance_head_to(&commit_id)?;

        self.clear_staging()?;
        Ok(commit_id)
    }

    /// Signs, stores, and returns a commit capturing `manifest` with the
    /// given parents — without touching any ref. Callers own ref updates.
    fn store_signed_commit(
        &self,
        parents: &[CommitId],
        manifest: &Manifest,
        message: &str,
        author: IdentityRef,
        keypair: &SigningKeyPair,
    ) -> Result<CommitId, RepoError> {
        History::new(&self.store).validate_parents(parents)?;

        let manifest_payload = serde_json::to_vec(manifest)?;
        let manifest_id = self
            .store
            .put(&ObjectEnvelope::new(ObjectType::Manifest, manifest_payload))?;

        let commit =
            Commit::new(parents.to_vec(), manifest_id, author, message).sign_with(keypair)?;
        let expected_oid = crate::commit::commit_object_id(&commit)?;
        let stored_oid = self.store.put(&commit_envelope(&commit)?)?;
        if stored_oid != expected_oid {
            return Err(RepoError::CorruptObject {
                id: stored_oid,
                reason: "commit storage id diverged from derived id".to_owned(),
            });
        }
        commit.commit_id()
    }

    /// Moves HEAD (and therefore its symbolic branch, if any) onto
    /// `commit_id`. Used by history-appending operations whose new tip is
    /// the caller's current position.
    fn advance_head_to(&self, commit_id: &CommitId) -> Result<(), RepoError> {
        match self.refs.read_head()? {
            Some(HeadTarget::Branch { name }) => {
                self.refs.write_ref(RefNamespace::Heads, &name, commit_id)
            }
            // Detached (or otherwise non-branch) heads advance to the new
            // commit directly.
            _ => self.refs.write_head(&HeadTarget::Detached {
                commit: commit_id.clone(),
            }),
        }
    }

    /// First-parent history from the current head (newest first).
    ///
    /// # Errors
    /// Propagates history-walk failures.
    pub fn log(&self, limit: usize) -> Result<Vec<(CommitId, Commit)>, RepoError> {
        match self.current_head()? {
            None => Ok(Vec::new()),
            Some(head) => History::new(&self.store).log(&head, limit),
        }
    }

    /// Loads a commit together with the manifest it captures.
    ///
    /// # Errors
    /// Propagates lookup/decode failures.
    pub fn show(&self, id: &CommitId) -> Result<(Commit, Manifest), RepoError> {
        let commit = History::new(&self.store).find_commit(id)?;
        let manifest = self.load_manifest_object(&commit.manifest)?;
        Ok((commit, manifest))
    }

    /// Creates a branch at `start` (defaulting to the current head).
    ///
    /// # Errors
    /// * [`RepoError::RefAlreadyExists`] when the branch exists.
    /// * [`RepoError::RefNotFound`] when no start point can be resolved.
    pub fn create_branch(&self, name: &str, start: Option<&CommitId>) -> Result<(), RepoError> {
        if self.refs.read_ref(RefNamespace::Heads, name)?.is_some() {
            return Err(RepoError::RefAlreadyExists(format!("heads/{name}")));
        }
        let start = match start {
            Some(id) => id.clone(),
            None => self
                .current_head()?
                .ok_or_else(|| RepoError::RefNotFound("heads/HEAD".to_owned()))?,
        };
        self.refs.write_ref(RefNamespace::Heads, name, &start)
    }

    /// All branch refs sorted by name.
    ///
    /// # Errors
    /// Propagates ref-store failures.
    pub fn list_branches(&self) -> Result<Vec<(String, CommitId)>, RepoError> {
        self.refs.list_refs(RefNamespace::Heads)
    }

    /// Checks out a branch by name; HEAD becomes symbolic again.
    ///
    /// # Errors
    /// [`RepoError::RefNotFound`] when the branch has no ref yet.
    pub fn checkout_branch(&self, name: &str) -> Result<(), RepoError> {
        if self.refs.read_ref(RefNamespace::Heads, name)?.is_none() {
            return Err(RepoError::RefNotFound(format!("heads/{name}")));
        }
        self.refs.write_head(&HeadTarget::Branch {
            name: name.to_owned(),
        })
    }

    /// Detaches HEAD onto an existing commit after verifying it loads.
    ///
    /// # Errors
    /// Propagates lookup failures.
    pub fn checkout_commit(&self, id: &CommitId) -> Result<(), RepoError> {
        History::new(&self.store).find_commit(id)?;
        self.refs
            .write_head(&HeadTarget::Detached { commit: id.clone() })
    }

    /// Finds a best-effort common ancestor of `a` and `b` by breadth-first
    /// search over the **full** parent graph (merge commits included).
    ///
    /// Returns the first commit reachable from `b` that is also an
    /// ancestor of (or equal to) `a`, which yields the closest shared
    /// ancestor along `b`'s ancestry — correct for ordinary branch
    /// topologies; criss-cross merges may pick any valid base. `None`
    /// when the two histories share no commits.
    ///
    /// # Error tolerance (asymmetric by design)
    ///
    /// The walk over `a`'s ancestry is **strict**: every visited commit
    /// must resolve in this store, and lookup/corruption failures
    /// propagate as [`RepoError`]. The walk from `b` is **tolerant**:
    /// commits that do not resolve here (disjoint roots, foreign stores)
    /// are treated as leaves, so "no common ancestor" stays representable
    /// as `Ok(None)` instead of surfacing as
    /// [`RepoError::ObjectNotFound`].
    ///
    /// # Errors
    /// Propagates lookup/decode failures for commits visited on the `a`
    /// side and for resolvable commits visited on the `b` side.
    pub fn merge_base(&self, a: &CommitId, b: &CommitId) -> Result<Option<CommitId>, RepoError> {
        let history = History::new(&self.store);
        let mut ancestors_of_a = std::collections::BTreeSet::new();
        let mut queue_a = std::collections::VecDeque::from([a.clone()]);
        while let Some(id) = queue_a.pop_front() {
            if !ancestors_of_a.insert(id.clone()) {
                continue;
            }
            for parent in history.find_commit(&id)?.parents {
                queue_a.push_back(parent);
            }
        }

        let mut seen_b = std::collections::BTreeSet::new();
        let mut queue_b = std::collections::VecDeque::from([b.clone()]);
        while let Some(id) = queue_b.pop_front() {
            if !seen_b.insert(id.clone()) {
                continue;
            }
            if ancestors_of_a.contains(&id) {
                return Ok(Some(id));
            }
            // Commits that do not resolve in this store (disjoint roots,
            // foreign stores) have no traversable ancestry here; treat
            // them as leaves so "no common ancestor" stays representable
            // instead of surfacing as ObjectNotFound.
            let parents = match history.find_commit(&id) {
                Ok(commit) => commit.parents,
                Err(_) => Vec::new(),
            };
            queue_b.extend(parents);
        }
        Ok(None)
    }

    /// Creates a signed two-parent merge commit on `target_branch`
    /// capturing an already-merged `manifest`.
    ///
    /// Parents are `[target_tip, theirs_tip]`; nothing here recomputes or
    /// validates the merge itself — callers must have resolved conflicts
    /// beforehand. The target branch ref advances; when HEAD symbolically
    /// points at the same branch its working state follows automatically.
    ///
    /// # Concurrency (TOCTOU)
    ///
    /// The target tip is read and the ref written without any
    /// compare-and-swap guard: this relies on the crate-wide
    /// single-process single-writer assumption. A concurrent writer
    /// advancing the same branch between the tip read above and the final
    /// ref write would have its tip silently overwritten (its commit
    /// objects remain intact in the content-addressed store).
    ///
    /// # Errors
    /// * [`RepoError::RefNotFound`] for unknown branches.
    /// * [`RepoError::ParentNotFound`] for dangling ancestry.
    /// * Propagates storage/ref failures.
    pub fn create_merge_commit(
        &self,
        message: &str,
        author: IdentityRef,
        keypair: &SigningKeyPair,
        target_branch: &str,
        theirs_tip: &CommitId,
        manifest: &Manifest,
    ) -> Result<CommitId, RepoError> {
        let ours_tip = self
            .refs
            .read_ref(RefNamespace::Heads, target_branch)?
            .ok_or_else(|| RepoError::RefNotFound(format!("heads/{target_branch}")))?;
        let parents = vec![ours_tip, theirs_tip.clone()];
        let commit_id = self.store_signed_commit(&parents, manifest, message, author, keypair)?;
        self.refs
            .write_ref(RefNamespace::Heads, target_branch, &commit_id)?;
        Ok(commit_id)
    }

    /// Creates a signed rollback commit whose manifest equals the one
    /// captured by `target`. Because manifests are content-addressed, the
    /// new commit references the *historical* manifest object id — no
    /// history is rewritten and old commits stay intact.
    ///
    /// Refuses while the staging index holds pending changes so staged
    /// intent cannot silently diverge from the restored state. HEAD (and
    /// its symbolic branch) advances onto the rollback commit.
    ///
    /// # Errors
    /// * [`RepoError::StagingNotEmpty`] with pending changes.
    /// * [`RepoError::RefNotFound`] before the first commit (no head).
    /// * Propagates lookup/storage/ref failures.
    pub fn create_rollback_commit(
        &self,
        message: &str,
        author: IdentityRef,
        keypair: &SigningKeyPair,
        target: &CommitId,
    ) -> Result<CommitId, RepoError> {
        let index = StagingIndex::load(&self.vault_dir)?;
        if !index.is_empty() {
            return Err(RepoError::StagingNotEmpty);
        }
        // Loading the historical manifest both validates the target and
        // provides the payload; storing it dedups onto the original object.
        let manifest = self.manifest_at(target)?;
        let head = self
            .current_head()?
            .ok_or_else(|| RepoError::RefNotFound("heads/HEAD".to_owned()))?;
        let commit_id = self.store_signed_commit(&[head], &manifest, message, author, keypair)?;
        self.advance_head_to(&commit_id)?;
        Ok(commit_id)
    }

    /// Merges `theirs` (a branch's tip) into the working state against
    /// `base`. With `base = None` an **empty** ancestor is assumed — a
    /// conservative v1 simplification; pass the common ancestor manifest
    /// for real three-way semantics once ancestry tracking lands.
    ///
    /// Conflicts never partially apply: either a fully merged manifest
    /// comes back or the conflict set does.
    ///
    /// # Errors
    /// [`RepoError::MergeConflict`] carrying all unresolved disagreements;
    /// [`RepoError::RefNotFound`] for unknown branches.
    pub fn merge(
        &self,
        theirs_branch: &str,
        base: Option<&Manifest>,
    ) -> Result<Manifest, RepoError> {
        let theirs_tip = self
            .refs
            .read_ref(RefNamespace::Heads, theirs_branch)?
            .ok_or_else(|| RepoError::RefNotFound(format!("heads/{theirs_branch}")))?;
        let ours = self.working_manifest()?;
        let theirs = self.manifest_at(&theirs_tip)?;
        let empty = Manifest::default();
        merge::three_way_merge(base.unwrap_or(&empty), &ours, &theirs)
            .map_err(RepoError::MergeConflict)
    }

    /// Metadata-only diff between two arbitrary manifests using this
    /// repository's diff classifier.
    #[must_use]
    pub fn diff_manifests(old: &Manifest, new: &Manifest) -> Vec<diff::DiffEntry> {
        diff::compute_diff(old, new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::ManifestEntry;
    use vaultx_crypto::signature::VerifyingPublicKey;
    use vaultx_types::{CredentialRef, SecretRevisionId};

    struct TestRepo {
        _guard: tempfile::TempDir,
        repo: Repository,
        pair: SigningKeyPair,
    }

    fn temp_repo() -> TestRepo {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        TestRepo {
            _guard: dir,
            repo: Repository::init(root).unwrap(),
            pair: SigningKeyPair::generate(),
        }
    }

    fn cfg_obj(value: &str) -> ManifestEntry {
        ManifestEntry::Config {
            object: ObjectId::parse(&format!("obj_{value}")).unwrap(),
        }
    }

    fn var(name: &str) -> VariableName {
        VariableName::parse(name).unwrap()
    }

    #[test]
    fn init_then_reinit_and_open_behave() {
        let dir = tempfile::tempdir().unwrap();
        Repository::init(dir.path()).expect("first init");
        assert!(matches!(
            Repository::init(dir.path()),
            Err(RepoError::RefAlreadyExists(_))
        ));
        Repository::open(dir.path()).expect("reopen works");

        let empty_dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            Repository::open(empty_dir.path()),
            Err(RepoError::Io(_))
        ));
    }

    #[test]
    fn full_lifecycle_stage_commit_log_checkout_old_state() {
        let fx = temp_repo();

        // Fresh repository: no head, no history.
        assert!(fx.repo.current_head().unwrap().is_none());
        assert!(fx.repo.log(10).unwrap().is_empty());
        assert!(fx.repo.working_manifest().unwrap().entries.is_empty());

        // Stage a config value and commit it.
        fx.repo.add(var("DB_HOST"), cfg_obj("host_v1")).unwrap();
        let status = fx.repo.status().unwrap();
        assert_eq!(status.branch.as_deref(), Some("main"));
        assert_eq!(status.staged.len(), 1);

        let c1 = fx
            .repo
            .create_commit(
                "add DB_HOST",
                IdentityRef::parse("user:alice").unwrap(),
                &fx.pair,
            )
            .unwrap();

        // Staging cleared, history shows exactly one commit.
        assert!(fx.repo.status().unwrap().staged.is_empty());
        let log = fx.repo.log(10).unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].0, c1);
        assert!(log[0]
            .1
            .verify(&VerifyingPublicKey::from_signing(&fx.pair))
            .is_ok());

        // Second commit adds a brokered entry on top.
        fx.repo
            .add(
                var("API_TOKEN"),
                ManifestEntry::Brokered {
                    credential: CredentialRef::parse("github-token").unwrap(),
                    revision: SecretRevisionId::parse("sec_rev_2").unwrap(),
                },
            )
            .unwrap();
        let c2 = fx
            .repo
            .create_commit(
                "bind API_TOKEN",
                IdentityRef::parse("user:alice").unwrap(),
                &fx.pair,
            )
            .unwrap();
        assert_ne!(c1, c2);
        let log = fx.repo.log(10).unwrap();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].0, c2);
        assert_eq!(log[0].1.parents, vec![c1.clone()]);
        assert_eq!(log[1].0, c1);
        assert!(log[1].1.parents.is_empty());

        // Checkout the OLD commit: its manifest must load unchanged.
        fx.repo.checkout_commit(&c1).unwrap();
        assert_eq!(fx.repo.current_head().unwrap(), Some(c1.clone()));
        let manifest = fx.repo.working_manifest().unwrap();
        assert_eq!(manifest.get(&var("DB_HOST")), Some(&cfg_obj("host_v1")));
        assert!(manifest.get(&var("API_TOKEN")).is_none());

        // Show reproduces both halves for each commit.
        let (_, m1) = fx.repo.show(&c1).unwrap();
        assert_eq!(m1.entries.len(), 1);
        let (_, m2) = fx.repo.show(&c2).unwrap();
        assert_eq!(m2.entries.len(), 2);

        // Back onto the branch tip.
        fx.repo.checkout_branch("main").unwrap();
        assert_eq!(fx.repo.working_manifest().unwrap().entries.len(), 2);
    }

    #[test]
    fn commits_require_staged_changes_and_existing_parents() {
        let fx = temp_repo();
        assert!(matches!(
            fx.repo
                .create_commit("nothing", IdentityRef::parse("u:x").unwrap(), &fx.pair),
            Err(RepoError::StagingEmpty)
        ));
    }

    #[test]
    fn restore_drops_pending_intent_before_commit() {
        let fx = temp_repo();
        fx.repo.add(var("TEMP"), cfg_obj("temp_v1")).unwrap();
        assert!(fx.repo.restore(&var("TEMP")).unwrap());
        assert!(!fx.repo.restore(&var("TEMP")).unwrap());
        assert!(matches!(
            fx.repo
                .create_commit("empty", IdentityRef::parse("u:x").unwrap(), &fx.pair),
            Err(RepoError::StagingEmpty)
        ));
    }

    #[test]
    fn branch_operations_isolate_history() {
        let fx = temp_repo();
        fx.repo.add(var("BASE"), cfg_obj("base_v1")).unwrap();
        fx.repo
            .create_commit("base", IdentityRef::parse("user:a").unwrap(), &fx.pair)
            .unwrap();

        fx.repo.create_branch("feature/x", None).unwrap();
        assert!(matches!(
            fx.repo.create_branch("feature/x", None),
            Err(RepoError::RefAlreadyExists(_))
        ));

        fx.repo.checkout_branch("feature/x").unwrap();
        fx.repo.add(var("FEATURE"), cfg_obj("feat_v1")).unwrap();
        let feature_tip = fx
            .repo
            .create_commit(
                "feature work",
                IdentityRef::parse("user:a").unwrap(),
                &fx.pair,
            )
            .unwrap();

        // main untouched by feature commits.
        fx.repo.checkout_branch("main").unwrap();
        let main_manifest = fx.repo.working_manifest().unwrap();
        assert!(main_manifest.get(&var("FEATURE")).is_none());
        assert_eq!(main_manifest.get(&var("BASE")), Some(&cfg_obj("base_v1")));

        let branches = fx.repo.list_branches().unwrap();
        assert_eq!(
            branches.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
            vec!["feature/x", "main"]
        );
        assert_eq!(
            branches
                .iter()
                .find(|(n, _)| n == "feature/x")
                .map(|(_, c)| c.clone()),
            Some(feature_tip)
        );
    }

    #[test]
    fn checkout_unknown_things_fail_loudly() {
        let fx = temp_repo();
        assert!(matches!(
            fx.repo.checkout_branch("ghost"),
            Err(RepoError::RefNotFound(_))
        ));
        let ghost =
            CommitId::parse("cmt_ghost00000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        assert!(matches!(
            fx.repo.checkout_commit(&ghost),
            Err(RepoError::ObjectNotFound(_))
        ));
    }

    #[test]
    fn staging_persists_across_repository_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let pair = SigningKeyPair::generate();
        let repo = Repository::init(dir.path()).unwrap();
        repo.add(var("PERSISTED"), cfg_obj("persist_v1")).unwrap();

        drop(repo);
        let reopened = Repository::open(dir.path()).unwrap();
        let status = reopened.status().unwrap();
        assert_eq!(status.staged.len(), 1);
        assert_eq!(status.staged[0].0, var("PERSISTED"));

        reopened
            .create_commit("after reopen", IdentityRef::parse("user:r").unwrap(), &pair)
            .unwrap();
        assert_eq!(
            reopened.working_manifest().unwrap().get(&var("PERSISTED")),
            Some(&cfg_obj("persist_v1"))
        );
    }

    #[test]
    fn merge_clean_and_conflicting_paths() {
        let fx = temp_repo();
        fx.repo.add(var("SHARED"), cfg_obj("shared_v1")).unwrap();
        fx.repo
            .create_commit("base", IdentityRef::parse("user:m").unwrap(), &fx.pair)
            .unwrap();
        fx.repo.create_branch("side", None).unwrap();

        // Advance main with OURS-style change.
        fx.repo
            .add(var("MAIN_ONLY"), cfg_obj("main_only_v1"))
            .unwrap();
        fx.repo
            .create_commit(
                "main advance",
                IdentityRef::parse("user:m").unwrap(),
                &fx.pair,
            )
            .unwrap();

        // Advance side with a non-overlapping change.
        fx.repo.checkout_branch("side").unwrap();
        fx.repo
            .add(var("SIDE_ONLY"), cfg_obj("side_only_v1"))
            .unwrap();
        fx.repo
            .create_commit(
                "side advance",
                IdentityRef::parse("user:s").unwrap(),
                &fx.pair,
            )
            .unwrap();

        // Merge side INTO main: non-overlapping additions merge cleanly.
        fx.repo.checkout_branch("main").unwrap();
        let merged = fx.repo.merge("side", None).expect("clean merge");
        assert_eq!(merged.entries.len(), 3);
        assert!(merged.get(&var("SIDE_ONLY")).is_some());
        assert!(merged.get(&var("MAIN_ONLY")).is_some());

        // Now manufacture a conflicting secret on both branches and merge.
        fx.repo
            .add(
                var("CONFLICT_SECRET"),
                ManifestEntry::Secret {
                    revision: SecretRevisionId::parse("sec_rev_main").unwrap(),
                },
            )
            .unwrap();
        fx.repo
            .create_commit(
                "main secret",
                IdentityRef::parse("user:m").unwrap(),
                &fx.pair,
            )
            .unwrap();

        fx.repo.checkout_branch("side").unwrap();
        fx.repo
            .add(
                var("CONFLICT_SECRET"),
                ManifestEntry::Secret {
                    revision: SecretRevisionId::parse("sec_rev_side").unwrap(),
                },
            )
            .unwrap();
        fx.repo
            .create_commit(
                "side secret",
                IdentityRef::parse("user:s").unwrap(),
                &fx.pair,
            )
            .unwrap();

        fx.repo.checkout_branch("main").unwrap();
        match fx.repo.merge("side", None) {
            Err(RepoError::MergeConflict(conflicts)) => {
                assert_eq!(conflicts.len(), 1);
                assert!(matches!(
                    &conflicts[0],
                    merge::Conflict::SecretConflict { name, .. } if name == &var("CONFLICT_SECRET")
                ));
                // Explicit selection resolves it.
                let chosen = merge::resolve_secret(
                    &conflicts,
                    &var("CONFLICT_SECRET"),
                    &SecretRevisionId::parse("sec_rev_side").unwrap(),
                )
                .unwrap();
                assert_eq!(
                    chosen,
                    ManifestEntry::Secret {
                        revision: SecretRevisionId::parse("sec_rev_side").unwrap()
                    }
                );
            }
            other => panic!("expected merge conflict, got {other:?}"),
        }
    }

    #[test]
    fn merge_base_finds_shared_ancestor_or_none() {
        let fx = temp_repo();
        let author = IdentityRef::parse("user:b").unwrap();

        fx.repo.add(var("ROOT"), cfg_obj("root_v1")).unwrap();
        let base = fx
            .repo
            .create_commit("base", author.clone(), &fx.pair)
            .unwrap();

        // Diverge main (ours) and feature (theirs).
        fx.repo.add(var("OURS"), cfg_obj("o1")).unwrap();
        let ours_tip = fx
            .repo
            .create_commit("ours", author.clone(), &fx.pair)
            .unwrap();
        fx.repo.create_branch("feature", Some(&base)).unwrap();
        fx.repo.checkout_branch("feature").unwrap();
        fx.repo.add(var("THEIRS"), cfg_obj("t1")).unwrap();
        let theirs_tip = fx
            .repo
            .create_commit("theirs", author.clone(), &fx.pair)
            .unwrap();

        assert_eq!(
            fx.repo.merge_base(&ours_tip, &theirs_tip).unwrap(),
            Some(base.clone())
        );
        assert_eq!(
            fx.repo.merge_base(&base, &ours_tip).unwrap(),
            Some(base.clone())
        );
        assert_eq!(fx.repo.merge_base(&ours_tip, &base).unwrap(), Some(base));

        // An unrelated root shares nothing.
        let other_dir = tempfile::tempdir().unwrap();
        let other = Repository::init(other_dir.path()).unwrap();
        other.add(var("X"), cfg_obj("x")).unwrap();
        let unrelated = other
            .create_commit(
                "unrelated",
                IdentityRef::parse("user:o").unwrap(),
                &SigningKeyPair::generate(),
            )
            .unwrap();
        assert_eq!(fx.repo.merge_base(&ours_tip, &unrelated).unwrap(), None);
    }

    #[test]
    fn diff_manifests_delegates_to_classifier() {
        let mut old = Manifest::new();
        old.set_config(var("A"), ObjectId::parse("obj_a1").unwrap());
        let mut new = Manifest::new();
        new.set_config(var("A"), ObjectId::parse("obj_a2").unwrap());

        let entries = Repository::diff_manifests(&old, &new);
        assert_eq!(entries.len(), 1);
        assert_eq!(diff::render_diff(&entries), "~ config A : obj_a1 -> obj_a2");
    }

    #[test]
    fn merge_with_explicit_base_resolves_diverged_changes() {
        let fx = temp_repo();

        // Genuine three-way scenario:
        //   base   : SHARED=v1, TUNED=v1
        //   main   : TUNED -> v2 (+ MAIN_ONLY)   [ours]
        //   feature: SHARED -> v2                [theirs]
        // With the empty base used by merge(branch, None), both sides count
        // as additions and conflict; the real common ancestor merges clean.
        let mut base = Manifest::new();
        base.set_config(var("SHARED"), ObjectId::parse("obj_shared_v1").unwrap());
        base.set_config(var("TUNED"), ObjectId::parse("obj_tuned_v1").unwrap());

        // Sanity: an unknown branch still errors before merging happens.
        assert!(fx.repo.merge("nonexistent-branch", Some(&base)).is_err());
        // And without a base the same divergence conflicts.
        // (Setup first, re-asserted below once commits exist.)

        fx.repo.add(var("SHARED"), cfg_obj("shared_v1")).unwrap();
        fx.repo.add(var("TUNED"), cfg_obj("tuned_v1")).unwrap();
        fx.repo
            .create_commit(
                "base state",
                IdentityRef::parse("user:b").unwrap(),
                &fx.pair,
            )
            .unwrap();
        fx.repo.create_branch("feature", None).unwrap();

        // Ours (main): change TUNED only.
        fx.repo.add(var("TUNED"), cfg_obj("tuned_v2")).unwrap();
        fx.repo.add(var("MAIN_ONLY"), cfg_obj("main_only")).unwrap();
        fx.repo
            .create_commit(
                "main diverges",
                IdentityRef::parse("user:m").unwrap(),
                &fx.pair,
            )
            .unwrap();

        // Theirs (feature): change SHARED only.
        fx.repo.checkout_branch("feature").unwrap();
        fx.repo.add(var("SHARED"), cfg_obj("shared_v2")).unwrap();
        fx.repo
            .create_commit(
                "feature diverges",
                IdentityRef::parse("user:f").unwrap(),
                &fx.pair,
            )
            .unwrap();

        fx.repo.checkout_branch("main").unwrap();

        // Without base info both sides look like fresh additions -> clash.
        let empty = Manifest::default();
        match fx.repo.merge("feature", Some(&empty)) {
            Err(RepoError::MergeConflict(conflicts)) => {
                assert_eq!(conflicts.len(), 2, "SHARED + TUNED both clash");
            }
            other => panic!("expected conflicts without base, got {other:?}"),
        }

        let merged = fx
            .repo
            .merge("feature", Some(&base))
            .expect("explicit base resolves");
        assert_eq!(
            merged.get(&var("TUNED")),
            Some(&cfg_obj("tuned_v2")),
            "ours kept"
        );
        assert_eq!(
            merged.get(&var("SHARED")),
            Some(&cfg_obj("shared_v2")),
            "theirs taken (untouched on our side vs base)"
        );
        assert_eq!(merged.get(&var("MAIN_ONLY")), Some(&cfg_obj("main_only")));
    }

    #[test]
    fn committing_from_detached_head_advances_detached_state() {
        let fx = temp_repo();

        fx.repo.add(var("FIRST"), cfg_obj("first_v1")).unwrap();
        let c1 = fx
            .repo
            .create_commit("root", IdentityRef::parse("user:d").unwrap(), &fx.pair)
            .unwrap();

        // Detach onto c1.
        fx.repo.checkout_commit(&c1).unwrap();
        assert!(fx.repo.status().unwrap().branch.is_none(), "detached");

        // Committing while detached must not touch any branch ref.
        fx.repo.add(var("SECOND"), cfg_obj("second_v1")).unwrap();
        let c2 = fx
            .repo
            .create_commit(
                "on detached head",
                IdentityRef::parse("user:d").unwrap(),
                &fx.pair,
            )
            .unwrap();

        assert_ne!(c1, c2);
        assert_eq!(
            fx.repo.current_head().unwrap(),
            Some(c2.clone()),
            "HEAD advanced"
        );
        assert_eq!(
            fx.repo.head_target().unwrap(),
            Some(HeadTarget::Detached { commit: c2.clone() }),
            "HEAD remains detached at the new commit"
        );

        // Branch refs untouched: main still points at c1.
        let branches = fx.repo.list_branches().unwrap();
        assert_eq!(
            branches
                .iter()
                .find(|(n, _)| n == "main")
                .map(|(_, c)| c.clone()),
            Some(c1.clone()),
            "main must remain on its original tip"
        );

        // History chains detached commits correctly.
        let log = fx.repo.log(10).unwrap();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].0, c2);
        assert_eq!(log[0].1.parents, vec![c1]);
    }

    #[test]
    fn environment_ref_flow_through_facade() {
        let fx = temp_repo();
        fx.repo.add(var("APP_URL"), cfg_obj("url_v1")).unwrap();
        let dev_tip = fx
            .repo
            .create_commit(
                "dev baseline",
                IdentityRef::parse("user:d").unwrap(),
                &fx.pair,
            )
            .unwrap();

        // Point an environment ref at it and protect it.
        fx.repo
            .refs()
            .write_env_ref("development", &dev_tip, false)
            .unwrap();
        fx.repo
            .refs()
            .write_env_protection(
                "development",
                &crate::refs::EnvironmentProtection { protected: true },
            )
            .unwrap();

        // Later commit on main; moving the protected env ref needs force.
        fx.repo.add(var("APP_URL"), cfg_obj("url_v2")).unwrap();
        let new_tip = fx
            .repo
            .create_commit("bump url", IdentityRef::parse("user:d").unwrap(), &fx.pair)
            .unwrap();

        assert!(matches!(
            fx.repo.refs().write_env_ref("development", &new_tip, false),
            Err(RepoError::ProtectedRef(_))
        ));
        fx.repo
            .refs()
            .write_env_ref("development", &new_tip, true)
            .unwrap();
        assert_eq!(
            fx.repo
                .refs()
                .read_ref(RefNamespace::Environments, "development")
                .unwrap(),
            Some(new_tip)
        );
    }

    #[test]
    fn tampered_commit_object_breaks_lookup_but_not_untouched_neighbors() {
        let fx = temp_repo();
        fx.repo.add(var("V"), cfg_obj("v1")).unwrap();
        let c1 = fx
            .repo
            .create_commit("one", IdentityRef::parse("user:t").unwrap(), &fx.pair)
            .unwrap();

        // Corrupt the stored commit bytes on disk at their content address.
        let digest = &c1.as_str()[4..];
        let path = fx
            .repo
            .objects()
            .root()
            .join("sha256")
            .join(&digest[..2])
            .join(&digest[2..]);
        std::fs::write(path, b"{\"tampered\":true}").unwrap();

        assert!(matches!(
            fx.repo.show(&c1),
            Err(RepoError::CorruptObject { .. })
        ));
        // Integrity sweep catches it too.
        assert!(matches!(
            fx.repo.objects().verify_all(),
            Err(RepoError::CorruptObject { .. })
        ));
    }
}
