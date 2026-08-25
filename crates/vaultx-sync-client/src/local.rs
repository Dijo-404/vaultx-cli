//! The local side of synchronization: a trait seam over the developer's
//! repository plus the filesystem adapter backed by
//! [`vaultx_repository::Repository`].
//!
//! Objects crossing this boundary are repository-canonical
//! ([`vaultx_repository::ObjectEnvelope`] bytes), so hashes computed here
//! are byte-identical to the ones the control plane validates.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use vaultx_repository::history::History;
use vaultx_repository::object::ObjectEnvelope;
use vaultx_repository::{RefNamespace as RepoRefNamespace, RefStore};
use vaultx_types::{CommitId, ObjectId};

use crate::error::SyncError;
use crate::RefNamespace;

/// Outcome of applying one remote ref value locally.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefApplyOutcome {
    /// The ref moved to the requested commit.
    Applied,
    /// The ref already pointed at the requested commit.
    AlreadyCurrent,
    /// A locally protected environment ref refused the move because no
    /// authorization was asserted.
    RefusedProtected,
}

/// Read/write access to the local workspace state participating in sync.
///
/// Implementations keep every decision reversible: nothing is applied
/// before the client has verified content or established ancestry.
pub trait LocalWorkspace: Send + Sync {
    /// Every object id held locally.
    ///
    /// # Errors
    /// [`SyncError`] on enumeration failures.
    fn known_object_ids(&self) -> Result<Vec<ObjectId>, SyncError>;

    /// Canonical bytes of `id`, or `None` when absent.
    ///
    /// # Errors
    /// [`SyncError`] when present-but-unreadable.
    fn canonical_bytes(&self, id: &ObjectId) -> Result<Option<Vec<u8>>, SyncError>;

    /// Stores a verified envelope; returns true when newly stored.
    ///
    /// # Errors
    /// [`SyncError`] on storage failures or content-address conflicts.
    fn apply_object(&self, envelope: &ObjectEnvelope) -> Result<bool, SyncError>;

    /// Current local refs including environment protection flags.
    ///
    /// # Errors
    /// [`SyncError`] on enumeration failures.
    fn all_refs(&self) -> Result<Vec<vaultx_control_plane::model::RefState>, SyncError>;

    /// Commit a ref points at, if it exists.
    ///
    /// # Errors
    /// [`SyncError`] on read failures.
    fn read_ref(&self, namespace: RefNamespace, name: &str) -> Result<Option<CommitId>, SyncError>;

    /// Moves a local ref to `commit`.
    ///
    /// # Errors
    /// [`SyncError`] on write failures.
    fn apply_ref(
        &self,
        namespace: RefNamespace,
        name: &str,
        commit: &CommitId,
        allow_protected_override: bool,
    ) -> Result<RefApplyOutcome, SyncError>;

    /// Declared parents of commit `id`; `None` when the commit cannot be
    /// resolved from local objects.
    ///
    /// # Errors
    /// [`SyncError`] when resolvable-but-unreadable.
    fn commit_parents(&self, id: &CommitId) -> Result<Option<Vec<CommitId>>, SyncError>;

    /// Applies one remotely-served policy document under `name`, where
    /// `yaml` is the server's canonical document text (canonical JSON,
    /// which parses as YAML). Returns true when local content differed and
    /// was overwritten; false when absent-difference meant no write. The
    /// default implementation is a no-op so workspaces without policy
    /// support keep compiling and report zero applied policies.
    ///
    /// # Errors
    /// [`SyncError`] on filesystem failures.
    fn apply_remote_policy(&self, _name: &str, _yaml: &str) -> Result<bool, SyncError> {
        Ok(false)
    }
}

/// Filesystem adapter over [`vaultx_repository::Repository`], reusing its
/// object store, ref store, and history walking unchanged.
#[derive(Clone, Debug)]
pub struct FsWorkspace {
    repo: vaultx_repository::Repository,
}

impl FsWorkspace {
    /// Opens an initialized repository at `root`.
    ///
    /// # Errors
    /// [`SyncError::Repository`] when the repository cannot be opened.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, SyncError> {
        Ok(Self {
            repo: vaultx_repository::Repository::open(root)?,
        })
    }

    /// The underlying repository handle.
    #[must_use]
    pub fn repository(&self) -> &vaultx_repository::Repository {
        &self.repo
    }

    fn objects_root(&self) -> PathBuf {
        self.repo.vault_dir().join("objects")
    }

    fn store(&self) -> &vaultx_repository::FileSystemObjectStore {
        self.repo.objects()
    }

    fn refs(&self) -> &RefStore {
        self.repo.refs()
    }

    fn map_namespace(namespace: RefNamespace) -> RepoRefNamespace {
        match namespace {
            RefNamespace::Heads => RepoRefNamespace::Heads,
            RefNamespace::Environments => RepoRefNamespace::Environments,
        }
    }
}

impl LocalWorkspace for FsWorkspace {
    fn known_object_ids(&self) -> Result<Vec<ObjectId>, SyncError> {
        // The two-level sha256 shard layout under `<vault>/objects` is part
        // of the documented object-store contract, so enumerating ids by
        // directory walk stays stable across releases.
        let shard_root = self.objects_root().join("sha256");
        let mut ids = Vec::new();
        if !shard_root.exists() {
            return Ok(ids);
        }
        let mut shards: Vec<_> = std::fs::read_dir(&shard_root)?
            .filter_map(std::result::Result::ok)
            .collect();
        shards.sort_by_key(std::fs::DirEntry::file_name);
        for shard in shards {
            let shard_name = shard.file_name().to_string_lossy().into_owned();
            if shard_name.len() != 2 || !shard_name.chars().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }
            let mut entries: Vec<_> = std::fs::read_dir(shard.path())?
                .filter_map(std::result::Result::ok)
                .collect();
            entries.sort_by_key(std::fs::DirEntry::file_name);
            for entry in entries {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with('.') || name.len() != 62 {
                    continue;
                }
                if !name.chars().all(|c| c.is_ascii_hexdigit()) {
                    continue;
                }
                if let Ok(id) = ObjectId::parse(&format!("{}{shard_name}{name}", ObjectId::PREFIX))
                {
                    ids.push(id);
                }
            }
        }
        Ok(ids)
    }

    fn canonical_bytes(&self, id: &ObjectId) -> Result<Option<Vec<u8>>, SyncError> {
        match self.store().get(id) {
            Ok(envelope) => Ok(Some(envelope.canonical_bytes()?)),
            Err(vaultx_repository::RepoError::ObjectNotFound(_)) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    fn apply_object(&self, envelope: &ObjectEnvelope) -> Result<bool, SyncError> {
        // Content addressing makes this idempotent and tamper-evident: the
        // store derives the id itself, so a forged envelope claiming
        // another object's identity fails here rather than corrupting the
        // local store.
        let existed = self.store().exists(&vaultx_repository::object::object_id(
            &envelope.canonical_bytes()?,
        )?);
        self.store().put(envelope)?;
        Ok(!existed)
    }

    fn all_refs(&self) -> Result<Vec<vaultx_control_plane::model::RefState>, SyncError> {
        use vaultx_control_plane::model::RefState;

        let mut out = Vec::new();
        for &(namespace, protected_capable) in &[
            (RepoRefNamespace::Heads, false),
            (RepoRefNamespace::Environments, true),
        ] {
            for (name, commit) in self.refs().list_refs(namespace)? {
                let protected =
                    protected_capable && self.refs().read_env_protection(&name)?.protected;
                out.push(RefState {
                    namespace: match namespace {
                        RepoRefNamespace::Heads => RefNamespace::Heads,
                        RepoRefNamespace::Environments => RefNamespace::Environments,
                    },
                    name,
                    commit,
                    protected,
                });
            }
        }
        out.sort_by(|a, b| {
            (namespace_rank(a.namespace), a.name.as_str())
                .cmp(&(namespace_rank(b.namespace), b.name.as_str()))
        });
        Ok(out)
    }

    fn read_ref(&self, namespace: RefNamespace, name: &str) -> Result<Option<CommitId>, SyncError> {
        Ok(self.refs().read_ref(Self::map_namespace(namespace), name)?)
    }

    fn apply_ref(
        &self,
        namespace: RefNamespace,
        name: &str,
        commit: &CommitId,
        allow_protected_override: bool,
    ) -> Result<RefApplyOutcome, SyncError> {
        match namespace {
            RefNamespace::Heads => {
                let current = self.refs().read_ref(RepoRefNamespace::Heads, name)?;
                if current.as_ref() == Some(commit) {
                    return Ok(RefApplyOutcome::AlreadyCurrent);
                }
                self.refs()
                    .write_ref(RepoRefNamespace::Heads, name, commit)?;
                Ok(RefApplyOutcome::Applied)
            }
            RefNamespace::Environments => {
                let current = self.refs().read_ref(RepoRefNamespace::Environments, name)?;
                if current.as_ref() == Some(commit) {
                    return Ok(RefApplyOutcome::AlreadyCurrent);
                }
                let protected = self.refs().read_env_protection(name)?.protected;
                if protected && !allow_protected_override {
                    return Ok(RefApplyOutcome::RefusedProtected);
                }
                self.refs()
                    .write_env_ref(name, commit, allow_protected_override)?;
                Ok(RefApplyOutcome::Applied)
            }
        }
    }

    fn commit_parents(&self, id: &CommitId) -> Result<Option<Vec<CommitId>>, SyncError> {
        let history = History::new(self.store());
        match history.find_commit(id) {
            Ok(commit) => Ok(Some(commit.parents)),
            Err(vaultx_repository::RepoError::ObjectNotFound(_)) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    fn apply_remote_policy(&self, name: &str, yaml: &str) -> Result<bool, SyncError> {
        // Mirrors the human-editable layout (`<root>/.vaultx/policies/
        // <name>.yaml`) used by the policy ops service, so pulled policies
        // load identically to locally authored ones. Policy names are
        // validated `[a-z0-9_-]`, keeping the derived filename path-safe.
        let dir = self.repo.vault_dir().join("policies");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{name}.yaml"));
        if let Ok(existing) = std::fs::read_to_string(&path) {
            if existing == yaml {
                return Ok(false);
            }
        }
        std::fs::write(&path, yaml)?;
        Ok(true)
    }
}

/// Shared ancestry helper used by the client: true when `ancestor` equals
/// or precedes `descendant` in the reachable parent graph.
pub(crate) fn is_ancestor_or_equal<W: LocalWorkspace + ?Sized>(
    workspace: &W,
    ancestor: &CommitId,
    descendant: &CommitId,
) -> Result<bool, SyncError> {
    if ancestor == descendant {
        return Ok(true);
    }
    let mut queue = vec![descendant.clone()];
    let mut visited = BTreeSet::new();
    while let Some(current) = queue.pop() {
        if !visited.insert(current.clone()) {
            continue;
        }
        let Some(parents) = workspace.commit_parents(&current)? else {
            continue; // Unresolvable link: not proof of ancestry.
        };
        for parent in parents {
            if &parent == ancestor {
                return Ok(true);
            }
            queue.push(parent);
        }
    }
    Ok(false)
}

/// Namespace sort rank matching the control plane's listing order.
fn namespace_rank(namespace: RefNamespace) -> u8 {
    match namespace {
        RefNamespace::Heads => 0,
        RefNamespace::Environments => 1,
    }
}

#[cfg(test)]
mod tests {
    use vaultx_crypto::signature::SigningKeyPair;
    use vaultx_repository::{ManifestEntry, RefNamespace as RepoNs, Repository};
    use vaultx_types::{IdentityRef, VariableName};

    use super::*;
    use crate::RefNamespace;

    fn temp_repo(tag: &str) -> (tempfile::TempDir, Repository) {
        let dir = tempfile::tempdir().expect("tempdir");
        let repo = Repository::init(dir.path().join(tag)).expect("init");
        (dir, repo)
    }

    /// Commits one config variable so the store gains a config-value
    /// object, a manifest object, and a commit object.
    fn commit_config(
        repo: &Repository,
        pair: &SigningKeyPair,
        name: &str,
        value: &str,
    ) -> CommitId {
        let value_id = repo
            .objects()
            .put(&vaultx_repository::ObjectEnvelope::new(
                vaultx_repository::ObjectType::ConfigValue,
                format!("{{\"value\":\"{value}\"}}").into_bytes(),
            ))
            .expect("store config value");
        repo.add(
            VariableName::parse(name).expect("valid name"),
            ManifestEntry::Config { object: value_id },
        )
        .expect("stage");
        repo.create_commit(
            &format!("set {name}"),
            IdentityRef::parse("user:tester").expect("valid"),
            pair,
        )
        .expect("commit")
    }

    #[test]
    fn known_object_ids_enumerate_shard_layout() {
        let (_guard, repo) = temp_repo("enum");
        let pair = SigningKeyPair::generate();
        commit_config(&repo, &pair, "API_KEY", "v1");

        let ws = FsWorkspace::open(repo.root()).expect("open");
        let ids = ws.known_object_ids().expect("ids");
        assert_eq!(ids.len(), 3, "config + manifest + commit objects");
        for id in &ids {
            assert!(ws.canonical_bytes(id).expect("bytes").is_some());
        }
        let missing = ObjectId::parse("obj_deadbeefcafebabe").expect("valid shape");
        assert!(ws.canonical_bytes(&missing).expect("absent").is_none());
    }

    #[test]
    fn apply_object_is_content_addressed_and_reports_novelty() {
        let (_guard, repo) = temp_repo("apply");
        let ws = FsWorkspace::open(repo.root()).expect("open");
        let envelope = vaultx_repository::ObjectEnvelope::new(
            vaultx_repository::ObjectType::Manifest,
            b"{}".to_vec(),
        );
        assert!(ws.apply_object(&envelope).expect("first apply"));
        assert!(!ws.apply_object(&envelope).expect("duplicate apply"));
        assert_eq!(ws.known_object_ids().expect("ids").len(), 1);
    }

    #[test]
    fn head_refs_apply_and_report_current() {
        let (_guard, repo) = temp_repo("heads");
        let ws = FsWorkspace::open(repo.root()).expect("open");
        let c1 = CommitId::parse("cmt_head_one").expect("valid");
        assert_eq!(
            ws.apply_ref(RefNamespace::Heads, "main", &c1, false)
                .expect("apply"),
            RefApplyOutcome::Applied
        );
        assert_eq!(
            ws.apply_ref(RefNamespace::Heads, "main", &c1, false)
                .expect("again"),
            RefApplyOutcome::AlreadyCurrent
        );
        assert_eq!(
            ws.read_ref(RefNamespace::Heads, "main").expect("read"),
            Some(c1)
        );
    }

    #[test]
    fn protected_environment_refs_refuse_unauthorized_override() {
        let (_guard, repo) = temp_repo("envs");
        let c1 = CommitId::parse("cmt_prod_ref_a").expect("valid");
        let c2 = CommitId::parse("cmt_prod_ref_b").expect("valid");
        repo.refs()
            .write_env_ref("production", &c1, false)
            .expect("seed ref");
        repo.refs()
            .write_env_protection(
                "production",
                &vaultx_repository::EnvironmentProtection { protected: true },
            )
            .expect("protect");

        let ws = FsWorkspace::open(repo.root()).expect("open");
        let refused = ws
            .apply_ref(RefNamespace::Environments, "production", &c2, false)
            .expect("evaluated");
        assert_eq!(refused, RefApplyOutcome::RefusedProtected);
        assert_eq!(
            ws.read_ref(RefNamespace::Environments, "production")
                .expect("read"),
            Some(c1.clone()),
            "protected ref must stay untouched"
        );
        let forced = ws
            .apply_ref(RefNamespace::Environments, "production", &c2, true)
            .expect("authorized");
        assert_eq!(forced, RefApplyOutcome::Applied);
        assert_eq!(
            ws.read_ref(RefNamespace::Environments, "production")
                .expect("read"),
            Some(c2)
        );
    }

    #[test]
    fn all_refs_carry_protection_flags_sorted() {
        let (_guard, repo) = temp_repo("listrefs");
        let c = CommitId::parse("cmt_listing").expect("valid");
        repo.refs()
            .write_ref(RepoNs::Heads, "main", &c)
            .expect("head");
        repo.refs()
            .write_env_ref("staging", &c, false)
            .expect("env");
        repo.refs()
            .write_env_protection(
                "staging",
                &vaultx_repository::EnvironmentProtection { protected: true },
            )
            .expect("protect staging");

        let ws = FsWorkspace::open(repo.root()).expect("open");
        let refs = ws.all_refs().expect("refs");
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].namespace, RefNamespace::Heads);
        assert_eq!(refs[0].name, "main");
        assert!(!refs[0].protected);
        assert_eq!(refs[1].namespace, RefNamespace::Environments);
        assert_eq!(refs[1].name, "staging");
        assert!(refs[1].protected);
    }

    #[test]
    fn commit_parents_resolve_stored_commits_only() {
        let (_guard, repo) = temp_repo("parents");
        let pair = SigningKeyPair::generate();
        let root = commit_config(&repo, &pair, "A", "1");
        let child = commit_config(&repo, &pair, "B", "2");

        let ws = FsWorkspace::open(repo.root()).expect("open");
        let child_commit = {
            let history = History::new(repo.objects());
            history.find_commit(&child).expect("child")
        };
        assert_eq!(
            ws.commit_parents(&child).expect("parents"),
            Some(child_commit.parents)
        );
        let unknown = CommitId::parse("cmt_nowhere").expect("valid shape");
        assert_eq!(ws.commit_parents(&unknown).expect("unknown"), None);

        // Root commit has no parents; ancestry helper agrees.
        assert!(is_ancestor_or_equal(&ws, &root, &child).expect("ancestry"));
        assert!(!is_ancestor_or_equal(&ws, &child, &root).expect("reverse"));
        assert!(is_ancestor_or_equal(&ws, &child, &child).expect("self"));
    }

    /// Minimal workspace implementing only the pre-policy surface: proves
    /// the provided `apply_remote_policy` default keeps such impls
    /// compiling and reports "not applied".
    struct BareWorkspace;

    impl LocalWorkspace for BareWorkspace {
        fn known_object_ids(&self) -> Result<Vec<ObjectId>, SyncError> {
            Ok(Vec::new())
        }

        fn canonical_bytes(&self, _id: &ObjectId) -> Result<Option<Vec<u8>>, SyncError> {
            Ok(None)
        }

        fn apply_object(&self, _envelope: &ObjectEnvelope) -> Result<bool, SyncError> {
            Ok(false)
        }

        fn all_refs(&self) -> Result<Vec<vaultx_control_plane::model::RefState>, SyncError> {
            Ok(Vec::new())
        }

        fn read_ref(
            &self,
            _namespace: RefNamespace,
            _name: &str,
        ) -> Result<Option<CommitId>, SyncError> {
            Ok(None)
        }

        fn apply_ref(
            &self,
            _namespace: RefNamespace,
            _name: &str,
            _commit: &CommitId,
            _allow_protected_override: bool,
        ) -> Result<RefApplyOutcome, SyncError> {
            Ok(RefApplyOutcome::Applied)
        }

        fn commit_parents(&self, _id: &CommitId) -> Result<Option<Vec<CommitId>>, SyncError> {
            Ok(None)
        }
    }

    #[test]
    fn apply_remote_policy_defaults_to_not_applied() {
        let bare = BareWorkspace;
        assert!(!bare
            .apply_remote_policy("read_only", "{}")
            .expect("default is a no-op"));
    }
}
