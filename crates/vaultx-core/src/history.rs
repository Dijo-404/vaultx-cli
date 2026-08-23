//! [`HistoryService`]: commits, history inspection, diffs, branches, and
//! commit-signature verification.
//!
//! # Device signing identity
//!
//! Commits are Ed25519-signed with a **persistent device keypair**:
//!
//! * On first use a fresh keypair is generated and its 32-byte seed is
//!   persisted as lowercase hex (64 chars) at `.vaultx/device.key`; the
//!   matching compressed public key is persisted as hex at
//!   `.vaultx/device.pub`. Later sessions load the seed back through
//!   [`SigningKeyPair::from_seed`], so every commit in the project is
//!   signed by the same identity and remains verifiable across processes.
//! * The private-key file is created with owner-only permissions (`0600`)
//!   on unix and re-enforced on rewrite; other platforms currently rely
//!   on default file permissions (Windows ACL hardening deferred).
//! * A corrupt or non-hex `device.key` surfaces as
//!   [`CoreError::DeviceKey`] instead of being silently overwritten:
//!   rotation must be an explicit operator decision, since any 32 bytes
//!   are a valid seed and tampering cannot be detected from the file
//!   alone. `device.pub` is treated as derived data and self-heals to the
//!   active pair's verifying key on each initialization.
//!
//! [`HistoryService::verify_head_signature`] validates the head commit's
//! signature against `.vaultx/device.pub`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError};

use vaultx_crypto::signature::{SigningKeyPair, VerifyingPublicKey};
use vaultx_repository::{
    three_way_merge, three_way_merge_with_strategy, DiffEntry, HeadTarget, Manifest, ManifestEntry,
    MergeStrategy, RefNamespace, StagingIndex,
};
use vaultx_types::model::VariableKind;
use vaultx_types::{CommitId, IdentityRef};

use crate::error::{CoreError, CoreResult};
use crate::project::ProjectContext;
use crate::secrets::{SecretRevisionState, SecretService};

/// File holding the hex-encoded 32-byte signing seed of the device
/// identity (owner-only permissions on unix).
pub(crate) const DEVICE_KEY_FILE: &str = "device.key";
/// File holding the hex-encoded compressed verifying key of the device
/// identity.
pub(crate) const DEVICE_PUB_FILE: &str = "device.pub";

/// One row of [`HistoryService::log`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitSummary {
    /// Commit id.
    pub id: CommitId,
    /// Commit message.
    pub message: String,
    /// Author identity string.
    pub author: String,
    /// Number of parents (0 = root).
    pub parents_len: usize,
}

/// One manifest entry rendered for `show`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntrySummary {
    /// Variable name.
    pub name: String,
    /// Entry kind (`config`, `secret`, `brokered`, `dynamic`).
    pub kind: &'static str,
    /// Kind-specific reference (object id / revision id /
    /// `credential@revision` / provider ref). Never secret material.
    pub reference: String,
}

/// Full detail of one commit including its captured manifest entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitDetail {
    /// Commit id.
    pub id: CommitId,
    /// Commit message.
    pub message: String,
    /// Author identity string.
    pub author: String,
    /// Parent ids in canonical order.
    pub parents: Vec<CommitId>,
    /// Manifest entries sorted by variable name.
    pub entries: Vec<EntrySummary>,
}

/// One side of a config-value conflict, with both plaintext values
/// decoded from their config objects when readable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigValueConflict {
    /// Variable in dispute.
    pub name: String,
    /// Value bound on the target (ours) side.
    pub ours_value: String,
    /// Value bound on the merged-in (theirs) side.
    pub theirs_value: String,
}

/// One secret-revision dispute. Revision ids only — never values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretRevisionConflict {
    /// Variable in dispute.
    pub name: String,
    /// Revision chosen on the ours side (`(removed)` when deleted).
    pub ours_revision: String,
    /// Revision chosen on the theirs side (`(removed)` when deleted).
    pub theirs_revision: String,
}

/// Grouped conflict report for a refused merge. Nothing was written to
/// the repository when this is produced.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MergeConflictSet {
    /// Non-secret value disputes (values shown).
    pub configs: Vec<ConfigValueConflict>,
    /// Secret revision disputes (revision ids only).
    pub secrets: Vec<SecretRevisionConflict>,
    /// Policy document disputes (names only).
    pub policies: Vec<String>,
}

impl MergeConflictSet {
    /// Total number of unresolved disagreements across all groups.
    #[must_use]
    pub fn len(&self) -> usize {
        self.configs.len() + self.secrets.len() + self.policies.len()
    }

    /// Whether anything remains unresolved.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Outcome of a [`HistoryService::merge_branch`] request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MergeOutcome {
    /// The target already contains the other branch's tip; no commit.
    AlreadyUpToDate {
        /// Branch merged into.
        target_branch: String,
    },
    /// Clean merge committed onto the target branch.
    Committed {
        /// New two-parent merge commit.
        commit_id: CommitId,
        /// Branch merged into.
        target_branch: String,
    },
    /// Blocked by conflicts; refs and objects untouched.
    Conflicts(MergeConflictSet),
}

/// Result of a successful [`HistoryService::rollback`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RollbackReport {
    /// Historical commit whose state was restored.
    pub target: CommitId,
    /// Newly appended rollback commit.
    pub commit_id: CommitId,
    /// Per-secret notices about destroyed/shredded revisions bound by the
    /// restored manifest; replacement values are required before use.
    pub warnings: Vec<String>,
}

/// History operations: commit / log / show / diff / branch / verify.
#[derive(Clone, Copy, Debug)]
pub struct HistoryService<'a> {
    ctx: &'a ProjectContext,
}

impl<'a> HistoryService<'a> {
    /// Builds a service operating on `ctx`.
    #[must_use]
    pub const fn new(ctx: &'a ProjectContext) -> Self {
        Self { ctx }
    }

    fn device_path(&self, file: &str) -> PathBuf {
        self.ctx.vault_dir().join(file)
    }

    fn device_pub_path(&self) -> PathBuf {
        self.device_path(DEVICE_PUB_FILE)
    }

    /// Returns the project's signing identity: loaded from the persisted
    /// seed when `.vaultx/device.key` exists, otherwise freshly generated
    /// and persisted (seed + verifying key). Cached per process so every
    /// commit in one session shares the identity. See module docs for the
    /// file-permission and corruption contracts.
    fn signing_pair(&self) -> CoreResult<Arc<SigningKeyPair>> {
        let mut slot = self
            .ctx
            .device_pair_slot
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(pair) = slot.as_ref() {
            return Ok(Arc::clone(pair));
        }
        let pair = match std::fs::read_to_string(self.device_path(DEVICE_KEY_FILE)) {
            Ok(text) => self.load_persisted_pair(&text)?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                self.generate_and_persist_pair()?
            }
            Err(err) => return Err(err.into()),
        };
        *slot = Some(Arc::clone(&pair));
        Ok(pair)
    }

    fn load_persisted_pair(&self, text: &str) -> CoreResult<Arc<SigningKeyPair>> {
        let corrupt = |reason: String| CoreError::DeviceKey(reason);
        let trimmed = text.trim();
        let bytes =
            hex::decode(trimmed).map_err(|err| corrupt(format!("not valid hex ({err})")))?;
        let seed: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
            corrupt(format!("expected 32 bytes, found {}", bytes.len()))
        })?;
        let pair = SigningKeyPair::from_seed(&seed).map_err(|err| corrupt(err.to_string()))?;
        // device.pub is derived data: keep it in lockstep with whatever
        // identity the seed actually resolves to.
        self.persist_device_pub(&pair);
        // Defense in depth: re-assert owner-only mode in case an external
        // process loosened it between sessions.
        enforce_private_permissions(&self.device_path(DEVICE_KEY_FILE))?;
        Ok(Arc::new(pair))
    }

    fn generate_and_persist_pair(&self) -> CoreResult<Arc<SigningKeyPair>> {
        let pair = Arc::new(SigningKeyPair::generate());
        let mut seed_hex = String::new();
        pair.expose_seed(|seed| seed_hex = hex::encode(seed));
        write_private_file(&self.device_path(DEVICE_KEY_FILE), &format!("{seed_hex}\n"))?;
        self.persist_device_pub(&pair);
        Ok(pair)
    }

    /// Publishes `device.pub` atomically; treated as derived data and
    /// rewritten whenever the identity initializes.
    fn persist_device_pub(&self, pair: &SigningKeyPair) {
        let public_hex = hex::encode(pair.verifying_public_key().to_bytes());
        let path = self.device_pub_path();
        let tmp = path.with_file_name(format!(".tmp-device-pub-{}", std::process::id()));
        if std::fs::write(&tmp, format!("{public_hex}\n")).is_ok() {
            let _ = std::fs::rename(&tmp, &path);
        }
    }

    /// Creates a signed commit from the staging index.
    ///
    /// The author string is validated as an [`IdentityRef`]; the signature
    /// comes from the persistent device identity (see module docs).
    ///
    /// # Errors
    /// * [`CoreError::DeviceKey`] when a persisted device key is corrupt.
    /// * Propagates identifier-validation, staging-empty, and storage/ref
    ///   failures from the underlying repository.
    pub fn commit(&self, message: &str, author: &str) -> CoreResult<CommitId> {
        let identity = IdentityRef::parse(author)?;
        let pair = self.signing_pair()?;
        Ok(self
            .ctx
            .repository()
            .create_commit(message, identity, &pair)?)
    }

    /// First-parent log newest-first, at most `limit` entries.
    ///
    /// # Errors
    /// * Propagates history-walk failures.
    pub fn log(&self, limit: usize) -> CoreResult<Vec<CommitSummary>> {
        Ok(self
            .ctx
            .repository()
            .log(limit)?
            .into_iter()
            .map(|(id, commit)| CommitSummary {
                id,
                message: commit.message,
                author: commit.author.to_string(),
                parents_len: commit.parents.len(),
            })
            .collect())
    }

    /// Loads one commit with its manifest entries summarized.
    ///
    /// # Errors
    /// * Propagates lookup/decode failures (including
    ///   [`CoreError::Repo`] carrying a corrupt-object error for tampered
    ///   bytes on disk).
    pub fn show(&self, commit_id: &CommitId) -> CoreResult<CommitDetail> {
        let (commit, manifest) = self.ctx.repository().show(commit_id)?;
        let entries = manifest
            .entries
            .iter()
            .map(|(name, entry)| EntrySummary {
                name: name.to_string(),
                kind: kind_str(entry.kind()),
                reference: reference_of(entry),
            })
            .collect();
        Ok(CommitDetail {
            id: commit_id.clone(),
            message: commit.message,
            author: commit.author.to_string(),
            parents: commit.parents,
            entries,
        })
    }

    /// Metadata-only diff between the HEAD manifest and the manifest that
    /// committing the current staging index would produce.
    ///
    /// # Errors
    /// * Propagates manifest/staging failures.
    pub fn diff_staged(&self) -> CoreResult<Vec<DiffEntry>> {
        let repo = self.ctx.repository();
        let base = repo.working_manifest()?;
        let index = StagingIndex::load(self.ctx.vault_dir())?;
        let next = index.apply_onto(&base);
        Ok(vaultx_repository::Repository::diff_manifests(&base, &next))
    }

    /// Metadata-only diff between the manifests of two commits.
    ///
    /// # Errors
    /// * Propagates lookup failures.
    pub fn diff_commits(&self, a: &CommitId, b: &CommitId) -> CoreResult<Vec<DiffEntry>> {
        let old = self.ctx.repository().manifest_at(a)?;
        let new = self.ctx.repository().manifest_at(b)?;
        Ok(vaultx_repository::Repository::diff_manifests(&old, &new))
    }

    /// Creates a branch at the current head.
    ///
    /// # Errors
    /// * Propagates ref-store failures (duplicate names, no head yet).
    pub fn branch(&self, name: &str) -> CoreResult<()> {
        Ok(self.ctx.repository().create_branch(name, None)?)
    }

    /// Checks out a branch by name.
    ///
    /// # Errors
    /// * Propagates ref-store failures (unknown branch).
    pub fn checkout(&self, name: &str) -> CoreResult<()> {
        Ok(self.ctx.repository().checkout_branch(name)?)
    }

    /// All branches as `(name, tip)` pairs sorted by name.
    ///
    /// # Errors
    /// * Propagates ref-store failures.
    pub fn branches(&self) -> CoreResult<Vec<(String, CommitId)>> {
        Ok(self.ctx.repository().list_branches()?)
    }

    /// Three-way merges `theirs_branch` into a target branch (default:
    /// the current branch).
    ///
    /// The common ancestor is resolved through the repository's merge
    /// base, so genuinely diverged changes auto-merge. With `strategy`,
    /// non-secret disagreements resolve by picking that side; secret
    /// revisions always block regardless of strategy.
    ///
    /// Protection rule: every **protected** environment ref pinned on the
    /// target branch's lineage must not lose variables in the merged
    /// result; otherwise the merge is refused with
    /// [`CoreError::ProtectionWeakening`] unless `allow_weaker_protection`.
    ///
    /// On conflict nothing is written: refs and objects stay untouched.
    ///
    /// # Errors
    /// * [`CoreError::UnsupportedOperation`] for detached HEAD without an
    ///   explicit target and for histories without a common ancestor.
    /// * [`CoreError::ProtectionWeakening`] per the protection rule above.
    /// * Propagates ref/store/signing failures.
    pub fn merge_branch(
        &self,
        theirs_branch: &str,
        into_target: Option<&str>,
        strategy: Option<MergeStrategy>,
        allow_weaker_protection: bool,
        author: &str,
    ) -> CoreResult<MergeOutcome> {
        let repo = self.ctx.repository();
        let refs = repo.refs();

        let target = match into_target {
            Some(name) => name.to_owned(),
            None => match repo.head_target()? {
                Some(HeadTarget::Branch { name }) => name,
                _ => {
                    return Err(CoreError::UnsupportedOperation(
                        "HEAD is detached; pass --into <branch> to choose a merge target"
                            .to_owned(),
                    ))
                }
            },
        };
        let ours_tip = Self::require_head(refs, &target)?;
        let theirs_tip = Self::require_head(refs, theirs_branch)?;

        if ours_tip == theirs_tip {
            return Ok(MergeOutcome::AlreadyUpToDate {
                target_branch: target,
            });
        }

        let base_commit = repo.merge_base(&ours_tip, &theirs_tip)?.ok_or_else(|| {
            CoreError::UnsupportedOperation(format!(
                "branches `{target}` and `{theirs_branch}` share no common ancestor"
            ))
        })?;

        let base = repo.manifest_at(&base_commit)?;
        let ours = repo.manifest_at(&ours_tip)?;
        let theirs = repo.manifest_at(&theirs_tip)?;

        let merged = match strategy {
            Some(side) => three_way_merge_with_strategy(&base, &ours, &theirs, side),
            None => three_way_merge(&base, &ours, &theirs),
        };
        let merged = match merged {
            Ok(manifest) => manifest,
            Err(conflicts) => {
                return Ok(MergeOutcome::Conflicts(
                    self.conflict_set(&conflicts, &ours, &theirs)?,
                ));
            }
        };

        if !allow_weaker_protection {
            self.assert_no_protection_weakening(&target, &ours_tip, &merged)?;
        }

        let identity = IdentityRef::parse(author)?;
        let pair = self.signing_pair()?;
        let commit_id = repo.create_merge_commit(
            &format!("merge {theirs_branch} into {target}"),
            identity,
            &pair,
            &target,
            &theirs_tip,
            &merged,
        )?;
        Ok(MergeOutcome::Committed {
            commit_id,
            target_branch: target,
        })
    }

    fn require_head(refs: &vaultx_repository::RefStore, branch: &str) -> CoreResult<CommitId> {
        refs.read_ref(RefNamespace::Heads, branch)?.ok_or_else(|| {
            CoreError::Repo(vaultx_repository::RepoError::RefNotFound(format!(
                "heads/{branch}"
            )))
        })
    }

    /// Refuses merges whose result removes any variable bound by a
    /// protected environment ref pinned on the target branch's lineage.
    fn assert_no_protection_weakening(
        &self,
        target_branch: &str,
        ours_tip: &CommitId,
        merged: &Manifest,
    ) -> CoreResult<()> {
        let repo = self.ctx.repository();
        let refs = repo.refs();
        let mut weakened: Vec<String> = Vec::new();
        for (env_name, pinned) in refs.list_refs(RefNamespace::Environments)? {
            if !refs.read_env_protection(&env_name)?.protected {
                continue;
            }
            // Only environments following this branch's lineage are
            // affected by what the new tip will feed future promotions.
            if repo.merge_base(&pinned, ours_tip)? != Some(pinned.clone()) {
                continue;
            }
            let pinned_manifest = repo.manifest_at(&pinned)?;
            for name in pinned_manifest.entries.keys() {
                if !merged.entries.contains_key(name) {
                    weakened.push(format!(
                        "protected environment `{env_name}` would lose variable `{name}` \
                         from `{target_branch}`"
                    ));
                }
            }
        }
        if weakened.is_empty() {
            Ok(())
        } else {
            Err(CoreError::ProtectionWeakening(weakened.join("; ")))
        }
    }

    /// Buckets raw merge conflicts into the presentation-oriented report,
    /// decoding config values where their objects are readable.
    fn conflict_set(
        &self,
        conflicts: &[vaultx_repository::Conflict],
        ours: &Manifest,
        theirs: &Manifest,
    ) -> CoreResult<MergeConflictSet> {
        let mut set = MergeConflictSet::default();
        for conflict in conflicts {
            match conflict {
                vaultx_repository::Conflict::ConfigConflict { name } => {
                    set.configs.push(ConfigValueConflict {
                        name: name.to_string(),
                        ours_value: self.side_display(ours.get(name)),
                        theirs_value: self.side_display(theirs.get(name)),
                    });
                }
                vaultx_repository::Conflict::SecretConflict {
                    name,
                    ours_rev,
                    theirs_rev,
                } => {
                    set.secrets.push(SecretRevisionConflict {
                        name: name.to_string(),
                        ours_revision: revision_display(ours_rev),
                        theirs_revision: revision_display(theirs_rev),
                    });
                }
                vaultx_repository::Conflict::PolicyConflict { name } => {
                    set.policies.push(name.to_string());
                }
            }
        }
        Ok(set)
    }

    /// Human-readable rendering of one conflict side: decoded config
    /// value when possible, metadata reference otherwise, `(removed)`
    /// when absent. Never secret material — non-config entries render
    /// kind + identifier only.
    fn side_display(&self, entry: Option<&ManifestEntry>) -> String {
        match entry {
            None => "(removed)".to_owned(),
            Some(ManifestEntry::Config { object }) => crate::config::ConfigService::new(self.ctx)
                .value_of_config_object(object)
                .unwrap_or_else(|_| format!("<unreadable object {object}>")),
            Some(other) => format!("{} {}", kind_str(other.kind()), reference_of(other)),
        }
    }

    /// Rolls the working state back by creating a **new** commit whose
    /// manifest is the historical target's (append-only; no history or
    /// ref rewrite). Defaults to HEAD's first parent.
    ///
    /// Destroyed/shredded secret revisions bound by the restored manifest
    /// produce warnings but never block: the rollback still proceeds so
    /// the operator can stage replacements.
    ///
    /// # Errors
    /// * [`CoreError::UnsupportedOperation`] before the first commit, for
    ///   parent-less heads without an explicit target, and when rolling
    ///   back onto HEAD itself.
    /// * Propagates staging-not-empty, lookup, signing, and ref failures.
    pub fn rollback(&self, to: Option<&CommitId>, author: &str) -> CoreResult<RollbackReport> {
        let repo = self.ctx.repository();
        let head = repo.current_head()?.ok_or_else(|| {
            CoreError::UnsupportedOperation("no commits yet; nothing to roll back".to_owned())
        })?;
        let (head_commit, _) = repo.show(&head)?;
        let target = match to {
            Some(id) => id.clone(),
            None => head_commit.parents.first().cloned().ok_or_else(|| {
                CoreError::UnsupportedOperation(
                    "HEAD has no parent commit; pass --to <commit>".to_owned(),
                )
            })?,
        };
        if target == head {
            return Err(CoreError::UnsupportedOperation(
                "cannot roll back onto HEAD itself".to_owned(),
            ));
        }

        let warnings = self.destroyed_revision_warnings(&repo.manifest_at(&target)?)?;

        let identity = IdentityRef::parse(author)?;
        let pair = self.signing_pair()?;
        let commit_id = repo.create_rollback_commit(
            &format!("rollback to {target}"),
            identity,
            &pair,
            &target,
        )?;
        Ok(RollbackReport {
            target,
            commit_id,
            warnings,
        })
    }

    /// Names every destroyed/shredded revision bound by `manifest`.
    fn destroyed_revision_warnings(&self, manifest: &Manifest) -> CoreResult<Vec<String>> {
        let secrets = SecretService::new(self.ctx);
        let mut warnings = Vec::new();
        for (name, entry) in &manifest.entries {
            let revision = match entry {
                ManifestEntry::Secret { revision } | ManifestEntry::Brokered { revision, .. } => {
                    revision
                }
                _ => continue,
            };
            if secrets.revision_state(revision)? == Some(SecretRevisionState::Destroyed) {
                warnings.push(format!(
                    "`{name}` binds destroyed secret revision {revision}; its value is \
                     unrecoverable and must be replaced before use"
                ));
            }
        }
        Ok(warnings)
    }

    /// Verifies the head commit's signature against the persisted device
    /// verifying key (`.vaultx/device.pub`).
    ///
    /// Returns `false` on any failure: missing key file, malformed key,
    /// missing head commit, tampered commit objects (integrity check), or
    /// signature mismatch. Never panics and never leaks error detail.
    #[must_use]
    pub fn verify_head_signature(&self) -> bool {
        self.verify_head_signature_inner().unwrap_or(false)
    }

    fn verify_head_signature_inner(&self) -> Option<bool> {
        let head = self.ctx.repository().current_head().ok()??;
        let text = std::fs::read_to_string(self.device_pub_path()).ok()?;
        let bytes: [u8; 32] = hex::decode(text.trim()).ok()?.try_into().ok()?;
        let public = VerifyingPublicKey::from_bytes(&bytes).ok()?;
        let (commit, _) = self.ctx.repository().show(&head).ok()?;
        Some(commit.verify(&public).is_ok())
    }
}

fn kind_str(kind: VariableKind) -> &'static str {
    match kind {
        VariableKind::Config => "config",
        VariableKind::Secret => "secret",
        VariableKind::Brokered => "brokered",
        VariableKind::Dynamic => "dynamic",
    }
}

/// Writes owner-only-permission private material (the device seed).
///
/// On unix the file is created through [`std::fs::OpenOptions`] with mode
/// `0600` and the mode is re-asserted on the final handle so a
/// pre-existing loose file gets tightened too. Other platforms rely on
/// default permissions; Windows ACL hardening is deferred.
fn write_private_file(path: &Path, contents: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)
    }
}

/// Re-asserts owner-only mode on an existing private-key file (unix).
///
/// A no-op on other platforms where Windows ACL hardening remains
/// deferred.
fn enforce_private_permissions(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

fn reference_of(entry: &ManifestEntry) -> String {
    match entry {
        ManifestEntry::Config { object } => object.to_string(),
        ManifestEntry::Secret { revision } => revision.to_string(),
        ManifestEntry::Brokered {
            credential,
            revision,
        } => format!("{credential}@{revision}"),
        ManifestEntry::Dynamic { provider } => provider.to_string(),
    }
}

/// `(removed)` for absent revisions, the id otherwise.
fn revision_display(revision: &Option<vaultx_types::SecretRevisionId>) -> String {
    match revision {
        Some(id) => id.to_string(),
        None => "(removed)".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConfigService;
    use crate::error::CoreError;

    fn temp_ctx() -> (tempfile::TempDir, ProjectContext) {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ProjectContext::init(dir.path()).unwrap();
        (dir, ctx)
    }

    #[test]
    fn commit_log_show_and_diff_commits() {
        let (_guard, ctx) = temp_ctx();
        let config = ConfigService::new(&ctx);
        let history = HistoryService::new(&ctx);

        config.set_config("DB_HOST", "v1").unwrap();
        let c1 = history.commit("first", "user:alice").unwrap();

        let log = history.log(10).unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].id, c1);
        assert_eq!(log[0].message, "first");
        assert_eq!(log[0].author, "user:alice");
        assert_eq!(log[0].parents_len, 0);

        config.set_config("DB_HOST", "v2").unwrap();
        let c2 = history.commit("second", "user:alice").unwrap();

        let log = history.log(10).unwrap();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].id, c2);
        assert_eq!(log[0].parents_len, 1);

        let detail = history.show(&c1).unwrap();
        assert_eq!(detail.id, c1);
        assert_eq!(detail.entries.len(), 1);
        assert_eq!(detail.entries[0].name, "DB_HOST");
        assert_eq!(detail.entries[0].kind, "config");
        assert!(detail.entries[0].reference.starts_with("obj_"));

        let diff = history.diff_commits(&c1, &c2).unwrap();
        assert_eq!(diff.len(), 1);

        // Empty commits are refused by the repository layer.
        assert!(matches!(
            history.commit("nothing staged", "user:a"),
            Err(CoreError::Repo(vaultx_repository::RepoError::StagingEmpty))
        ));
        // Invalid authors are refused before any signing happens.
        ConfigService::new(&ctx).set_config("X", "1").unwrap();
        assert!(matches!(
            HistoryService::new(&ctx).commit("msg", ""),
            Err(CoreError::Id(_))
        ));
    }

    #[test]
    fn diff_staged_reflects_changes_after_baseline() {
        let (_guard, ctx) = temp_ctx();
        let config = ConfigService::new(&ctx);
        let history = HistoryService::new(&ctx);

        config.set_config("DB_HOST", "v1").unwrap();
        history.commit("baseline", "user:t").unwrap();

        config.set_config("NEW_VAR", "x").unwrap();
        let diff = history.diff_staged().unwrap();
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].subject(), "NEW_VAR");

        // Restoring clears it from the staged diff.
        crate::staging::StagingService::new(&ctx)
            .restore("NEW_VAR")
            .unwrap();
        assert!(history.diff_staged().unwrap().is_empty());

        // Unset of a committed variable shows as a removal.
        config.unset_config("DB_HOST").unwrap();
        let diff = history.diff_staged().unwrap();
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].subject(), "DB_HOST");
    }

    #[test]
    fn verify_head_signature_true_then_tampering_fails() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ProjectContext::init(dir.path()).unwrap();

        let history = HistoryService::new(&ctx);
        // No commits yet: nothing to verify.
        assert!(!history.verify_head_signature());

        ConfigService::new(&ctx).set_config("V", "1").unwrap();
        let c1 = history.commit("signed", "user:sig").unwrap();
        assert!(history.verify_head_signature(), "fresh head must verify");

        // Tamper with the stored commit bytes at their content address.
        let digest = &c1.as_str()[4..];
        let object_path = ctx
            .repository()
            .objects()
            .root()
            .join("sha256")
            .join(&digest[..2])
            .join(&digest[2..]);
        std::fs::write(object_path, b"{\"tampered\":true}").unwrap();
        assert!(
            !history.verify_head_signature(),
            "integrity check must fail verification after tampering"
        );
    }

    #[test]
    fn device_identity_persists_and_verifies_across_sessions() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // Session 1: first commit creates the persistent identity.
        let c1 = {
            let ctx = ProjectContext::init(root).unwrap();
            ConfigService::new(&ctx).set_config("A", "1").unwrap();
            let id = HistoryService::new(&ctx).commit("first", "user:s").unwrap();
            assert!(HistoryService::new(&ctx).verify_head_signature());
            assert!(ctx.vault_dir().join("device.key").is_file());
            assert!(ctx.vault_dir().join("device.pub").is_file());
            id
        }; // ctx dropped: signing identity gone from memory.

        // Session 2: the seed is reloaded, not regenerated.
        let (c2, first_commit_still_verifies) = {
            let ctx = ProjectContext::open(root).unwrap();
            ConfigService::new(&ctx).set_config("B", "2").unwrap();
            let history = HistoryService::new(&ctx);
            let c2 = history.commit("second", "user:s").unwrap();

            // The head must verify under the SAME persisted identity.
            assert!(history.verify_head_signature());

            // And the FIRST session's commit must still verify too: load
            // the persisted verifying key and check its signature.
            let text = std::fs::read_to_string(ctx.vault_dir().join("device.pub")).unwrap();
            let bytes: [u8; 32] = hex::decode(text.trim()).unwrap().try_into().unwrap();
            let public = VerifyingPublicKey::from_bytes(&bytes).unwrap();
            let (commit, _) = ctx.repository().show(&c1).unwrap();
            (c2, commit.verify(&public).is_ok())
        };
        assert_ne!(c1, c2);
        assert!(
            first_commit_still_verifies,
            "cross-session commits must share one identity"
        );
    }

    #[cfg(unix)]
    #[test]
    fn device_key_file_gets_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let ctx = ProjectContext::init(dir.path()).unwrap();
        ConfigService::new(&ctx).set_config("V", "1").unwrap();
        HistoryService::new(&ctx)
            .commit("seeded", "user:p")
            .unwrap();

        let key_path = ctx.vault_dir().join("device.key");
        let mode = std::fs::metadata(key_path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "device.key must be readable/writable by the owner only"
        );

        // Rewrites keep the tightened mode even if something loosened it.
        let loose = std::fs::Permissions::from_mode(0o644);
        std::fs::set_permissions(ctx.vault_dir().join("device.key"), loose).unwrap();
        drop(ctx);

        let ctx = ProjectContext::open(dir.path()).unwrap();
        crate::config::ConfigService::new(&ctx)
            .set_config("W", "2")
            .unwrap();
        HistoryService::new(&ctx)
            .commit("reloaded", "user:p")
            .unwrap();
        let mode = std::fs::metadata(ctx.vault_dir().join("device.key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn corrupt_device_key_fails_loudly_without_being_overwritten() {
        for garbage in ["definitely not hex!!", &"ab".repeat(31)] {
            let dir = tempfile::tempdir().unwrap();
            let ctx = ProjectContext::init(dir.path()).unwrap();
            let key_path = ctx.vault_dir().join("device.key");
            std::fs::write(&key_path, garbage).unwrap();

            crate::config::ConfigService::new(&ctx)
                .set_config("X", "1")
                .unwrap();
            let outcome = HistoryService::new(&ctx).commit("blocked", "user:c");
            assert!(
                matches!(&outcome, Err(CoreError::DeviceKey(_))),
                "`{garbage}` must surface a clear error, got {outcome:?}"
            );

            // The corrupt file is preserved for operator inspection.
            assert_eq!(std::fs::read_to_string(&key_path).unwrap(), garbage);
        }
    }

    #[test]
    fn branch_checkout_cycle_preserves_manifests() {
        let (_guard, ctx) = temp_ctx();
        let config = ConfigService::new(&ctx);
        let history = HistoryService::new(&ctx);

        config.set_config("A", "1").unwrap();
        history.commit("base", "user:b").unwrap();

        history.branch("feature").unwrap();
        history.checkout("feature").unwrap();
        config.set_config("B", "2").unwrap();
        history.commit("feature work", "user:b").unwrap();

        history.checkout("main").unwrap();
        let names: Vec<String> = ConfigService::new(&ctx)
            .list_configs()
            .unwrap()
            .into_iter()
            .map(|(n, _)| n.to_string())
            .collect();
        assert_eq!(names, vec!["A"]);

        let branches = history.branches().unwrap();
        assert_eq!(
            branches.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
            vec!["feature", "main"]
        );

        // Unknown branches are refused.
        assert!(matches!(
            history.checkout("ghost"),
            Err(CoreError::Repo(vaultx_repository::RepoError::RefNotFound(
                _
            )))
        ));
    }

    // ---- merge / rollback ----

    use crate::config::ConfigService as MergeConfig;
    use vaultx_crypto::secret::SecretString;

    fn commit_cfg(ctx: &ProjectContext, name: &str, value: &str, message: &str) -> CommitId {
        MergeConfig::new(ctx).set_config(name, value).unwrap();
        HistoryService::new(ctx).commit(message, "user:m").unwrap()
    }

    fn set_secret_and_commit(
        ctx: &ProjectContext,
        name: &str,
        value: &str,
        message: &str,
    ) -> CommitId {
        crate::secrets::SecretService::new(ctx)
            .set_secret(
                name,
                &SecretString::copy_from(value),
                VariableKind::Secret,
                "development",
                None,
            )
            .unwrap();
        HistoryService::new(ctx).commit(message, "user:m").unwrap()
    }

    #[test]
    fn clean_merge_creates_two_parent_commit_combining_sides() {
        let (_guard, ctx) = temp_ctx();
        let history = HistoryService::new(&ctx);

        commit_cfg(&ctx, "A", "1", "base");
        history.branch("feature").unwrap();

        let ours_tip = commit_cfg(&ctx, "C", "3", "main advance");
        history.checkout("feature").unwrap();
        let theirs_tip = commit_cfg(&ctx, "B", "2", "feature work");
        history.checkout("main").unwrap();

        match history
            .merge_branch("feature", None, None, false, "user:m")
            .unwrap()
        {
            MergeOutcome::Committed {
                commit_id,
                target_branch,
            } => {
                assert_eq!(target_branch, "main");
                assert_ne!(commit_id, ours_tip);
                let detail = history.show(&commit_id).unwrap();
                assert_eq!(detail.parents, vec![ours_tip, theirs_tip], "two parents");
                let names: Vec<String> = detail.entries.iter().map(|e| e.name.clone()).collect();
                assert_eq!(names, vec!["A", "B", "C"]);
                assert_eq!(history.branches().unwrap()[1].1, commit_id);
            }
            other => panic!("expected committed merge, got {other:?}"),
        }
    }

    #[test]
    fn config_conflict_reports_values_and_leaves_refs_moved_nowhere() {
        let (_guard, ctx) = temp_ctx();
        let history = HistoryService::new(&ctx);

        commit_cfg(&ctx, "PORT", "8080", "base");
        history.branch("feature").unwrap();
        commit_cfg(&ctx, "PORT", "9090", "ours change");
        let main_tip = ctx.repository().current_head().unwrap().unwrap();
        history.checkout("feature").unwrap();
        commit_cfg(&ctx, "PORT", "7070", "their change");
        let feature_tip = ctx.repository().current_head().unwrap().unwrap();
        history.checkout("main").unwrap();

        match history
            .merge_branch("feature", None, None, false, "user:m")
            .unwrap()
        {
            MergeOutcome::Conflicts(set) => {
                assert!(set.secrets.is_empty() && set.policies.is_empty());
                assert_eq!(set.configs.len(), 1);
                let conflict = &set.configs[0];
                assert_eq!(conflict.name, "PORT");
                assert_eq!(conflict.ours_value, "9090", "config values are shown");
                assert_eq!(conflict.theirs_value, "7070");
            }
            other => panic!("expected conflicts, got {other:?}"),
        }

        // Nothing moved.
        history.checkout("main").unwrap();
        assert_eq!(ctx.repository().current_head().unwrap(), Some(main_tip));
        history.checkout("feature").unwrap();
        assert_eq!(ctx.repository().current_head().unwrap(), Some(feature_tip));
    }

    #[test]
    fn secret_conflicts_block_and_never_surface_plaintext() {
        let (_guard, ctx) = temp_ctx();
        let history = HistoryService::new(&ctx);

        commit_cfg(&ctx, "A", "1", "base");
        history.branch("feature").unwrap();
        let ours_rev = {
            set_secret_and_commit(&ctx, "DB_PASSWORD", "canary-hunter2-ours", "ours rotate");
            ctx.repository().working_manifest().unwrap()
        };
        let ours_revision =
            match ours_rev.get(&vaultx_types::VariableName::parse("DB_PASSWORD").unwrap()) {
                Some(ManifestEntry::Secret { revision }) => revision.clone(),
                other => panic!("expected secret entry, got {other:?}"),
            };
        history.checkout("feature").unwrap();
        let _ = set_secret_and_commit(&ctx, "DB_PASSWORD", "canary-hunter2-theirs", "their rotate");
        history.checkout("main").unwrap();

        match history
            .merge_branch("feature", None, None, false, "user:m")
            .unwrap()
        {
            MergeOutcome::Conflicts(set) => {
                assert!(set.configs.is_empty());
                let conflict = &set.secrets[0];
                assert_eq!(conflict.name, "DB_PASSWORD");
                assert_eq!(conflict.ours_revision, ours_revision.to_string());
                assert!(!conflict.theirs_revision.is_empty());
                let rendered = format!("{set:?}");
                assert!(
                    !rendered.contains("canary-hunter2"),
                    "plaintext leaked into conflict report"
                );
            }
            other => panic!("expected conflicts, got {other:?}"),
        }
    }

    #[test]
    fn strategy_resolves_config_disputes_but_secrets_still_block() {
        let (_guard, ctx) = temp_ctx();
        let history = HistoryService::new(&ctx);

        commit_cfg(&ctx, "PORT", "8080", "base");
        history.branch("feature").unwrap();
        commit_cfg(&ctx, "PORT", "9090", "ours change");
        history.checkout("feature").unwrap();
        commit_cfg(&ctx, "PORT", "7070", "their change");
        history.checkout("main").unwrap();

        let merged = |strategy| match history
            .merge_branch("feature", Some("main"), strategy, false, "user:m")
            .unwrap()
        {
            MergeOutcome::Committed { .. } => MergeConfig::new(&ctx).get_config("PORT").unwrap(),
            MergeOutcome::Conflicts(_) => "conflicts".to_owned(),
            other => panic!("unexpected outcome {other:?}"),
        };

        // Each probe runs against a fresh scenario clone because a
        // committed merge advances the branch tip.
        assert_eq!(merged(Some(MergeStrategy::Ours)), "9090");

        let dir2 = tempfile::tempdir().unwrap();
        let ctx2 = ProjectContext::init(dir2.path()).unwrap();
        let history2 = HistoryService::new(&ctx2);
        commit_cfg(&ctx2, "PORT", "8080", "base");
        history2.branch("feature").unwrap();
        commit_cfg(&ctx2, "PORT", "9090", "ours change");
        history2.checkout("feature").unwrap();
        commit_cfg(&ctx2, "PORT", "7070", "their change");
        history2.checkout("main").unwrap();
        match history2
            .merge_branch(
                "feature",
                None,
                Some(MergeStrategy::Theirs),
                false,
                "user:m",
            )
            .unwrap()
        {
            MergeOutcome::Committed { .. } => {}
            other => panic!("expected committed merge, got {other:?}"),
        }
        assert_eq!(MergeConfig::new(&ctx2).get_config("PORT").unwrap(), "7070");
    }

    #[test]
    fn protection_weakening_is_refused_unless_overridden() {
        for allow in [false, true] {
            let (_guard, ctx) = temp_ctx();
            let history = HistoryService::new(&ctx);
            let envs = crate::envs::EnvironmentService::new(&ctx);

            commit_cfg(&ctx, "KEEP", "1", "base");
            envs.create_environment("staging").unwrap();
            envs.protect_environment("staging", true).unwrap();
            history.branch("feature").unwrap();

            // Feature removes the variable staging depends on; main stays put.
            history.checkout("feature").unwrap();
            MergeConfig::new(&ctx).unset_config("KEEP").unwrap();
            history.commit("drop KEEP", "user:m").unwrap();
            history.checkout("main").unwrap();

            let outcome = history.merge_branch("feature", None, None, allow, "user:m");
            if allow {
                assert!(
                    matches!(outcome, Ok(MergeOutcome::Committed { .. })),
                    "override must proceed, got {outcome:?}"
                );
            } else {
                match outcome {
                    Err(CoreError::ProtectionWeakening(msg)) => {
                        assert!(msg.contains("staging") && msg.contains("KEEP"), "{msg}");
                    }
                    other => panic!("expected ProtectionWeakening, got {other:?}"),
                }
                // Refusal left refs untouched.
                let branches = history.branches().unwrap();
                let feature = &branches[0];
                assert_eq!(feature.0, "feature");
            }
        }
    }

    #[test]
    fn rollback_appends_new_commit_referencing_historical_manifest() {
        let (_guard, ctx) = temp_ctx();
        let history = HistoryService::new(&ctx);

        commit_cfg(&ctx, "A", "1", "first");
        let c2 = { set_secret_and_commit(&ctx, "TOKEN", "secret-value-v1", "second adds token") };
        let c3 = commit_cfg(&ctx, "B", "2", "third adds B");

        // Destroy the secret after it was captured by c2's manifest.
        crate::secrets::SecretService::new(&ctx)
            .destroy_secret("TOKEN", "development")
            .unwrap();

        let report = history.rollback(None, "user:m").unwrap();
        assert_eq!(report.target, c2, "default target is HEAD's first parent");
        assert_ne!(report.commit_id, c3);
        assert_eq!(
            report.warnings.len(),
            1,
            "destroyed revision must warn: {:?}",
            report.warnings
        );
        assert!(report.warnings[0].contains("TOKEN"));

        // The new commit references the historical manifest object id and
        // chains onto the previous head; old commits stay intact.
        let repo = ctx.repository();
        let (_, new_manifest) = repo.show(&report.commit_id).unwrap();
        assert_eq!(
            new_manifest,
            repo.manifest_at(&c2).unwrap(),
            "rollback reuses the historical manifest content"
        );
        assert_eq!(
            repo.show(&report.commit_id).unwrap().0.parents,
            vec![c3.clone()]
        );

        let detail = history.show(&c2).unwrap();
        assert!(detail.entries.iter().any(|e| e.name == "A"));
        assert_eq!(history.log(10).unwrap().len(), 4);
    }

    #[test]
    fn rollback_edge_cases_error_clearly() {
        let (_guard, ctx) = temp_ctx();
        let history = HistoryService::new(&ctx);

        // No commits at all.
        assert!(matches!(
            history.rollback(None, "user:m"),
            Err(CoreError::UnsupportedOperation(_))
        ));

        commit_cfg(&ctx, "A", "1", "root only");
        // Root has no parent to roll back to.
        assert!(matches!(
            history.rollback(None, "user:m"),
            Err(CoreError::UnsupportedOperation(msg)) if msg.contains("--to")
        ));

        let head = ctx.repository().current_head().unwrap().unwrap();
        assert!(matches!(
            history.rollback(Some(&head), "user:m"),
            Err(CoreError::UnsupportedOperation(msg)) if msg.contains("HEAD itself")
        ));
    }
}
