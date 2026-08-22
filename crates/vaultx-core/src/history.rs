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
use vaultx_repository::{DiffEntry, ManifestEntry, StagingIndex};
use vaultx_types::model::VariableKind;
use vaultx_types::{CommitId, IdentityRef};

use crate::error::{CoreError, CoreResult};
use crate::project::ProjectContext;

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
}
