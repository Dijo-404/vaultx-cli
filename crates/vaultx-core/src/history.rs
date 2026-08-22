//! [`HistoryService`]: commits, history inspection, diffs, branches, and
//! commit-signature verification.
//!
//! # Device signing identity (dev-mode contract)
//!
//! Commits are Ed25519-signed. v1 uses a **process-local signing
//! keypair**:
//!
//! * The first commit in a process generates a fresh keypair and persists
//!   its *verifying half* to `.vaultx/device.pub` (hex-encoded compressed
//!   Ed25519 public key). The pair is then reused for every commit in that
//!   process.
//! * [`HistoryService::verify_head_signature`] validates the head commit's
//!   signature against `.vaultx/device.pub`.
//!
//! **Limitation (documented deferral):** the private seed cannot be
//! persisted yet because `vaultx_crypto::signature::SigningKeyPair` v1
//! exposes neither a seed constructor nor seed extraction. Consequently a
//! new process session rotates the signing identity: older commits stop
//! verifying against the refreshed `device.pub` until the platform-keyring
//! integration task lands and honors a durable private key. The
//! `device.pub` file format is final; only private-half storage is
//! deferred.

use std::path::PathBuf;
use std::sync::{Arc, PoisonError};

use vaultx_crypto::signature::{SigningKeyPair, VerifyingPublicKey};
use vaultx_repository::{DiffEntry, ManifestEntry, StagingIndex};
use vaultx_types::model::VariableKind;
use vaultx_types::{CommitId, IdentityRef};

use crate::error::CoreResult;
use crate::project::ProjectContext;

/// File holding the hex-encoded verifying key of the active device signer.
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

    fn device_pub_path(&self) -> PathBuf {
        self.ctx.vault_dir().join(DEVICE_PUB_FILE)
    }

    /// Returns the per-process signing identity, initializing it (and
    /// persisting `device.pub`) on first use. See the module docs for the
    /// rotation caveat.
    fn signing_pair(&self) -> CoreResult<Arc<SigningKeyPair>> {
        let mut slot = self
            .ctx
            .device_pair_slot
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(pair) = slot.as_ref() {
            return Ok(Arc::clone(pair));
        }
        let pair = Arc::new(SigningKeyPair::generate());
        let public_hex = hex::encode(pair.verifying_public_key().to_bytes());
        // Publish atomically (temp file + rename) mirroring repository
        // conventions so readers never observe partial content.
        let path = self.device_pub_path();
        let tmp = path.with_file_name(format!(".tmp-device-pub-{}", std::process::id()));
        std::fs::write(&tmp, format!("{public_hex}\n"))?;
        std::fs::rename(&tmp, &path)?;
        *slot = Some(Arc::clone(&pair));
        Ok(pair)
    }

    /// Creates a signed commit from the staging index.
    ///
    /// The author string is validated as an [`IdentityRef`]; the signature
    /// comes from the process device identity (see module docs).
    ///
    /// # Errors
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
