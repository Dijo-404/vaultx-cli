//! [`RecoveryService`]: plan §Recovery read-mostly integrity auditing and
//! conservative ref repair.
//!
//! Three validation categories, grouped in one report:
//!
//! * every ref resolves to an existing commit,
//! * commit signatures verify along history against the device key
//!   (`.vaultx/device.pub`), including resolvable parent chains,
//! * every secret revision referenced by any reachable manifest has a
//!   record under `.vaultx/secrets/` (destroyed revisions count as
//!   present — they are intentionally unrecoverable, not missing).
//!
//! `--fix` deletes only refs whose targets are unresolvable, after the
//! CLI layer has obtained explicit confirmation. Objects are never
//! mutated (INV-013: destruction/repair never requires history
//! mutation), and encrypted-backup import is out of scope.

use std::collections::{BTreeMap, BTreeSet};

use vaultx_crypto::signature::VerifyingPublicKey;
use vaultx_repository::history::History;
use vaultx_repository::{ManifestEntry, RefNamespace};
use vaultx_types::{CommitId, SecretRevisionId};

use crate::error::CoreResult;
use crate::history::DEVICE_PUB_FILE;
use crate::project::ProjectContext;
use crate::secrets::SecretService;

/// A ref whose target commit cannot be resolved from the object store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnresolvableRef {
    /// Ref namespace label (`heads` / `environments`).
    pub namespace: &'static str,
    /// Ref name within its namespace.
    pub name: String,
    /// Target that failed to resolve.
    pub commit: CommitId,
}

/// One signature/graph finding along a walked history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureFinding {
    /// Commit the finding is about; `None` when the device verifying key
    /// itself is unusable.
    pub commit: Option<CommitId>,
    /// Secret-free reason string.
    pub reason: String,
}

/// Grouped findings of one audit pass.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    /// Refs pointing at commits absent from the object store.
    pub unresolvable_refs: Vec<UnresolvableRef>,
    /// Signature or graph-integrity failures along reachable history.
    pub signature_failures: Vec<SignatureFinding>,
    /// `(variable, revision)` pairs referenced by manifests with no
    /// backing record. Deduplicated.
    pub missing_secret_revisions: Vec<(String, SecretRevisionId)>,
}

impl RecoveryReport {
    /// True when every category is empty.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.unresolvable_refs.is_empty()
            && self.signature_failures.is_empty()
            && self.missing_secret_revisions.is_empty()
    }

    /// Total number of findings across all categories.
    #[must_use]
    pub fn len(&self) -> usize {
        self.unresolvable_refs.len()
            + self.signature_failures.len()
            + self.missing_secret_revisions.len()
    }

    /// Whether anything at all was reported.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Recovery audit and conservative ref repair over one project.
#[derive(Clone, Copy, Debug)]
pub struct RecoveryService<'a> {
    ctx: &'a ProjectContext,
}

impl<'a> RecoveryService<'a> {
    /// Builds a service operating on `ctx`.
    #[must_use]
    pub const fn new(ctx: &'a ProjectContext) -> Self {
        Self { ctx }
    }

    /// Runs every validation category and returns the grouped findings.
    ///
    /// # Errors
    /// * Propagates ref-listing and record-scan failures.
    pub fn audit(&self) -> CoreResult<RecoveryReport> {
        let repo = self.ctx.repository();
        let history = History::new(repo.objects());
        let mut report = RecoveryReport::default();

        // Category 1 + collection of walk roots.
        let mut tips: Vec<CommitId> = Vec::new();
        for (namespace, label) in [
            (RefNamespace::Heads, "heads"),
            (RefNamespace::Environments, "environments"),
        ] {
            for (name, commit) in repo.refs().list_refs(namespace)? {
                if history.find_commit(&commit).is_err() {
                    report.unresolvable_refs.push(UnresolvableRef {
                        namespace: label,
                        name,
                        commit,
                    });
                } else {
                    tips.push(commit);
                }
            }
        }

        // Load the device verifying key once; without it signatures along
        // history cannot be checked, which is itself a single finding.
        let public = self.load_device_public_key();
        if public.is_none() && !tips.is_empty() {
            report.signature_failures.push(SignatureFinding {
                commit: None,
                reason: format!(
                    "device verifying key (.vaultx/{DEVICE_PUB_FILE}) is unusable; \
                     signatures along history could not be checked"
                ),
            });
        }

        let mut visited: BTreeSet<CommitId> = BTreeSet::new();
        let mut missing_revisions: BTreeMap<String, BTreeSet<SecretRevisionId>> = BTreeMap::new();
        let secrets = SecretService::new(self.ctx);

        for tip in &tips {
            let mut queue = vec![tip.clone()];
            while let Some(id) = queue.pop() {
                if !visited.insert(id.clone()) {
                    continue;
                }
                let Ok(commit) = history.find_commit(&id) else {
                    report.signature_failures.push(SignatureFinding {
                        commit: Some(id),
                        reason: "commit object unresolvable".to_owned(),
                    });
                    continue;
                };
                if let Some(key) = public.as_ref() {
                    if let Err(err) = commit.verify(key) {
                        report.signature_failures.push(SignatureFinding {
                            commit: Some(id.clone()),
                            reason: err.to_string(),
                        });
                    }
                }
                for parent in &commit.parents {
                    if history.find_commit(parent).is_err() {
                        report.signature_failures.push(SignatureFinding {
                            commit: Some(id.clone()),
                            reason: format!("declared parent {parent} is unresolvable"),
                        });
                    } else {
                        queue.push(parent.clone());
                    }
                }
                self.collect_manifest_findings(&secrets, &id, &mut missing_revisions, &mut report)?;
            }
        }

        for (name, revisions) in missing_revisions {
            for revision in revisions {
                report
                    .missing_secret_revisions
                    .push((name.clone(), revision));
            }
        }
        Ok(report)
    }

    /// Records manifest-decode problems as signature-category findings and
    /// gathers secret revisions whose records are absent. Destroyed
    /// revisions are present records and never reported here.
    fn collect_manifest_findings(
        &self,
        secrets: &SecretService<'a>,
        commit_id: &CommitId,
        missing: &mut BTreeMap<String, BTreeSet<SecretRevisionId>>,
        report: &mut RecoveryReport,
    ) -> CoreResult<()> {
        let manifest = match self.ctx.repository().manifest_at(commit_id) {
            Ok(manifest) => manifest,
            Err(err) => {
                report.signature_failures.push(SignatureFinding {
                    commit: Some(commit_id.clone()),
                    reason: format!("manifest unreadable: {err}"),
                });
                return Ok(());
            }
        };
        for (name, entry) in &manifest.entries {
            let revision = match entry {
                ManifestEntry::Secret { revision } | ManifestEntry::Brokered { revision, .. } => {
                    revision
                }
                _ => continue,
            };
            if secrets.revision_state(revision)?.is_none() {
                missing
                    .entry(name.to_string())
                    .or_default()
                    .insert(revision.clone());
            }
        }
        Ok(())
    }

    fn load_device_public_key(&self) -> Option<VerifyingPublicKey> {
        let text = std::fs::read_to_string(self.ctx.vault_dir().join(DEVICE_PUB_FILE)).ok()?;
        let bytes: [u8; 32] = hex::decode(text.trim()).ok()?.try_into().ok()?;
        VerifyingPublicKey::from_bytes(&bytes).ok()
    }

    /// Deletes exactly the listed refs after the caller has confirmed
    /// them. Branch deletion forces past the HEAD-checked-out guard, and
    /// environment deletion forces past protection: both require the same
    /// explicit operator consent that produced this list. Objects are
    /// never touched.
    ///
    /// Returns the number of refs actually removed.
    ///
    /// # Errors
    /// * Propagates ref-store failures.
    pub fn fix_unresolvable_refs(&self, targets: &[UnresolvableRef]) -> CoreResult<usize> {
        let refs = self.ctx.repository().refs();
        let mut removed = 0;
        for target in targets {
            match target.namespace {
                "heads" => {
                    refs.delete_ref(RefNamespace::Heads, &target.name, true)?;
                }
                _ => {
                    refs.delete_env_ref(&target.name, true)?;
                }
            }
            removed += 1;
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::ConfigService;
    use crate::history::HistoryService;
    use vaultx_crypto::signature::SigningKeyPair;
    use vaultx_repository::history::History as RepoHistory;
    use vaultx_types::model::VariableKind;

    struct Fixture {
        _dir: tempfile::TempDir,
        ctx: ProjectContext,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ProjectContext::init(dir.path()).unwrap();
        Fixture { _dir: dir, ctx }
    }

    /// Commits one config value plus one plain secret at HEAD so history
    /// walking, signature checks, and revision lookups all have material.
    fn seed(fx: &Fixture) {
        ConfigService::new(&fx.ctx)
            .set_config("PORT", "8080")
            .unwrap();
        SecretService::new(&fx.ctx)
            .set_secret(
                "DB_PASSWORD",
                &crate::SecretString::copy_from("hunter2"),
                VariableKind::Secret,
                "development",
                None,
            )
            .unwrap();
        HistoryService::new(&fx.ctx)
            .commit("seed", "user:t")
            .unwrap();
    }

    fn repo(fx: &Fixture) -> &vaultx_repository::Repository {
        fx.ctx.repository()
    }

    fn ghost_commit(suffix: u8) -> CommitId {
        let mut hex = "1111111122222222333333334444444455555555666666667777777788888888".to_owned();
        hex.replace_range(..2, &format!("{suffix:02x}"));
        CommitId::parse(&format!("cmt_{hex}")).unwrap()
    }

    #[test]
    fn healthy_history_is_clean() {
        let fx = fixture();
        seed(&fx);

        let report = RecoveryService::new(&fx.ctx).audit().unwrap();
        assert!(report.is_clean(), "{report:?}");
        assert_eq!(report.len(), 0);
        // Repairing nothing is a no-op success.
        assert_eq!(
            RecoveryService::new(&fx.ctx)
                .fix_unresolvable_refs(&[])
                .unwrap(),
            0
        );
    }

    #[test]
    fn unresolvable_refs_are_detected_and_fix_removes_only_them() {
        let fx = fixture();
        seed(&fx);
        let head = HistoryService::new(&fx.ctx).log(1).unwrap()[0].id.clone();

        // One severed branch ref and one severed environment ref; main
        // stays healthy throughout.
        let broken_branch = ghost_commit(0xAB);
        let broken_env = ghost_commit(0xCD);
        repo(&fx)
            .refs()
            .write_ref(RefNamespace::Heads, "broken", &broken_branch)
            .unwrap();
        repo(&fx)
            .refs()
            .write_env_ref("ghostenv", &broken_env, true)
            .unwrap();

        let report = RecoveryService::new(&fx.ctx).audit().unwrap();
        assert_eq!(report.unresolvable_refs.len(), 2, "{report:?}");
        assert!(report.unresolvable_refs.contains(&UnresolvableRef {
            namespace: "heads",
            name: "broken".to_owned(),
            commit: broken_branch.clone(),
        }));
        assert!(report.unresolvable_refs.contains(&UnresolvableRef {
            namespace: "environments",
            name: "ghostenv".to_owned(),
            commit: broken_env,
        }));
        assert!(!report.is_clean());

        // Fix deletes exactly the listed refs — including past HEAD/
        // protection guards — and never touches objects (INV-013).
        let targets = report.unresolvable_refs.clone();
        let removed = RecoveryService::new(&fx.ctx)
            .fix_unresolvable_refs(&targets)
            .unwrap();
        assert_eq!(removed, 2);
        assert!(repo(&fx)
            .refs()
            .read_ref(RefNamespace::Heads, "broken")
            .unwrap()
            .is_none());
        assert!(repo(&fx)
            .refs()
            .read_ref(RefNamespace::Environments, "ghostenv")
            .unwrap()
            .is_none());
        assert!(repo(&fx)
            .refs()
            .read_ref(RefNamespace::Heads, "main")
            .unwrap()
            .is_some());
        repo(&fx).objects().verify_all().unwrap();

        let after = RecoveryService::new(&fx.ctx).audit().unwrap();
        assert!(after.is_clean(), "{after:?}");
        let _ = head;
    }

    #[test]
    fn foreign_signature_fails_verification_across_history() {
        let fx = fixture();
        seed(&fx);

        // Forge a resolvable commit sharing the real HEAD manifest but
        // signed by a stranger key; object integrity holds while signature
        // verification must fail against the device key.
        let head = HistoryService::new(&fx.ctx).log(1).unwrap()[0].id.clone();
        let manifest_id = RepoHistory::new(repo(&fx).objects())
            .find_commit(&head)
            .unwrap()
            .manifest;
        let forged = vaultx_repository::Commit::new(
            Vec::new(),
            manifest_id,
            vaultx_types::IdentityRef::parse("user:stranger").unwrap(),
            "forged",
        )
        .sign_with(&SigningKeyPair::generate())
        .unwrap();
        let envelope = vaultx_repository::ObjectEnvelope::new(
            vaultx_repository::ObjectType::Commit,
            serde_json::to_vec(&forged).unwrap(),
        );
        repo(&fx).objects().put(&envelope).unwrap();
        repo(&fx)
            .refs()
            .write_ref(RefNamespace::Heads, "forged", &forged.commit_id().unwrap())
            .unwrap();

        let report = RecoveryService::new(&fx.ctx).audit().unwrap();
        assert!(report.unresolvable_refs.is_empty(), "{report:?}");
        assert_eq!(report.signature_failures.len(), 1, "{report:?}");
        assert_eq!(
            report.signature_failures[0].commit.as_ref(),
            Some(&forged.commit_id().unwrap())
        );
        assert!(
            report.signature_failures[0]
                .reason
                .contains("signature invalid"),
            "{:?}",
            report.signature_failures[0]
        );

        // The legit tip still verifies: only the foreign commit is named.
        let clean_ids: Vec<_> = report
            .signature_failures
            .iter()
            .filter_map(|f| f.commit.as_ref())
            .collect();
        assert!(!clean_ids.contains(&&head));
    }

    #[test]
    fn missing_secret_revisions_are_reported_but_destroyed_are_not() {
        let fx = fixture();
        seed(&fx);
        SecretService::new(&fx.ctx)
            .set_secret(
                "KEEP_ME",
                &crate::SecretString::copy_from("still-here"),
                VariableKind::Secret,
                "development",
                None,
            )
            .unwrap();
        HistoryService::new(&fx.ctx)
            .commit("second", "user:t")
            .unwrap();

        // Destroy KEEP_ME's record state but keep the file present...
        SecretService::new(&fx.ctx)
            .destroy_secret("KEEP_ME", "development")
            .unwrap();
        // ...while DB_PASSWORD's record is deleted outright (located via
        // its metadata so the right record file goes).
        let meta = SecretService::new(&fx.ctx)
            .secret_metadata("DB_PASSWORD", "development")
            .unwrap();
        let record_path = fx
            .ctx
            .vault_dir()
            .join("secrets")
            .join(meta.secret_id.as_str())
            .join(format!("{}.json", meta.current_revision.as_str()));
        std::fs::remove_file(record_path).unwrap();

        let report = RecoveryService::new(&fx.ctx).audit().unwrap();
        let missing: Vec<_> = report
            .missing_secret_revisions
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();
        assert!(missing.contains(&"DB_PASSWORD"), "{report:?}");
        // Destroyed revisions keep their records: intentionally
        // unrecoverable is not missing.
        assert!(!missing.contains(&"KEEP_ME"), "{report:?}");
        assert!(!report.is_clean());

        // Findings never carry value material (INV-012).
        let rendered_names = format!("{report:?}");
        assert!(!rendered_names.contains("hunter2"));
        assert!(!rendered_names.contains("still-here"));
    }
}
