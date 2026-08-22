//! The staging index: intended manifest changes awaiting a commit.
//!
//! The index is persisted as canonical JSON at `.vaultx/index.json` and
//! records, per [`VariableName`], either a full replacement
//! ([`StagedChange::Set`]) or a deletion ([`StagedChange::Remove`]). It is
//! the only place where intended changes live between sessions, so writes
//! are atomic (temp file + rename) and reloads are exact.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use vaultx_types::VariableName;

use crate::error::RepoError;
use crate::manifest::{Manifest, ManifestEntry};

/// A single intended change to one variable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum StagedChange {
    /// Replace (or introduce) the variable with this entry.
    Set(ManifestEntry),
    /// Delete the variable.
    Remove,
}

impl StagedChange {
    /// The entry being set, if this change is a `Set`.
    #[must_use]
    pub fn as_entry(&self) -> Option<&ManifestEntry> {
        match self {
            Self::Set(entry) => Some(entry),
            Self::Remove => None,
        }
    }
}

/// Persisted staging index mapping variable names to intended changes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StagingIndex {
    entries: BTreeMap<VariableName, StagedChange>,
}

impl StagingIndex {
    /// Loads the index from `.vaultx/index.json` rooted at `vault_dir`.
    ///
    /// A missing file yields an empty index; a present-but-unparseable file
    /// is an error rather than silent data loss.
    ///
    /// # Errors
    /// [`RepoError::Json`] when the stored index cannot be decoded.
    pub fn load(vault_dir: impl AsRef<Path>) -> Result<Self, RepoError> {
        let path = vault_dir.as_ref().join("index.json");
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(&path)?;
        let entries: BTreeMap<VariableName, StagedChange> = serde_json::from_str(&raw)?;
        Ok(Self { entries })
    }

    /// Persists the index atomically to `.vaultx/index.json`.
    ///
    /// # Errors
    /// Propagates I/O / JSON failures.
    pub fn save(&self, vault_dir: impl AsRef<Path>) -> Result<(), RepoError> {
        let path = vault_dir.as_ref().join("index.json");
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let temp_path = path.with_file_name(format!(
            ".tmp-index-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::write(&temp_path, serde_json::to_string_pretty(self.entries())?)?;
        std::fs::rename(&temp_path, &path)?;
        Ok(())
    }

    /// Records (or overwrites) the staged intent for `name`.
    pub fn stage(&mut self, name: VariableName, change: StagedChange) {
        self.entries.insert(name, change);
    }

    /// Drops any staged intent for `name`; returns whether one existed.
    pub fn unstage(&mut self, name: &VariableName) -> bool {
        self.entries.remove(name).is_some()
    }

    /// Empties the entire index.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Snapshot of all staged intents, sorted by variable name.
    #[must_use]
    pub fn list(&self) -> Vec<(&VariableName, &StagedChange)> {
        self.entries.iter().collect()
    }

    /// Borrowed view of the underlying map.
    #[must_use]
    pub fn entries(&self) -> &BTreeMap<VariableName, StagedChange> {
        &self.entries
    }

    /// True when nothing is staged.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Number of variables with staged intent.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Applies every staged change onto `manifest`, returning a new
    /// manifest. The staging index itself is left untouched — clearing it
    /// is the caller's decision after a successful commit.
    #[must_use]
    pub fn apply_onto(&self, base: &Manifest) -> Manifest {
        let mut next = base.clone();
        for (name, change) in &self.entries {
            match change {
                StagedChange::Set(entry) => {
                    next.entries.insert(name.clone(), entry.clone());
                }
                StagedChange::Remove => {
                    next.entries.remove(name);
                }
            }
        }
        next
    }

    /// Path helper for tests and diagnostics.
    #[must_use]
    pub fn path_for(vault_dir: impl AsRef<Path>) -> PathBuf {
        vault_dir.as_ref().join("index.json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{DynamicProviderRef, Manifest};
    use vaultx_types::{CredentialRef, ObjectId, SecretRevisionId};

    fn var(name: &str) -> VariableName {
        VariableName::parse(name).unwrap()
    }

    fn config_entry(id: &str) -> ManifestEntry {
        ManifestEntry::Config {
            object: ObjectId::parse(id).unwrap(),
        }
    }

    #[test]
    fn stage_unstage_clear_and_len_behave() {
        let mut index = StagingIndex::default();
        assert!(index.is_empty());

        index.stage(var("A"), StagedChange::Set(config_entry("obj_a")));
        index.stage(var("B"), StagedChange::Remove);
        assert_eq!(index.len(), 2);

        // Re-staging same name replaces intent.
        index.stage(var("A"), StagedChange::Set(config_entry("obj_a2")));
        assert_eq!(index.len(), 2);
        assert_eq!(
            index.entries()[&var("A")],
            StagedChange::Set(config_entry("obj_a2"))
        );

        assert!(index.unstage(&var("B")));
        assert!(!index.unstage(&var("B")));
        assert_eq!(index.len(), 1);

        index.clear();
        assert!(index.is_empty());
        assert!(index.list().is_empty());
    }

    #[test]
    fn persistence_round_trips_across_reload() {
        let dir = tempfile::tempdir().unwrap();

        let mut first = StagingIndex::load(dir.path()).unwrap();
        assert!(first.is_empty(), "missing file means empty index");

        first.stage(var("DB_HOST"), StagedChange::Set(config_entry("obj_host")));
        first.stage(
            var("API_TOKEN"),
            StagedChange::Set(ManifestEntry::Brokered {
                credential: CredentialRef::parse("github-token").unwrap(),
                revision: SecretRevisionId::parse("sec_rev_3").unwrap(),
            }),
        );
        first.stage(var("OLD_VAR"), StagedChange::Remove);
        first.save(dir.path()).unwrap();

        let reloaded = StagingIndex::load(dir.path()).unwrap();
        assert_eq!(reloaded, first);
        assert_eq!(reloaded.len(), 3);
    }

    #[test]
    fn corrupt_index_file_is_an_error_not_silent_reset() {
        let dir = tempfile::tempdir().unwrap();
        let path = StagingIndex::path_for(&dir);
        std::fs::write(&path, "{not json").unwrap();
        assert!(matches!(
            StagingIndex::load(dir.path()),
            Err(RepoError::Json(_))
        ));
    }

    #[test]
    fn apply_onto_produces_expected_manifest() {
        let mut base = Manifest::new();
        base.set_config(var("KEEP"), ObjectId::parse("obj_keep").unwrap());
        base.set_config(var("DROP"), ObjectId::parse("obj_drop").unwrap());
        base.set_config(var("CHANGE"), ObjectId::parse("obj_old").unwrap());

        let mut index = StagingIndex::default();
        index.stage(var("DROP"), StagedChange::Remove);
        index.stage(var("CHANGE"), StagedChange::Set(config_entry("obj_new")));
        index.stage(var("NEW"), StagedChange::Set(config_entry("obj_new_var")));

        let merged = index.apply_onto(&base);
        assert_eq!(
            merged.get(&var("KEEP")),
            Some(&ManifestEntry::Config {
                object: ObjectId::parse("obj_keep").unwrap()
            })
        );
        assert!(merged.get(&var("DROP")).is_none());
        assert_eq!(merged.get(&var("CHANGE")), Some(&config_entry("obj_new")));
        assert_eq!(merged.get(&var("NEW")), Some(&config_entry("obj_new_var")));

        // Base manifest untouched by apply.
        assert!(base.get(&var("DROP")).is_some());
    }

    #[test]
    fn dynamic_provider_entries_survive_serialization() {
        let dir = tempfile::tempdir().unwrap();
        let mut index = StagingIndex::default();
        index.stage(
            var("EPHEMERAL"),
            StagedChange::Set(ManifestEntry::Dynamic {
                provider: DynamicProviderRef::parse("broker/dynamic-postgres").unwrap(),
            }),
        );
        index.save(dir.path()).unwrap();
        let reloaded = StagingIndex::load(dir.path()).unwrap();
        assert_eq!(reloaded, index);
    }

    #[test]
    fn staged_change_json_is_tagged_and_stable() {
        let remove = StagedChange::Remove;
        assert_eq!(
            serde_json::to_string(&remove).unwrap(),
            "{\"op\":\"remove\"}"
        );
        let set = StagedChange::Set(ManifestEntry::Secret {
            revision: SecretRevisionId::parse("sec_rev_9").unwrap(),
        });
        assert_eq!(
            serde_json::to_string(&set).unwrap(),
            "{\"op\":\"set\",\"kind\":\"secret\",\"revision\":\"sec_rev_9\"}"
        );
    }
}
