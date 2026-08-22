//! [`ConfigService`]: non-secret configuration variable operations.
//!
//! # Storage model
//!
//! A config value is stored twice, mirroring the repository design:
//!
//! 1. the value itself lives in a content-addressed
//!    [`ObjectEnvelope`] of type [`ObjectType::ConfigValue`] whose payload
//!    is canonical JSON `{"value": <string>}`;
//! 2. a [`ManifestEntry::Config`] binding the variable name to that object
//!    ID is staged into the manifest (and lands in history on commit).
//!
//! # Deferred: secret values
//!
//! Secret *values* are intentionally out of scope for v1 core services:
//! secret-bearing manifest entries (`Secret` / `Brokered`) reference
//! revision IDs only, and no API here writes plaintext secret material.
//! The vault layer materializing those revisions arrives in a later task;
//! until then `import_env_pairs` reports likely secrets instead of storing
//! them.
//!
//! # HEAD vs. staging semantics
//!
//! [`ConfigService::get_config`] resolves through the **staging overlay
//! first**, then the HEAD manifest, so `set` followed by `get` returns the
//! pending value without an intervening commit. [`ConfigService::list_configs`]
//! deliberately reflects the **HEAD manifest only**: staged changes stay
//! visible via status/diff instead (the plan's explicit decision), keeping
//! "what is committed" queryable while edits are in flight.

use serde_json::Value;

use vaultx_repository::{ManifestEntry, ObjectEnvelope, ObjectType, StagedChange, StagingIndex};
use vaultx_types::VariableName;

use crate::error::{CoreError, CoreResult};
use crate::project::ProjectContext;

/// JSON key holding the config value inside a `ConfigValue` object
/// payload.
const VALUE_KEY: &str = "value";

/// Report of an `.env`-style import pass.
///
/// Likely-secret names are **never** persisted by this crate; they are
/// listed in [`ImportReport::needs_secret`] so the caller can prompt for
/// `vaultx secret set` once the vault layer exists.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ImportReport {
    /// Names imported as plain config values.
    pub added_config: Vec<String>,
    /// Names classified as likely secrets and deliberately not stored.
    pub needs_secret: Vec<String>,
    /// Names already bound (HEAD manifest or staging index) and skipped.
    pub skipped_existing: Vec<String>,
    /// Names failing [`VariableName`] validation and skipped.
    pub skipped_invalid: Vec<String>,
}

/// Configuration operations: set / get / unset / list plus conservative
/// `.env` import classification.
#[derive(Clone, Copy, Debug)]
pub struct ConfigService<'a> {
    ctx: &'a ProjectContext,
}

impl<'a> ConfigService<'a> {
    /// Builds a service operating on `ctx`.
    #[must_use]
    pub const fn new(ctx: &'a ProjectContext) -> Self {
        Self { ctx }
    }

    fn parse_name(&self, name: &str) -> CoreResult<VariableName> {
        VariableName::parse(name).map_err(|_| CoreError::InvalidVariableName(name.to_owned()))
    }

    /// Validates, stores, and stages one config value.
    ///
    /// The change is staged immediately; call
    /// [`crate::history::HistoryService::commit`] to persist it into
    /// history.
    ///
    /// # Errors
    /// * [`CoreError::InvalidVariableName`] when `name` fails validation.
    /// * Propagates object-store and staging failures.
    pub fn set_config(&self, name: &str, value: &str) -> CoreResult<()> {
        let parsed = self.parse_name(name)?;
        self.set_config_parsed(parsed, value)
    }

    fn set_config_parsed(&self, name: VariableName, value: &str) -> CoreResult<()> {
        let payload = serde_json::json!({ VALUE_KEY: value });
        let envelope = ObjectEnvelope::new(ObjectType::ConfigValue, serde_json::to_vec(&payload)?);
        let object = self.ctx.repository().objects().put(&envelope)?;
        self.ctx
            .repository()
            .add(name, ManifestEntry::Config { object })?;
        Ok(())
    }

    /// Reads a config value.
    ///
    /// Lookup order: the **staging overlay first** (so `set` followed by
    /// `get` returns the pending value without an intervening commit),
    /// then the HEAD manifest. A staged removal makes the variable read as
    /// absent even if HEAD still binds it.
    ///
    /// # Errors
    /// * [`CoreError::InvalidVariableName`] on malformed names.
    /// * [`CoreError::VariableNotFound`] when unbound after overlay+HEAD.
    /// * [`CoreError::UnsupportedOperation`] when the entry is not a plain
    ///   config value or its object payload is malformed.
    pub fn get_config(&self, name: &str) -> CoreResult<String> {
        let parsed = self.parse_name(name)?;
        let entry = self.resolve_effective_entry(&parsed, name)?;
        let object = match entry {
            ManifestEntry::Config { object } => object,
            other => {
                return Err(CoreError::UnsupportedOperation(format!(
                    "variable `{name}` is bound to a non-config entry ({:?})",
                    other.kind()
                )));
            }
        };
        self.read_config_object(&object)
    }

    fn resolve_effective_entry(
        &self,
        parsed: &VariableName,
        raw: &str,
    ) -> CoreResult<ManifestEntry> {
        let staged = StagingIndex::load(self.ctx.vault_dir())?;
        if let Some(change) = staged.entries().get(parsed) {
            return match change {
                StagedChange::Set(entry) => Ok(entry.clone()),
                StagedChange::Remove => Err(CoreError::VariableNotFound(raw.to_owned())),
            };
        }
        self.ctx
            .repository()
            .working_manifest()?
            .get(parsed)
            .cloned()
            .ok_or_else(|| CoreError::VariableNotFound(raw.to_owned()))
    }

    fn read_config_object(&self, object: &vaultx_types::ObjectId) -> CoreResult<String> {
        let envelope = self.ctx.repository().objects().get(object)?;
        if envelope.object_type != ObjectType::ConfigValue {
            return Err(CoreError::Repo(
                vaultx_repository::RepoError::CorruptObject {
                    id: object.clone(),
                    reason: format!(
                        "expected a config-value object, found {:?}",
                        envelope.object_type
                    ),
                },
            ));
        }
        let payload: Value = envelope.decode_payload()?;
        payload
            .get(VALUE_KEY)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| {
                CoreError::Repo(vaultx_repository::RepoError::CorruptObject {
                    id: object.clone(),
                    reason: "config-value payload lacks a string `value` field".to_owned(),
                })
            })
    }

    /// Stages removal of a config variable.
    ///
    /// The name must be bound at HEAD or carry a staged `Set` intent;
    /// otherwise nothing is known about it and removal is refused.
    ///
    /// # Errors
    /// * [`CoreError::InvalidVariableName`] on malformed names.
    /// * [`CoreError::VariableNotFound`] when neither HEAD nor the staging
    ///   index knows the name.
    pub fn unset_config(&self, name: &str) -> CoreResult<()> {
        let parsed = self.parse_name(name)?;
        let head_has_it = self
            .ctx
            .repository()
            .working_manifest()?
            .get(&parsed)
            .is_some();
        let staged_has_it = StagingIndex::load(self.ctx.vault_dir())?
            .entries()
            .contains_key(&parsed);
        if !head_has_it && !staged_has_it {
            return Err(CoreError::VariableNotFound(name.to_owned()));
        }
        self.ctx
            .repository()
            .stage_change(parsed, StagedChange::Remove)?;
        Ok(())
    }

    /// Lists all config variables bound at the HEAD manifest with their
    /// resolved values, sorted by name.
    ///
    /// Staged changes are intentionally excluded (see module docs).
    ///
    /// # Errors
    /// * Propagates manifest/object lookup failures.
    pub fn list_configs(&self) -> CoreResult<Vec<(VariableName, String)>> {
        let manifest = self.ctx.repository().working_manifest()?;
        let mut configs = Vec::new();
        for (name, entry) in &manifest.entries {
            if let ManifestEntry::Config { object } = entry {
                configs.push((name.clone(), self.read_config_object(object)?));
            }
        }
        Ok(configs)
    }

    /// Imports key/value pairs using the plan §33 conservative classifier:
    /// names matching likely-secret patterns are reported via
    /// [`ImportReport::needs_secret`] and never stored; everything else is
    /// stored as config unless already bound (HEAD or staged).
    ///
    /// Likely-secret patterns: `*_TOKEN`, `*_KEY`, `*_SECRET`,
    /// `*_PASSWORD`, `*_PRIVATE_KEY`, and the exact name `DATABASE_URL`.
    ///
    /// # Errors
    /// * Propagates storage failures from accepted pairs.
    pub fn import_env_pairs<'p>(
        &self,
        pairs: impl IntoIterator<Item = (&'p str, &'p str)>,
    ) -> CoreResult<ImportReport> {
        let mut report = ImportReport::default();
        let head = self.ctx.repository().working_manifest()?;
        let staged = StagingIndex::load(self.ctx.vault_dir())?;

        for (raw_name, raw_value) in pairs {
            let Ok(parsed) = VariableName::parse(raw_name) else {
                report.skipped_invalid.push(raw_name.to_owned());
                continue;
            };
            if is_likely_secret_name(parsed.as_str()) {
                // Never persist candidate secret material in v1: report it
                // so the operator can run `vaultx secret set` later.
                report.needs_secret.push(raw_name.to_owned());
                continue;
            }
            let exists = head.get(&parsed).is_some() || staged.entries().contains_key(&parsed);
            if exists {
                report.skipped_existing.push(raw_name.to_owned());
                continue;
            }
            self.set_config_parsed(parsed, raw_value)?;
            report.added_config.push(raw_name.to_owned());
        }
        Ok(report)
    }
}

/// Conservative plan §33 secret-name heuristic.
fn is_likely_secret_name(name: &str) -> bool {
    if name == "DATABASE_URL" {
        return true;
    }
    ["_TOKEN", "_KEY", "_SECRET", "_PASSWORD", "_PRIVATE_KEY"]
        .iter()
        .any(|suffix| name.ends_with(suffix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::HistoryService;

    fn temp_ctx() -> (tempfile::TempDir, ProjectContext) {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ProjectContext::init(dir.path()).unwrap();
        (dir, ctx)
    }

    #[test]
    fn set_get_unset_list_cycle_persists_across_reopen() {
        let (_guard, ctx) = temp_ctx();
        let config = ConfigService::new(&ctx);

        config.set_config("DB_HOST", "db.internal").unwrap();
        assert_eq!(config.get_config("DB_HOST").unwrap(), "db.internal");
        // Listing reflects HEAD only, so it is still empty pre-commit.
        assert!(config.list_configs().unwrap().is_empty());

        HistoryService::new(&ctx)
            .commit("first", "user:test")
            .unwrap();
        assert_eq!(
            config.list_configs().unwrap(),
            vec![(
                VariableName::parse("DB_HOST").unwrap(),
                "db.internal".to_owned()
            )]
        );

        // Reopen: committed values survive the process boundary.
        let reopened = ProjectContext::open(ctx.root()).unwrap();
        let config = ConfigService::new(&reopened);
        assert_eq!(config.get_config("DB_HOST").unwrap(), "db.internal");

        // Uncommitted set + unset of the committed variable.
        config.set_config("PORT", "8080").unwrap();
        config.unset_config("DB_HOST").unwrap();

        let status = crate::staging::StagingService::new(&reopened)
            .status()
            .unwrap();
        assert!(status
            .staged_changes
            .iter()
            .any(|(name, kind)| name.as_str() == "DB_HOST"
                && *kind == crate::staging::StagedChangeKind::Remove));
        assert!(status
            .staged_changes
            .iter()
            .any(|(name, _)| name.as_str() == "PORT"));

        HistoryService::new(&reopened)
            .commit("second", "user:test")
            .unwrap();

        let final_ctx = ProjectContext::open(ctx.root()).unwrap();
        let config = ConfigService::new(&final_ctx);
        assert!(matches!(
            config.get_config("DB_HOST"),
            Err(CoreError::VariableNotFound(_))
        ));
        assert_eq!(config.get_config("PORT").unwrap(), "8080");
        assert_eq!(
            config
                .list_configs()
                .unwrap()
                .iter()
                .map(|(n, _)| n.as_str())
                .collect::<Vec<_>>(),
            vec!["PORT"]
        );

        // Error paths.
        assert!(matches!(
            config.get_config("TOTALLY_MISSING"),
            Err(CoreError::VariableNotFound(_))
        ));
        assert!(matches!(
            config.set_config("lower-case", "x"),
            Err(CoreError::InvalidVariableName(_))
        ));
        assert!(matches!(
            config.unset_config("ALSO_MISSING"),
            Err(CoreError::VariableNotFound(_))
        ));
    }

    #[test]
    fn import_classification_routes_secrets_away_from_storage() {
        let (_guard, ctx) = temp_ctx();
        let config = ConfigService::new(&ctx);

        let report = config
            .import_env_pairs([
                ("PORT", "8080"),
                ("LOG_LEVEL", "info"),
                ("DATABASE_URL", "postgres://localhost/app"),
                ("GITHUB_TOKEN", "gh-redacted"),
                ("SERVICE_PRIVATE_KEY", "redacted"),
            ])
            .unwrap();

        assert_eq!(
            report.added_config,
            vec!["PORT".to_owned(), "LOG_LEVEL".to_owned()]
        );
        assert_eq!(
            report.needs_secret,
            vec![
                "DATABASE_URL".to_owned(),
                "GITHUB_TOKEN".to_owned(),
                "SERVICE_PRIVATE_KEY".to_owned(),
            ]
        );
        assert!(report.skipped_existing.is_empty());
        assert!(report.skipped_invalid.is_empty());

        // Secrets must NOT appear anywhere: only the two accepted config
        // names are staged.
        let staged = crate::staging::StagingService::new(&ctx).status().unwrap();
        assert_eq!(staged.staged_changes.len(), 2);
        crate::history::HistoryService::new(&ctx)
            .commit("import", "user:i")
            .unwrap();
        assert_eq!(config.list_configs().unwrap().len(), 2);

        // Second pass: existing names skip; invalid names report.
        let second = config
            .import_env_pairs([("PORT", "9090"), ("FEATURE_X", "on"), ("not valid", "v")])
            .unwrap();
        assert_eq!(second.added_config, vec!["FEATURE_X".to_owned()]);
        assert_eq!(second.skipped_existing, vec!["PORT".to_owned()]);
        assert_eq!(second.skipped_invalid, vec!["not valid".to_owned()]);
        // Re-importing a secret keeps it out of storage.
        let third = config
            .import_env_pairs([("GITHUB_TOKEN", "again")])
            .unwrap();
        assert_eq!(third.needs_secret, vec!["GITHUB_TOKEN".to_owned()]);
        assert!(third.added_config.is_empty());
    }

    #[test]
    fn get_config_prefers_staged_overlay_over_head() {
        let (_guard, ctx) = temp_ctx();
        let config = ConfigService::new(&ctx);
        let history = crate::history::HistoryService::new(&ctx);

        config.set_config("VAR", "v1").unwrap();
        history.commit("base", "user:o").unwrap();

        // Pending set is visible without committing...
        config.set_config("VAR", "v2").unwrap();
        assert_eq!(config.get_config("VAR").unwrap(), "v2");
        // ...while listing still shows the committed value only.
        assert_eq!(config.list_configs().unwrap()[0].1, "v1");

        // A staged removal hides the committed value from `get`.
        config.unset_config("VAR").unwrap();
        assert!(matches!(
            config.get_config("VAR"),
            Err(CoreError::VariableNotFound(_))
        ));

        // Restoring brings it back (HEAD binding).
        crate::staging::StagingService::new(&ctx)
            .restore("VAR")
            .unwrap();
        assert_eq!(config.get_config("VAR").unwrap(), "v1");
    }
}
