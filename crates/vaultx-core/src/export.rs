//! [`ExportService`]: plan §33 config/secret export with placeholder
//! safety.
//!
//! Safe mode (the only default) renders non-secret config values
//! literally and every protected value as an inert placeholder:
//!
//! * secrets → [`SECRET_PLACEHOLDER`]
//! * brokered credentials → [`BROKERED_PLACEHOLDER`]
//! * dynamic provider bindings → [`DYNAMIC_PLACEHOLDER`]
//!
//! Reveal mode additionally decrypts **plain** secret revisions, but
//! brokered credential values are placeholders in every mode (INV-002 /
//! INV-003: they are never returned by any surface other than the
//! broker's injection path). Destroyed revisions render as
//! [`DESTROYED_PLACEHOLDER`] — their values are unrecoverable by design.
//!
//! The authorization friction (typed confirmation / explicit flag) lives
//! in the CLI layer; this module only refuses to produce plaintext unless
//! asked, and never embeds values in errors (INV-012).

use zeroize::Zeroizing;

use vaultx_repository::ManifestEntry;
use vaultx_types::{SecretRevisionId, VariableName};

use crate::config::ConfigService;
use crate::error::{CoreError, CoreResult};
use crate::project::ProjectContext;
use crate::secrets::{SecretRevisionState, SecretService};

/// Placeholder rendered for a plain secret in safe mode.
pub const SECRET_PLACEHOLDER: &str = "<vaultx:secret>";
/// Placeholder rendered for a brokered credential in every mode.
pub const BROKERED_PLACEHOLDER: &str = "<vaultx:brokered>";
/// Placeholder rendered for a dynamically issued value in every mode.
pub const DYNAMIC_PLACEHOLDER: &str = "<vaultx:dynamic>";
/// Placeholder rendered for a destroyed (unrecoverable) secret revision.
pub const DESTROYED_PLACEHOLDER: &str = "<vaultx:destroyed>";

/// One exported variable's resolved rendering.
#[derive(Clone, Debug)]
pub struct ExportEntry {
    /// Variable name.
    pub name: VariableName,
    /// Rendered value.
    pub value: ExportValue,
}

/// Resolved value class of one exported entry.
#[derive(Clone)]
pub enum ExportValue {
    /// Non-secret literal (config values only).
    Literal(String),
    /// Inert placeholder; carries no material.
    Placeholder(&'static str),
    /// Decrypted plaintext of a plain secret; reveal mode only and never
    /// for brokered credentials. Zeroized on drop.
    Plaintext(Zeroizing<Vec<u8>>),
}

impl std::fmt::Debug for ExportValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Literal(value) => f.debug_tuple("Literal").field(value).finish(),
            // Placeholders are inert; plaintext must never reach Debug or
            // Display output (INV-012).
            Self::Placeholder(tag) => f.debug_tuple("Placeholder").field(tag).finish(),
            Self::Plaintext(_) => f.write_str("Plaintext(<redacted>)"),
        }
    }
}

/// Renders one entry as a `NAME=value` line. Plaintext bytes are decoded
/// lossily (secrets are stored from UTF-8 text).
#[must_use]
pub fn render_export_entry(entry: &ExportEntry) -> String {
    let value = match &entry.value {
        ExportValue::Literal(value) => value.clone(),
        ExportValue::Placeholder(tag) => (*tag).to_owned(),
        ExportValue::Plaintext(bytes) => String::from_utf8_lossy(bytes).into_owned(),
    };
    format!("{}={}", entry.name.as_str(), value)
}

/// Plan §33 export over the HEAD manifest of the current branch.
#[derive(Clone, Copy, Debug)]
pub struct ExportService<'a> {
    ctx: &'a ProjectContext,
}

impl<'a> ExportService<'a> {
    /// Builds a service operating on `ctx`.
    #[must_use]
    pub const fn new(ctx: &'a ProjectContext) -> Self {
        Self { ctx }
    }

    /// Collects every HEAD-manifest entry as an export line, sorted by
    /// variable name.
    ///
    /// With `reveal_secrets` set, plain secret revisions bound at HEAD are
    /// decrypted into [`ExportValue::Plaintext`]; brokered credentials stay
    /// placeholders unconditionally. Without it, no decryption ever runs.
    ///
    /// # Errors
    /// * Propagates manifest/config-object lookup failures.
    /// * A revealed revision whose record is missing fails with
    ///   [`CoreError::MissingRevision`]; destroyed revisions are not
    ///   errors — they render [`DESTROYED_PLACEHOLDER`].
    pub fn export(&self, reveal_secrets: bool) -> CoreResult<Vec<ExportEntry>> {
        let manifest = self.ctx.repository().working_manifest()?;
        let secrets = SecretService::new(self.ctx);
        let mut entries = Vec::with_capacity(manifest.entries.len());
        for (name, entry) in &manifest.entries {
            let value = match entry {
                ManifestEntry::Config { object } => ExportValue::Literal(
                    ConfigService::new(self.ctx).value_of_config_object(object)?,
                ),
                ManifestEntry::Secret { revision } => {
                    self.resolve_secret(&secrets, name, revision, reveal_secrets)?
                }
                // INV-002/INV-003: brokered credential values never leave
                // the broker's injection path, in any mode.
                ManifestEntry::Brokered { .. } => ExportValue::Placeholder(BROKERED_PLACEHOLDER),
                ManifestEntry::Dynamic { .. } => ExportValue::Placeholder(DYNAMIC_PLACEHOLDER),
            };
            entries.push(ExportEntry {
                name: name.clone(),
                value,
            });
        }
        Ok(entries)
    }

    fn resolve_secret(
        &self,
        secrets: &SecretService<'a>,
        name: &VariableName,
        revision: &SecretRevisionId,
        reveal_secrets: bool,
    ) -> CoreResult<ExportValue> {
        if !reveal_secrets {
            return Ok(ExportValue::Placeholder(SECRET_PLACEHOLDER));
        }
        match secrets.revision_state(revision)? {
            None => Err(CoreError::MissingRevision {
                name: name.to_string(),
                revision: revision.to_string(),
            }),
            Some(SecretRevisionState::Destroyed) => {
                Ok(ExportValue::Placeholder(DESTROYED_PLACEHOLDER))
            }
            Some(_) => Ok(ExportValue::Plaintext(
                secrets.reveal_revision(name, revision)?,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::ConfigService;
    use crate::history::HistoryService;
    use crate::SecretString;
    use vaultx_types::model::VariableKind;

    const CANARY_PLAIN: &str = "canary-plain-hunter3";
    const CANARY_BROKERED: &str = "canary-brokered-hunter4";

    struct Fixture {
        _dir: tempfile::TempDir,
        ctx: ProjectContext,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ProjectContext::init(dir.path()).unwrap();
        Fixture { _dir: dir, ctx }
    }

    /// Commits one literal config value, one plain secret, and one
    /// brokered credential at HEAD.
    fn seed(fx: &Fixture) {
        ConfigService::new(&fx.ctx)
            .set_config("PORT", "8080")
            .unwrap();
        let secrets = SecretService::new(&fx.ctx);
        secrets
            .set_secret(
                "API_TOKEN",
                &SecretString::copy_from(CANARY_PLAIN),
                VariableKind::Secret,
                "development",
                None,
            )
            .unwrap();
        secrets
            .set_secret(
                "GITHUB_CRED",
                &SecretString::copy_from(CANARY_BROKERED),
                VariableKind::Brokered,
                "development",
                Some(crate::secrets::BrokeredBinding {
                    credential_ref: vaultx_types::CredentialRef::parse("github-token").unwrap(),
                    injection: vaultx_types::model::InjectionTemplateId::Bearer,
                    provider_hint: None,
                }),
            )
            .unwrap();
        HistoryService::new(&fx.ctx)
            .commit("seed", "user:t")
            .unwrap();
    }

    fn rendered(fx: &Fixture, reveal_secrets: bool) -> String {
        let entries = ExportService::new(&fx.ctx).export(reveal_secrets).unwrap();
        entries
            .iter()
            .map(render_export_entry)
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn safe_mode_renders_config_literals_and_inert_placeholders() {
        let fx = fixture();
        seed(&fx);

        let entries = ExportService::new(&fx.ctx).export(false).unwrap();
        assert_eq!(entries.len(), 3);
        for entry in &entries {
            match entry.name.as_str() {
                "PORT" => {
                    assert!(matches!(&entry.value, ExportValue::Literal(value) if value == "8080"))
                }
                "API_TOKEN" => {
                    assert_eq!(entry.value_placeholder_tag(), SECRET_PLACEHOLDER)
                }
                "GITHUB_CRED" => {
                    assert_eq!(entry.value_placeholder_tag(), BROKERED_PLACEHOLDER)
                }
                other => panic!("unexpected entry {other}"),
            }
        }

        // Leak scan across the full rendering: neither canary plaintext
        // may surface in safe mode (INV-012).
        let out = rendered(&fx, false);
        assert!(!out.contains(CANARY_PLAIN), "plaintext leaked: {out}");
        assert!(!out.contains(CANARY_BROKERED), "brokered leaked: {out}");
        assert!(out.contains("PORT=8080"), "{out}");
    }

    #[test]
    fn reveal_mode_decrypts_plain_secrets_but_never_brokered_values() {
        let fx = fixture();
        seed(&fx);

        let out = rendered(&fx, true);
        // The plain secret's real value appears only under reveal...
        assert!(out.contains(&format!("API_TOKEN={CANARY_PLAIN}")), "{out}");
        // ...while the brokered credential stays a placeholder in every
        // mode (INV-002/INV-003).
        assert!(out.contains("GITHUB_CRED=<vaultx:brokered>"), "{out}");
        assert!(!out.contains(CANARY_BROKERED), "brokered leaked: {out}");
    }

    #[test]
    fn destroyed_revision_renders_destroyed_placeholder_under_any_mode() {
        let fx = fixture();
        seed(&fx);
        SecretService::new(&fx.ctx)
            .destroy_secret("API_TOKEN", "development")
            .unwrap();

        let safe = rendered(&fx, false);
        assert!(safe.contains("API_TOKEN=<vaultx:secret>"), "{safe}");
        let revealed = rendered(&fx, true);
        assert!(
            revealed.contains(&format!("API_TOKEN={DESTROYED_PLACEHOLDER}")),
            "{revealed}"
        );
        assert!(!revealed.contains(CANARY_PLAIN), "shred leak: {revealed}");
    }

    #[test]
    fn missing_revision_record_fails_without_value_material() {
        use vaultx_types::SecretRevisionId;

        let fx = fixture();
        seed(&fx);
        let ghost =
            SecretRevisionId::parse("sec_rev_deadbeef0000000000000000000000000000000000").unwrap();
        fx.ctx
            .repository()
            .add(
                vaultx_types::VariableName::parse("API_TOKEN").unwrap(),
                ManifestEntry::Secret { revision: ghost },
            )
            .unwrap();
        HistoryService::new(&fx.ctx)
            .commit("bind ghost", "user:t")
            .unwrap();

        let err = ExportService::new(&fx.ctx).export(true).unwrap_err();
        match &err {
            CoreError::MissingRevision { name, revision } => {
                assert_eq!(name, "API_TOKEN");
                assert!(revision.starts_with("sec_rev_"));
            }
            other => panic!("expected MissingRevision, got {other:?}"),
        }
        // Safe mode never touches revision records and still succeeds.
        assert!(rendered(&fx, false).contains("API_TOKEN=<vaultx:secret>"));
    }

    #[test]
    fn render_and_debug_cover_every_value_class_without_exposure() {
        let literal = ExportEntry {
            name: vaultx_types::VariableName::parse("PORT").unwrap(),
            value: ExportValue::Literal("8080".to_owned()),
        };
        let placeholder = ExportEntry {
            name: vaultx_types::VariableName::parse("TOKEN").unwrap(),
            value: ExportValue::Placeholder(SECRET_PLACEHOLDER),
        };
        let plaintext_entry = ExportEntry {
            name: vaultx_types::VariableName::parse("SHOWN").unwrap(),
            value: ExportValue::Plaintext(Zeroizing::new(b"hunter2-canary".to_vec())),
        };

        assert_eq!(render_export_entry(&literal), "PORT=8080");
        assert_eq!(
            render_export_entry(&placeholder),
            format!("TOKEN={SECRET_PLACEHOLDER}")
        );
        assert_eq!(
            render_export_entry(&plaintext_entry),
            "SHOWN=hunter2-canary"
        );

        // Debug/Display of the value enum itself must redact plaintext
        // (INV-012); the renderer is the only sanctioned disclosure path.
        let debugged = format!("{:?}", plaintext_entry.value);
        assert!(!debugged.contains("hunter2"), "{debugged}");
    }

    impl ExportEntry {
        fn value_placeholder_tag(&self) -> &'static str {
            match &self.value {
                ExportValue::Placeholder(tag) => tag,
                other => panic!("expected placeholder, got {other:?}"),
            }
        }
    }
}
