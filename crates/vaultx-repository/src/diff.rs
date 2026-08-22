//! Manifest diffing: metadata-only change classification.
//!
//! [`compute_diff`] compares two manifests and produces a deterministic,
//! sorted list of [`DiffEntry`] values covering every plan category:
//! config added/removed/changed, secret revision changed, credential
//! binding changed, variable kind changed, policy added/removed/changed,
//! plus the dynamic-provider analogue. Diff output is metadata only — it
//! contains IDs, revisions, and names, never secret values.

use std::fmt;

use serde::{Deserialize, Serialize};
use vaultx_types::model::VariableKind;
use vaultx_types::{CredentialRef, ObjectId, PolicyName, SecretRevisionId, VariableName};

use crate::manifest::{DynamicProviderRef, Manifest, ManifestEntry};

/// A brokered binding snapshot used in diff entries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokeredBinding {
    /// Logical credential reference at the broker.
    pub credential: CredentialRef,
    /// Revision of the underlying secret material.
    pub revision: SecretRevisionId,
}

impl BrokeredBinding {
    fn from_entry(credential: &CredentialRef, revision: &SecretRevisionId) -> Self {
        Self {
            credential: credential.clone(),
            revision: revision.clone(),
        }
    }
}

/// One classified difference between two manifests.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "change", rename_all = "snake_case")]
pub enum DiffEntry {
    /// A config variable was introduced.
    ConfigAdded {
        /// Variable name.
        name: VariableName,
        /// Object holding the new value.
        value: ObjectId,
    },
    /// A config variable was deleted.
    ConfigRemoved {
        /// Variable name.
        name: VariableName,
    },
    /// A config variable now points at a different object.
    ConfigChanged {
        /// Variable name.
        name: VariableName,
        /// Previously referenced object.
        old: ObjectId,
        /// Newly referenced object.
        new: ObjectId,
    },
    /// A secret entry was introduced (metadata only).
    SecretAdded {
        /// Variable name.
        name: VariableName,
        /// Bound revision.
        revision: SecretRevisionId,
    },
    /// A secret entry was deleted (metadata only).
    SecretRemoved {
        /// Variable name.
        name: VariableName,
        /// Previously bound revision.
        revision: SecretRevisionId,
    },
    /// A secret now binds a different revision (metadata only; never a
    /// value).
    SecretRevisionChanged {
        /// Variable name.
        name: VariableName,
        /// Previously bound revision.
        old_revision: SecretRevisionId,
        /// Newly bound revision.
        new_revision: SecretRevisionId,
    },
    /// A brokered entry was introduced.
    CredentialAdded {
        /// Variable name.
        name: VariableName,
        /// The full new binding.
        binding: BrokeredBinding,
    },
    /// A brokered entry was deleted.
    CredentialRemoved {
        /// Variable name.
        name: VariableName,
        /// The removed binding.
        binding: BrokeredBinding,
    },
    /// A brokered entry's credential or revision changed.
    CredentialBindingChanged {
        /// Variable name.
        name: VariableName,
        /// Binding before the change.
        old_binding: BrokeredBinding,
        /// Binding after the change.
        new_binding: BrokeredBinding,
    },
    /// A dynamic entry was introduced.
    DynamicAdded {
        /// Variable name.
        name: VariableName,
        /// Provider that will issue the value.
        provider: DynamicProviderRef,
    },
    /// A dynamic entry was deleted.
    DynamicRemoved {
        /// Variable name.
        name: VariableName,
        /// Provider that previously issued the value.
        provider: DynamicProviderRef,
    },
    /// A dynamic entry switched providers.
    DynamicProviderChanged {
        /// Variable name.
        name: VariableName,
        /// Provider before the change.
        old_provider: DynamicProviderRef,
        /// Provider after the change.
        new_provider: DynamicProviderRef,
    },
    /// An existing variable changed kind without any same-kind field
    /// comparison applying (e.g. config -> secret).
    VariableKindChanged {
        /// Variable name.
        name: VariableName,
        /// Kind before the change.
        old_kind: VariableKind,
        /// Kind after the change.
        new_kind: VariableKind,
    },
    /// A policy was bound to the manifest.
    PolicyAdded {
        /// Policy name.
        name: PolicyName,
        /// Referenced policy document object.
        policy_object: ObjectId,
    },
    /// A policy binding was removed.
    PolicyRemoved {
        /// Policy name.
        name: PolicyName,
        /// Previously referenced policy document object.
        policy_object: ObjectId,
    },
    /// A policy now references a different document.
    PolicyChanged {
        /// Policy name.
        name: PolicyName,
        /// Previously referenced object.
        old_policy_object: ObjectId,
        /// Newly referenced object.
        new_policy_object: ObjectId,
    },
}

impl DiffEntry {
    /// Name of the affected variable or policy.
    #[must_use]
    pub fn subject(&self) -> String {
        match self {
            Self::ConfigAdded { name, .. }
            | Self::ConfigRemoved { name }
            | Self::ConfigChanged { name, .. }
            | Self::SecretAdded { name, .. }
            | Self::SecretRemoved { name, .. }
            | Self::SecretRevisionChanged { name, .. }
            | Self::CredentialAdded { name, .. }
            | Self::CredentialRemoved { name, .. }
            | Self::CredentialBindingChanged { name, .. }
            | Self::DynamicAdded { name, .. }
            | Self::DynamicRemoved { name, .. }
            | Self::DynamicProviderChanged { name, .. }
            | Self::VariableKindChanged { name, .. } => name.as_str().to_owned(),
            Self::PolicyAdded { name, .. }
            | Self::PolicyRemoved { name, .. }
            | Self::PolicyChanged { name, .. } => name.as_str().to_owned(),
        }
    }

    /// Git-style single-character marker for rendered output.
    fn marker(&self) -> char {
        match self {
            Self::ConfigAdded { .. }
            | Self::SecretAdded { .. }
            | Self::CredentialAdded { .. }
            | Self::DynamicAdded { .. }
            | Self::PolicyAdded { .. } => '+',
            Self::ConfigRemoved { .. }
            | Self::SecretRemoved { .. }
            | Self::CredentialRemoved { .. }
            | Self::DynamicRemoved { .. }
            | Self::PolicyRemoved { .. } => '-',
            _ => '~',
        }
    }

    /// Human-readable body of the diff line. Metadata only by
    /// construction: no variant carries secret values.
    fn describe(&self) -> String {
        match self {
            Self::ConfigAdded { name, value } => format!("config {} = {}", name, value),
            Self::ConfigRemoved { name } => format!("config {}", name),
            Self::ConfigChanged { name, old, new } => {
                format!("config {} : {} -> {}", name, old, new)
            }
            Self::SecretAdded { name, revision } => format!("secret {} @ {}", name, revision),
            Self::SecretRemoved { name, revision } => {
                format!("secret {} (was @ {})", name, revision)
            }
            Self::SecretRevisionChanged {
                name,
                old_revision,
                new_revision,
            } => {
                format!("secret {} : {} -> {}", name, old_revision, new_revision)
            }
            Self::CredentialAdded { name, binding } => {
                format!(
                    "brokered {} = {}@{}",
                    name, binding.credential, binding.revision
                )
            }
            Self::CredentialRemoved { name, binding } => {
                format!(
                    "brokered {} (was {}@{})",
                    name, binding.credential, binding.revision
                )
            }
            Self::CredentialBindingChanged {
                name,
                old_binding,
                new_binding,
            } => format!(
                "brokered {} : {}@{} -> {}@{}",
                name,
                old_binding.credential,
                old_binding.revision,
                new_binding.credential,
                new_binding.revision
            ),
            Self::DynamicAdded { name, provider } => {
                format!("dynamic {} via {}", name, provider)
            }
            Self::DynamicRemoved { name, provider } => {
                format!("dynamic {} (was via {})", name, provider)
            }
            Self::DynamicProviderChanged {
                name,
                old_provider,
                new_provider,
            } => {
                format!("dynamic {} : {} -> {}", name, old_provider, new_provider)
            }
            Self::VariableKindChanged {
                name,
                old_kind,
                new_kind,
            } => {
                format!("kind {} : {:?} -> {:?}", name, old_kind, new_kind)
            }
            Self::PolicyAdded {
                name,
                policy_object,
            } => {
                format!("policy {} = {}", name, policy_object)
            }
            Self::PolicyRemoved {
                name,
                policy_object,
            } => {
                format!("policy {} (was {})", name, policy_object)
            }
            Self::PolicyChanged {
                name,
                old_policy_object,
                new_policy_object,
            } => {
                format!(
                    "policy {} : {} -> {}",
                    name, old_policy_object, new_policy_object
                )
            }
        }
    }
}

impl fmt::Display for DiffEntry {
    /// Renders one git-style line, e.g. `+ DB_HOST = obj_abc`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.marker(), self.describe())
    }
}

/// Renders an entire diff in git-style order (sorted by subject then
/// description), one [`DiffEntry`] per line.
#[must_use]
pub fn render_diff(diff: &[DiffEntry]) -> String {
    let mut lines: Vec<(String, String)> =
        diff.iter().map(|e| (e.subject(), e.to_string())).collect();
    lines.sort();
    lines
        .into_iter()
        .map(|(_, line)| line)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Classifies every difference between `old` and `new`.
///
/// Entries are emitted in deterministic order: variables first (sorted by
/// name), then policies (sorted by name). Within one variable at most one
/// entry is produced — a kind change subsumes any same-kind comparison.
#[must_use]
pub fn compute_diff(old: &Manifest, new: &Manifest) -> Vec<DiffEntry> {
    use std::collections::BTreeSet;
    let names: BTreeSet<&VariableName> = old.entries.keys().chain(new.entries.keys()).collect();

    let mut diff = Vec::new();
    for name in names {
        match (old.entries.get(name), new.entries.get(name)) {
            (Some(old_entry), Some(new_entry)) => {
                classify_change(&mut diff, name, old_entry, new_entry)
            }
            (None, Some(entry)) => classify_addition(&mut diff, name, entry),
            (Some(entry), None) => classify_removal(&mut diff, name, entry),
            (None, None) => unreachable!("name came from the union"),
        }
    }

    let policies: BTreeSet<&PolicyName> = old.policies.keys().chain(new.policies.keys()).collect();
    for name in policies {
        match (old.policies.get(name), new.policies.get(name)) {
            (Some(old_obj), Some(new_obj)) if old_obj != new_obj => {
                diff.push(DiffEntry::PolicyChanged {
                    name: name.clone(),
                    old_policy_object: old_obj.clone(),
                    new_policy_object: new_obj.clone(),
                });
            }
            (None, Some(obj)) => diff.push(DiffEntry::PolicyAdded {
                name: name.clone(),
                policy_object: obj.clone(),
            }),
            (Some(obj), None) => diff.push(DiffEntry::PolicyRemoved {
                name: name.clone(),
                policy_object: obj.clone(),
            }),
            _ => {}
        }
    }

    diff
}

fn classify_addition(diff: &mut Vec<DiffEntry>, name: &VariableName, entry: &ManifestEntry) {
    match entry {
        ManifestEntry::Config { object } => diff.push(DiffEntry::ConfigAdded {
            name: name.clone(),
            value: object.clone(),
        }),
        ManifestEntry::Secret { revision } => diff.push(DiffEntry::SecretAdded {
            name: name.clone(),
            revision: revision.clone(),
        }),
        ManifestEntry::Brokered {
            credential,
            revision,
        } => {
            diff.push(DiffEntry::CredentialAdded {
                name: name.clone(),
                binding: BrokeredBinding::from_entry(credential, revision),
            });
        }
        ManifestEntry::Dynamic { provider } => diff.push(DiffEntry::DynamicAdded {
            name: name.clone(),
            provider: provider.clone(),
        }),
    }
}

fn classify_removal(diff: &mut Vec<DiffEntry>, name: &VariableName, entry: &ManifestEntry) {
    match entry {
        ManifestEntry::Config { .. } => diff.push(DiffEntry::ConfigRemoved { name: name.clone() }),
        ManifestEntry::Secret { revision } => diff.push(DiffEntry::SecretRemoved {
            name: name.clone(),
            revision: revision.clone(),
        }),
        ManifestEntry::Brokered {
            credential,
            revision,
        } => {
            diff.push(DiffEntry::CredentialRemoved {
                name: name.clone(),
                binding: BrokeredBinding::from_entry(credential, revision),
            });
        }
        ManifestEntry::Dynamic { provider } => diff.push(DiffEntry::DynamicRemoved {
            name: name.clone(),
            provider: provider.clone(),
        }),
    }
}

fn classify_change(
    diff: &mut Vec<DiffEntry>,
    name: &VariableName,
    old_entry: &ManifestEntry,
    new_entry: &ManifestEntry,
) {
    // Kind transitions are reported once, atomically.
    if old_entry.kind() != new_entry.kind() {
        diff.push(DiffEntry::VariableKindChanged {
            name: name.clone(),
            old_kind: old_entry.kind(),
            new_kind: new_entry.kind(),
        });
        return;
    }
    match (old_entry, new_entry) {
        (ManifestEntry::Config { object: old_obj }, ManifestEntry::Config { object: new_obj })
            if old_obj != new_obj =>
        {
            diff.push(DiffEntry::ConfigChanged {
                name: name.clone(),
                old: old_obj.clone(),
                new: new_obj.clone(),
            })
        }
        (
            ManifestEntry::Secret { revision: old_rev },
            ManifestEntry::Secret { revision: new_rev },
        ) if old_rev != new_rev => diff.push(DiffEntry::SecretRevisionChanged {
            name: name.clone(),
            old_revision: old_rev.clone(),
            new_revision: new_rev.clone(),
        }),
        (
            ManifestEntry::Brokered {
                credential: old_cred,
                revision: old_rev,
            },
            ManifestEntry::Brokered {
                credential: new_cred,
                revision: new_rev,
            },
        ) if old_cred != new_cred || old_rev != new_rev => {
            diff.push(DiffEntry::CredentialBindingChanged {
                name: name.clone(),
                old_binding: BrokeredBinding::from_entry(old_cred, old_rev),
                new_binding: BrokeredBinding::from_entry(new_cred, new_rev),
            });
        }
        (
            ManifestEntry::Dynamic {
                provider: old_provider,
            },
            ManifestEntry::Dynamic {
                provider: new_provider,
            },
        ) if old_provider != new_provider => diff.push(DiffEntry::DynamicProviderChanged {
            name: name.clone(),
            old_provider: old_provider.clone(),
            new_provider: new_provider.clone(),
        }),
        _ => {} // Identical bindings produce no diff entry.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn var(name: &str) -> VariableName {
        VariableName::parse(name).unwrap()
    }

    fn obj(id: &str) -> ObjectId {
        ObjectId::parse(id).unwrap()
    }

    fn rev(id: &str) -> SecretRevisionId {
        SecretRevisionId::parse(id).unwrap()
    }

    fn cred(id: &str) -> CredentialRef {
        CredentialRef::parse(id).unwrap()
    }

    fn provider(value: &str) -> DynamicProviderRef {
        DynamicProviderRef::parse(value).unwrap()
    }

    fn base_manifest() -> Manifest {
        let mut m = Manifest::new();
        m.set_config(var("DB_HOST"), obj("obj_host_v1"));
        m.set_secret(var("DB_PASSWORD"), rev("sec_rev_1"));
        m.set_brokered(var("API_TOKEN"), cred("github-token"), rev("sec_rev_2"));
        m.set_dynamic(var("EPHEMERAL_DB"), provider("broker/dyn-pg-1"));
        m
    }

    #[test]
    fn identical_manifests_produce_no_diff() {
        let m = base_manifest();
        assert!(compute_diff(&m, &m).is_empty());
    }

    #[test]
    fn config_added_removed_changed_are_classified() {
        let mut before = base_manifest();
        before.set_config(var("EXTRA"), obj("obj_extra_v1"));

        let mut after = base_manifest();
        after.set_config(var("DB_HOST"), obj("obj_host_v2"));

        // Forward (before -> after): EXTRA disappears, DB_HOST changes.
        let forward = compute_diff(&before, &after);
        assert!(forward.contains(&DiffEntry::ConfigRemoved { name: var("EXTRA") }));
        assert!(forward.contains(&DiffEntry::ConfigChanged {
            name: var("DB_HOST"),
            old: obj("obj_host_v1"),
            new: obj("obj_host_v2"),
        }));

        // Reverse direction flips the categories.
        let reverse = compute_diff(&after, &before);
        assert!(reverse.contains(&DiffEntry::ConfigAdded {
            name: var("EXTRA"),
            value: obj("obj_extra_v1"),
        }));
        assert!(reverse.contains(&DiffEntry::ConfigChanged {
            name: var("DB_HOST"),
            old: obj("obj_host_v2"),
            new: obj("obj_host_v1"),
        }));
    }

    #[test]
    fn config_removed_is_classified() {
        let mut after = base_manifest();
        after.remove(&var("DB_HOST"));
        assert_eq!(
            compute_diff(&base_manifest(), &after),
            vec![DiffEntry::ConfigRemoved {
                name: var("DB_HOST")
            }]
        );
    }

    #[test]
    fn secret_diff_shows_metadata_only() {
        let mut after = base_manifest();
        after.set_secret(var("DB_PASSWORD"), rev("sec_rev_99"));

        let diff = compute_diff(&base_manifest(), &after);
        assert_eq!(
            diff,
            vec![DiffEntry::SecretRevisionChanged {
                name: var("DB_PASSWORD"),
                old_revision: rev("sec_rev_1"),
                new_revision: rev("sec_rev_99"),
            }]
        );

        // Rendered output must not contain anything resembling plaintext.
        let rendered = render_diff(&diff);
        assert!(rendered.contains("sec_rev_99"));
        assert!(!rendered.to_lowercase().contains("password="));
        // And serialization of the entry stays metadata-only.
        let json = serde_json::to_string(&diff[0]).unwrap();
        assert!(json.contains("\"secret_revision_changed\""));
    }

    #[test]
    fn credential_binding_change_covers_credential_and_revision() {
        let mut after = base_manifest();
        after.set_brokered(var("API_TOKEN"), cred("gitlab-token"), rev("sec_rev_2"));

        let diff = compute_diff(&base_manifest(), &after);
        assert_eq!(
            diff,
            vec![DiffEntry::CredentialBindingChanged {
                name: var("API_TOKEN"),
                old_binding: BrokeredBinding {
                    credential: cred("github-token"),
                    revision: rev("sec_rev_2")
                },
                new_binding: BrokeredBinding {
                    credential: cred("gitlab-token"),
                    revision: rev("sec_rev_2")
                },
            }]
        );
    }

    #[test]
    fn variable_kind_change_subsumes_field_changes() {
        let mut after = base_manifest();
        // Config -> Secret with different payload fields.
        after.entries.remove(&var("DB_HOST"));
        after.set_secret(var("DB_HOST"), rev("sec_rev_50"));

        assert_eq!(
            compute_diff(&base_manifest(), &after),
            vec![DiffEntry::VariableKindChanged {
                name: var("DB_HOST"),
                old_kind: VariableKind::Config,
                new_kind: VariableKind::Secret,
            }]
        );
    }

    #[test]
    fn dynamic_provider_change_is_classified() {
        let mut after = base_manifest();
        after.set_dynamic(var("EPHEMERAL_DB"), provider("broker/dyn-pg-2"));
        assert_eq!(
            compute_diff(&base_manifest(), &after),
            vec![DiffEntry::DynamicProviderChanged {
                name: var("EPHEMERAL_DB"),
                old_provider: provider("broker/dyn-pg-1"),
                new_provider: provider("broker/dyn-pg-2"),
            }]
        );
    }

    #[test]
    fn policy_added_removed_changed_are_classified() {
        let mut before = base_manifest();
        before.set_policy(
            PolicyName::parse("drop_me").unwrap(),
            obj("obj_policy_doc_removed"),
        );
        before.set_policy(
            PolicyName::parse("rotate").unwrap(),
            obj("obj_policy_doc_rotate_v1"),
        );

        let mut after = base_manifest();
        after.set_policy(
            PolicyName::parse("read_only").unwrap(),
            obj("obj_policy_doc_ro"),
        );
        after.set_policy(
            PolicyName::parse("rotate").unwrap(),
            obj("obj_policy_doc_rotate_v2"),
        );

        let diff = compute_diff(&before, &after);
        assert!(diff.contains(&DiffEntry::PolicyAdded {
            name: PolicyName::parse("read_only").unwrap(),
            policy_object: obj("obj_policy_doc_ro"),
        }));
        assert!(diff.contains(&DiffEntry::PolicyRemoved {
            name: PolicyName::parse("drop_me").unwrap(),
            policy_object: obj("obj_policy_doc_removed"),
        }));
        assert!(diff.contains(&DiffEntry::PolicyChanged {
            name: PolicyName::parse("rotate").unwrap(),
            old_policy_object: obj("obj_policy_doc_rotate_v1"),
            new_policy_object: obj("obj_policy_doc_rotate_v2"),
        }));
    }

    #[test]
    fn diff_order_and_rendering_are_deterministic() {
        let mut after = base_manifest();
        after.set_config(var("DB_HOST"), obj("obj_host_v9"));
        after.set_config(var("AAA_NEW"), obj("obj_new_a"));
        after.remove(&var("EPHEMERAL_DB"));

        let diff = compute_diff(&base_manifest(), &after);
        let subjects: Vec<String> = diff.iter().map(DiffEntry::subject).collect();
        assert_eq!(
            subjects,
            vec!["AAA_NEW", "DB_HOST", "EPHEMERAL_DB"],
            "variables must be sorted by name"
        );
        assert_eq!(diff.len(), 3);

        let rendered = render_diff(&diff);
        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(lines[0], "+ config AAA_NEW = obj_new_a");
        assert_eq!(lines[1], "~ config DB_HOST : obj_host_v1 -> obj_host_v9");
        assert_eq!(lines[2], "- dynamic EPHEMERAL_DB (was via broker/dyn-pg-1)");
    }
}
