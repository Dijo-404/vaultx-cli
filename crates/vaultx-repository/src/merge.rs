//! Three-way manifest merge with explicit conflict resolution.
//!
//! Rules (per plan §11):
//!
//! 1. Identical changes on both sides auto-resolve.
//! 2. Non-overlapping changes (one side untouched) auto-merge.
//! 3. Conflicting config values produce [`Conflict::ConfigConflict`].
//!    Brokered and dynamic bindings are manifest-level config too, so
//!    their disagreements surface as `ConfigConflict` as well.
//! 4. Conflicting secret revisions **always** conflict
//!    ([`Conflict::SecretConflict`]): secret revisions are atomic values,
//!    so the merger never silently selects one.
//! 5. Policy disagreements always conflict ([`Conflict::PolicyConflict`]).
//!
//! Environment protection is not part of manifests; it lives on env refs
//! (`refs` module), whose protection metadata prevents silent weakening at
//! the ref layer.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use vaultx_types::model::VariableKind;
use vaultx_types::{ObjectId, PolicyName, SecretRevisionId, VariableName};

use crate::error::RepoError;
use crate::manifest::{Manifest, ManifestEntry};

/// Automatic resolution applied to **non-secret** disagreements during a
/// merge. Secret revisions are atomic values: they are never picked
/// automatically and remain blocking under every strategy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MergeStrategy {
    /// Keep our side of each resolvable disagreement.
    Ours,
    /// Take their side of each resolvable disagreement.
    Theirs,
}

impl MergeStrategy {
    fn picks_ours(self) -> bool {
        matches!(self, Self::Ours)
    }
}

/// A disagreement that requires explicit human resolution before a merge
/// can complete.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, thiserror::Error,
)]
pub enum Conflict {
    /// Both branches changed the same non-secret variable differently.
    #[error("config `{name}` changed differently on both sides")]
    ConfigConflict {
        /// Variable in dispute.
        name: VariableName,
    },
    /// Both branches changed the same secret's binding differently.
    ///
    /// `None` means that side removed the entry. Secret revisions are
    /// atomic: resolution is an explicit choice between the recorded
    /// options (including removal), never an automatic pick.
    #[error(
        "secret `{name}` has competing revisions ({ours_rev:?} vs {theirs_rev:?}); explicit selection required"
    )]
    SecretConflict {
        /// Variable in dispute.
        name: VariableName,
        /// Revision chosen on our side (`None` = removed).
        ours_rev: Option<SecretRevisionId>,
        /// Revision chosen on their side (`None` = removed).
        theirs_rev: Option<SecretRevisionId>,
    },
    /// Both branches bound different policy documents under the same name.
    #[error("policy `{name}` changed differently on both sides")]
    PolicyConflict {
        /// Policy in dispute.
        name: PolicyName,
    },
}

impl Conflict {
    /// Name of the disputed subject.
    #[must_use]
    pub fn subject(&self) -> String {
        match self {
            Self::ConfigConflict { name } | Self::SecretConflict { name, .. } => {
                name.as_str().to_owned()
            }
            Self::PolicyConflict { name } => name.as_str().to_owned(),
        }
    }
}

/// Merges `ours` and `theirs` against their common ancestor `base`.
///
/// # Errors
/// Returns `Err(Vec<Conflict>)` listing every unresolved disagreement,
/// sorted deterministically (conflict kind first, then subject); nothing is
/// partially applied — callers get either a fully merged manifest or the
/// complete conflict set.
pub fn three_way_merge(
    base: &Manifest,
    ours: &Manifest,
    theirs: &Manifest,
) -> Result<Manifest, Vec<Conflict>> {
    merge_inner(base, ours, theirs, None)
}

/// Like [`three_way_merge`], but non-secret disagreements are resolved
/// automatically by picking `strategy`'s side. Secret revision conflicts
/// are never auto-resolvable and still block with a full conflict list.
///
/// # Errors
/// [`Vec<Conflict>`] holding only the unresolvable (secret) disagreements,
/// sorted deterministically; nothing is partially applied.
pub fn three_way_merge_with_strategy(
    base: &Manifest,
    ours: &Manifest,
    theirs: &Manifest,
    strategy: MergeStrategy,
) -> Result<Manifest, Vec<Conflict>> {
    merge_inner(base, ours, theirs, Some(strategy))
}

fn merge_inner(
    base: &Manifest,
    ours: &Manifest,
    theirs: &Manifest,
    strategy: Option<MergeStrategy>,
) -> Result<Manifest, Vec<Conflict>> {
    let mut merged = Manifest::new();
    let mut conflicts: Vec<Conflict> = Vec::new();

    let names: BTreeSet<&VariableName> = base
        .entries
        .keys()
        .chain(ours.entries.keys())
        .chain(theirs.entries.keys())
        .collect();

    for name in names {
        let b = base.entries.get(name);
        let o = ours.entries.get(name);
        let t = theirs.entries.get(name);

        let resolved: Option<Option<ManifestEntry>> = if o == t {
            Some(o.cloned()) // Rule 1: identical (or both absent).
        } else if o == b {
            Some(t.cloned()) // Rule 2a: only theirs changed.
        } else if t == b {
            Some(o.cloned()) // Rule 2b: only ours changed.
        } else {
            None // Genuine disagreement.
        };

        match resolved {
            Some(Some(entry)) => {
                merged.entries.insert(name.clone(), entry);
            }
            Some(None) => {}
            None => {
                let classified = classify_entry_conflict(name, b, o, t);
                if matches!(classified, Conflict::SecretConflict { .. }) {
                    // Secret revisions are atomic: no strategy may pick one.
                    conflicts.push(classified);
                } else if let Some(side) = strategy {
                    let chosen = if side.picks_ours() { o } else { t };
                    apply_entry_side(&mut merged.entries, name.clone(), chosen);
                } else {
                    conflicts.push(classified);
                }
            }
        }
    }

    let policies: BTreeSet<&PolicyName> = base
        .policies
        .keys()
        .chain(ours.policies.keys())
        .chain(theirs.policies.keys())
        .collect();

    for name in policies {
        let b = base.policies.get(name);
        let o = ours.policies.get(name);
        let t = theirs.policies.get(name);

        let resolved: Option<Option<ObjectId>> = if o == t {
            Some(o.cloned())
        } else if o == b {
            Some(t.cloned())
        } else if t == b {
            Some(o.cloned())
        } else {
            None // Rule 5: policy conflicts never auto-resolve.
        };

        match resolved {
            Some(Some(obj)) => {
                merged.policies.insert(name.clone(), obj);
            }
            Some(None) => {}
            None => {
                // Policies are never secret material, so a strategy may
                // always pick a side here.
                if let Some(side) = strategy {
                    let chosen = if side.picks_ours() { o } else { t };
                    debug_assert!(
                        chosen.is_some(),
                        "a genuine policy disagreement implies both sides bind a document"
                    );
                    merged.policies.insert(
                        name.clone(),
                        chosen.cloned().expect("both sides bound a document"),
                    );
                } else {
                    conflicts.push(Conflict::PolicyConflict { name: name.clone() });
                }
            }
        }
    }

    if conflicts.is_empty() {
        Ok(merged)
    } else {
        conflicts.sort();
        Err(conflicts)
    }
}

/// Applies one side's entry resolution (`None` = removal) for `name`.
fn apply_entry_side(
    entries: &mut std::collections::BTreeMap<VariableName, ManifestEntry>,
    name: VariableName,
    chosen: Option<&ManifestEntry>,
) {
    match chosen {
        Some(entry) => {
            entries.insert(name, entry.clone());
        }
        None => {
            entries.remove(&name);
        }
    }
}

/// Picks the most specific conflict category for an irreconcilable entry.
///
/// Any dispute that touches a secret binding blocks under **every**
/// strategy: when any of `base`, `ours`, or `theirs` binds a secret, the
/// disagreement returns [`Conflict::SecretConflict`] — covering
/// rotate-vs-rotate, modify-vs-delete, rotation vs. kind change, and
/// fresh secret-vs-config clashes alike — so a merge strategy can never
/// adopt or drop a secret binding silently. Every other disagreement —
/// config objects, brokered bindings, dynamic providers, or non-secret
/// kind mismatches — reports as [`Conflict::ConfigConflict`].
fn classify_entry_conflict(
    name: &VariableName,
    base: Option<&ManifestEntry>,
    ours: Option<&ManifestEntry>,
    theirs: Option<&ManifestEntry>,
) -> Conflict {
    fn secret_revision(entry: Option<&ManifestEntry>) -> Option<SecretRevisionId> {
        match entry {
            Some(ManifestEntry::Secret { revision }) => Some(revision.clone()),
            _ => None,
        }
    }

    let is_secret =
        |entry: Option<&ManifestEntry>| entry.is_some_and(|e| e.kind() == VariableKind::Secret);

    if is_secret(base) || is_secret(ours) || is_secret(theirs) {
        Conflict::SecretConflict {
            name: name.clone(),
            ours_rev: secret_revision(ours),
            theirs_rev: secret_revision(theirs),
        }
    } else {
        Conflict::ConfigConflict { name: name.clone() }
    }
}

/// Resolves a secret conflict by explicit selection, returning the
/// resulting manifest entry to insert.
///
/// # Errors
/// [`RepoError::ManifestMismatch`] when `conflicts` contains no
/// [`Conflict::SecretConflict`] for `name`.
pub fn resolve_secret(
    conflicts: &[Conflict],
    name: &VariableName,
    chosen_rev: &SecretRevisionId,
) -> Result<ManifestEntry, RepoError> {
    let matching = conflicts
        .iter()
        .any(|c| matches!(c, Conflict::SecretConflict { name: n, .. } if n == name));
    if !matching {
        return Err(RepoError::ManifestMismatch(format!(
            "no secret conflict found for `{name}`"
        )));
    }
    Ok(ManifestEntry::Secret {
        revision: chosen_rev.clone(),
    })
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

    fn pol(name: &str) -> PolicyName {
        PolicyName::parse(name).unwrap()
    }

    fn cfg(object: &str) -> ManifestEntry {
        ManifestEntry::Config {
            object: obj(object),
        }
    }

    fn sec(revision: &str) -> ManifestEntry {
        ManifestEntry::Secret {
            revision: rev(revision),
        }
    }

    fn manifest_of(pairs: &[(&str, ManifestEntry)]) -> Manifest {
        let mut m = Manifest::new();
        for (name, entry) in pairs {
            m.entries.insert(var(name), entry.clone());
        }
        m
    }

    #[test]
    fn clean_merge_combines_non_overlapping_additions() {
        // Base has A only. Ours adds B, theirs adds C.
        let base = manifest_of(&[("A", cfg("obj_a_base"))]);
        let mut ours = base.clone();
        ours.set_config(var("B"), obj("obj_b_ours"));
        let mut theirs = base.clone();
        theirs.set_config(var("C"), obj("obj_c_theirs"));

        let merged = three_way_merge(&base, &ours, &theirs).expect("clean merge");
        assert_eq!(merged.get(&var("A")), Some(&cfg("obj_a_base")));
        assert_eq!(merged.get(&var("B")), Some(&cfg("obj_b_ours")));
        assert_eq!(merged.get(&var("C")), Some(&cfg("obj_c_theirs")));
    }

    #[test]
    fn identical_change_on_both_sides_auto_resolves() {
        let base = manifest_of(&[("A", cfg("obj_a_v1"))]);
        let ours = manifest_of(&[("A", cfg("obj_a_v2"))]);
        let theirs = manifest_of(&[("A", cfg("obj_a_v2"))]);

        let merged = three_way_merge(&base, &ours, &theirs).expect("identical changes resolve");
        assert_eq!(merged.get(&var("A")), Some(&cfg("obj_a_v2")));
    }

    #[test]
    fn single_sided_changes_take_the_changed_side() {
        let base = manifest_of(&[
            ("ONLY_OURS", cfg("obj_old")),
            ("ONLY_THEIRS", cfg("obj_old")),
            ("UNTOUCHED", cfg("obj_static")),
        ]);
        let ours = manifest_of(&[
            ("ONLY_OURS", cfg("obj_new_from_ours")),
            ("ONLY_THEIRS", cfg("obj_old")),
            ("UNTOUCHED", cfg("obj_static")),
        ]);
        let theirs = manifest_of(&[
            ("ONLY_OURS", cfg("obj_old")),
            ("ONLY_THEIRS", cfg("obj_new_from_theirs")),
            ("UNTOUCHED", cfg("obj_static")),
        ]);

        let merged = three_way_merge(&base, &ours, &theirs).expect("non-overlapping edits merge");
        assert_eq!(
            merged.get(&var("ONLY_OURS")),
            Some(&cfg("obj_new_from_ours"))
        );
        assert_eq!(
            merged.get(&var("ONLY_THEIRS")),
            Some(&cfg("obj_new_from_theirs"))
        );
        assert_eq!(merged.get(&var("UNTOUCHED")), Some(&cfg("obj_static")));
    }

    #[test]
    fn deletion_on_one_side_and_noop_on_other_takes_deletion() {
        let base = manifest_of(&[("GONE", cfg("obj_gone"))]);
        let theirs = Manifest::new(); // Deleted it.
        let merged = three_way_merge(&base, &base, &theirs).expect("delete merges cleanly");
        assert!(merged.get(&var("GONE")).is_none());
    }

    #[test]
    fn conflicting_config_values_conflict() {
        let base = manifest_of(&[("PORT", cfg("obj_port_8080"))]);
        let ours = manifest_of(&[("PORT", cfg("obj_port_9090"))]);
        let theirs = manifest_of(&[("PORT", cfg("obj_port_7070"))]);

        let conflicts = three_way_merge(&base, &ours, &theirs).expect_err("must conflict");
        assert_eq!(
            conflicts,
            vec![Conflict::ConfigConflict { name: var("PORT") }]
        );
    }

    #[test]
    fn kind_change_involving_a_secret_blocks_explicitly() {
        let base = manifest_of(&[("MIXED", cfg("obj_mixed_v1"))]);
        let ours = manifest_of(&[("MIXED", sec("sec_rev_1"))]); // became secret
        let theirs = manifest_of(&[("MIXED", cfg("obj_mixed_v2"))]);

        let conflicts = three_way_merge(&base, &ours, &theirs).expect_err("kind mismatch");
        assert_eq!(
            conflicts,
            vec![Conflict::SecretConflict {
                name: var("MIXED"),
                ours_rev: Some(rev("sec_rev_1")),
                theirs_rev: None,
            }]
        );
    }

    #[test]
    fn strategy_theirs_cannot_adopt_over_a_rotated_secret() {
        // base=secret; ours rotated; theirs replaced the binding with plain
        // config. Picking "theirs" would silently drop the rotated secret.
        let base = manifest_of(&[("TOKEN", sec("sec_rev_base"))]);
        let ours = manifest_of(&[("TOKEN", sec("sec_rev_ours"))]);
        let theirs = manifest_of(&[("TOKEN", cfg("obj_plain"))]);

        let conflicts = three_way_merge_with_strategy(&base, &ours, &theirs, MergeStrategy::Theirs)
            .expect_err("strategy must not adopt over a rotation");
        assert_eq!(
            conflicts,
            vec![Conflict::SecretConflict {
                name: var("TOKEN"),
                ours_rev: Some(rev("sec_rev_ours")),
                theirs_rev: None,
            }]
        );
    }

    #[test]
    fn strategy_theirs_cannot_drop_a_fresh_secret_for_config() {
        // No base binding: ours introduced a secret, theirs introduced
        // plain config at the same name.
        let base = Manifest::new();
        let ours = manifest_of(&[("TOKEN", sec("sec_rev_new"))]);
        let theirs = manifest_of(&[("TOKEN", cfg("obj_plain"))]);

        let conflicts = three_way_merge_with_strategy(&base, &ours, &theirs, MergeStrategy::Theirs)
            .expect_err("strategy must not silently drop a secret");
        assert_eq!(
            conflicts,
            vec![Conflict::SecretConflict {
                name: var("TOKEN"),
                ours_rev: Some(rev("sec_rev_new")),
                theirs_rev: None,
            }]
        );
    }

    #[test]
    fn conflicting_secret_revisions_always_conflict() {
        let base = manifest_of(&[("DB_PASSWORD", sec("sec_rev_10"))]);
        let ours = manifest_of(&[("DB_PASSWORD", sec("sec_rev_11"))]);
        let theirs = manifest_of(&[("DB_PASSWORD", sec("sec_rev_12"))]);

        let conflicts = three_way_merge(&base, &ours, &theirs).expect_err("secret conflict");
        assert_eq!(
            conflicts,
            vec![Conflict::SecretConflict {
                name: var("DB_PASSWORD"),
                ours_rev: Some(rev("sec_rev_11")),
                theirs_rev: Some(rev("sec_rev_12")),
            }]
        );

        // Even when both sides agree with EACH OTHER but differ from base,
        // rule 1 already resolved it; verify that stays clean.
        let theirs_same = manifest_of(&[("DB_PASSWORD", sec("sec_rev_11"))]);
        assert!(three_way_merge(&base, &ours, &theirs_same).is_ok());
    }

    #[test]
    fn secret_modify_delete_still_requires_explicit_selection() {
        let base = manifest_of(&[("API_SECRET", sec("sec_rev_20"))]);
        let ours = manifest_of(&[("API_SECRET", sec("sec_rev_21"))]);
        let theirs = Manifest::new(); // Removed it.

        let conflicts = three_way_merge(&base, &ours, &theirs).expect_err("modify/delete");
        assert_eq!(
            conflicts,
            vec![Conflict::SecretConflict {
                name: var("API_SECRET"),
                ours_rev: Some(rev("sec_rev_21")),
                theirs_rev: None,
            }]
        );
    }

    #[test]
    fn identical_secret_rotation_on_both_sides_resolves() {
        let base = manifest_of(&[("DB_PASSWORD", sec("sec_rev_30"))]);
        let rotated = manifest_of(&[("DB_PASSWORD", sec("sec_rev_31"))]);
        let merged = three_way_merge(&base, &rotated, &rotated).expect("same rotation twice");
        assert_eq!(merged.get(&var("DB_PASSWORD")), Some(&sec("sec_rev_31")));
    }

    #[test]
    fn policy_conflicts_require_explicit_resolution() {
        let mut base = Manifest::new();
        base.set_policy(pol("read_only"), obj("obj_policy_doc_v1"));
        base.set_policy(pol("stable"), obj("obj_policy_doc_stable"));

        let mut ours = base.clone();
        ours.set_policy(pol("read_only"), obj("obj_policy_doc_ours"));
        let mut theirs = base.clone();
        theirs.set_policy(pol("read_only"), obj("obj_policy_doc_theirs"));

        let conflicts = three_way_merge(&base, &ours, &theirs).expect_err("policy conflict");
        assert_eq!(
            conflicts,
            vec![Conflict::PolicyConflict {
                name: pol("read_only")
            }]
        );

        // Unrelated policy change still merges alongside the conflict list.
        assert_eq!(
            three_way_merge(&base, &base, &theirs).map(|_| ()).ok(),
            Some(())
        );
    }

    #[test]
    fn multiple_conflicts_are_sorted_by_subject() {
        let base = manifest_of(&[("ALPHA", cfg("obj_alpha_1")), ("ZULU", cfg("obj_zulu_1"))]);
        let ours = manifest_of(&[("ALPHA", cfg("obj_alpha_o")), ("ZULU", cfg("obj_zulu_o"))]);
        let theirs = manifest_of(&[("ALPHA", cfg("obj_alpha_t")), ("ZULU", cfg("obj_zulu_t"))]);

        let conflicts = three_way_merge(&base, &ours, &theirs).expect_err("two conflicts");
        assert_eq!(conflicts.len(), 2);
        assert_eq!(conflicts[0].subject(), "ALPHA");
        assert_eq!(conflicts[1].subject(), "ZULU");
    }

    #[test]
    fn resolve_secret_produces_entry_for_matching_conflict() {
        let conflict = Conflict::SecretConflict {
            name: var("DB_PASSWORD"),
            ours_rev: Some(rev("sec_rev_11")),
            theirs_rev: Some(rev("sec_rev_12")),
        };
        let resolved = resolve_secret(&[conflict], &var("DB_PASSWORD"), &rev("sec_rev_12"))
            .expect("resolution");
        assert_eq!(resolved, sec("sec_rev_12"));
    }

    #[test]
    fn resolve_secret_rejects_unknown_names() {
        let conflict = Conflict::ConfigConflict {
            name: var("NOT_A_SECRET"),
        };
        assert!(matches!(
            resolve_secret(&[conflict], &var("MISSING"), &rev("sec_rev_1")),
            Err(RepoError::ManifestMismatch(_))
        ));
    }

    #[test]
    fn empty_everything_merges_to_empty() {
        let empty = Manifest::new();
        assert_eq!(three_way_merge(&empty, &empty, &empty).unwrap(), empty);
    }

    #[test]
    fn strategy_resolves_config_conflicts_by_side() {
        let base = manifest_of(&[("PORT", cfg("obj_port_1"))]);
        let ours = manifest_of(&[("PORT", cfg("obj_port_ours"))]);
        let theirs = manifest_of(&[("PORT", cfg("obj_port_theirs"))]);

        let merged =
            three_way_merge_with_strategy(&base, &ours, &theirs, MergeStrategy::Ours).unwrap();
        assert_eq!(merged.get(&var("PORT")), Some(&cfg("obj_port_ours")));

        let merged =
            three_way_merge_with_strategy(&base, &ours, &theirs, MergeStrategy::Theirs).unwrap();
        assert_eq!(merged.get(&var("PORT")), Some(&cfg("obj_port_theirs")));
    }

    #[test]
    fn strategy_resolves_policy_conflicts_but_never_secrets() {
        let mut base = Manifest::new();
        base.set_config(var("PORT"), obj("obj_port_1"));
        base.set_policy(pol("rules"), obj("obj_policy_v1"));
        base.entries.insert(var("TOKEN"), sec("sec_rev_base"));

        let mut ours = base.clone();
        ours.set_policy(pol("rules"), obj("obj_policy_ours"));
        ours.entries.insert(var("TOKEN"), sec("sec_rev_ours"));

        let mut theirs = base.clone();
        theirs.set_policy(pol("rules"), obj("obj_policy_theirs"));
        theirs.entries.insert(var("TOKEN"), sec("sec_rev_theirs"));

        // The secret conflict survives every strategy...
        let conflicts = three_way_merge_with_strategy(&base, &ours, &theirs, MergeStrategy::Theirs)
            .expect_err("secret must still block");
        assert_eq!(
            conflicts,
            vec![Conflict::SecretConflict {
                name: var("TOKEN"),
                ours_rev: Some(rev("sec_rev_ours")),
                theirs_rev: Some(rev("sec_rev_theirs")),
            }]
        );

        // ...and with the secret aligned, both sides' policy disagreement
        // resolves by side.
        let mut theirs_aligned = theirs.clone();
        theirs_aligned
            .entries
            .insert(var("TOKEN"), sec("sec_rev_ours"));
        let merged =
            three_way_merge_with_strategy(&base, &ours, &theirs_aligned, MergeStrategy::Ours)
                .unwrap();
        assert_eq!(
            merged.policies.get(&pol("rules")),
            Some(&obj("obj_policy_ours"))
        );
        assert_eq!(merged.get(&var("TOKEN")), Some(&sec("sec_rev_ours")));
    }
}
