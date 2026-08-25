//! Manifests: the variable/policy mapping captured by each commit.
//!
//! A [`Manifest`] maps [`VariableName`] to a [`ManifestEntry`] and
//! [`PolicyName`] to the [`ObjectId`] of its policy document. Both maps are
//! `BTreeMap`s, so canonical serialization orders keys lexicographically
//! (see `object` module docs for the full canonical form v1 contract).
//!
//! Plaintext secret values never appear here: secret entries reference
//! revisions by ID only.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use vaultx_types::{
    model::VariableKind, CredentialRef, ObjectId, PolicyName, SecretRevisionId, VariableName,
};

/// Reference to a dynamic provider, e.g. `aws.secrets-manager` or
/// `vaultx-broker/dynamic-db`.
///
/// Validated: non-empty, lowercase ASCII alphanumerics plus `.`, `-`, `/`,
/// `_`, at most 128 characters.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DynamicProviderRef(String);

impl DynamicProviderRef {
    /// Maximum accepted length in characters.
    pub const MAX_LEN: usize = 128;

    /// Parses and validates a provider reference.
    ///
    /// # Errors
    /// [`vaultx_types::TypeError`] when empty, over-long, or containing
    /// characters outside `[a-z0-9./_-]`.
    pub fn parse(value: &str) -> Result<Self, vaultx_types::TypeError> {
        if value.is_empty() {
            return Err(vaultx_types::TypeError::Empty);
        }
        if !value.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-' | '/' | '_')
        }) {
            return Err(vaultx_types::TypeError::InvalidCharacters);
        }
        let len = value.chars().count();
        if len > Self::MAX_LEN {
            return Err(vaultx_types::TypeError::TooLong { max: Self::MAX_LEN });
        }
        Ok(Self(value.to_owned()))
    }

    /// Underlying validated string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for DynamicProviderRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// One variable's binding inside a manifest.
///
/// The JSON shape is internally tagged under `"kind"` so the category is
/// explicit on disk and diff/merge logic can discriminate entries without
/// guessing from fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ManifestEntry {
    /// Non-secret config resolved into a content-addressed object.
    Config {
        /// Object holding the config value.
        object: ObjectId,
    },
    /// Local secret pinned to one revision; values live outside this store.
    Secret {
        /// Revision of the secret this entry binds.
        revision: SecretRevisionId,
    },
    /// Brokered credential bound to a specific secret revision.
    Brokered {
        /// Logical credential reference at the broker.
        credential: CredentialRef,
        /// Revision of the underlying secret material.
        revision: SecretRevisionId,
    },
    /// Dynamically issued value delegated to a provider.
    Dynamic {
        /// Provider that issues the value.
        provider: DynamicProviderRef,
    },
}

impl ManifestEntry {
    /// Category of this entry, aligned with
    /// [`vaultx_types::model::VariableKind`].
    #[must_use]
    pub fn kind(&self) -> VariableKind {
        match self {
            Self::Config { .. } => VariableKind::Config,
            Self::Secret { .. } => VariableKind::Secret,
            Self::Brokered { .. } => VariableKind::Brokered,
            Self::Dynamic { .. } => VariableKind::Dynamic,
        }
    }
}

/// The complete variable + policy state captured by a commit.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Variable bindings keyed by name.
    pub entries: BTreeMap<VariableName, ManifestEntry>,
    /// Policy documents referenced by object ID, keyed by policy name.
    pub policies: BTreeMap<PolicyName, ObjectId>,
}

impl Manifest {
    /// Empty manifest.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets (or replaces) a config entry.
    pub fn set_config(&mut self, name: VariableName, object: ObjectId) -> Option<ManifestEntry> {
        self.entries.insert(name, ManifestEntry::Config { object })
    }

    /// Sets (or replaces) a secret entry by revision.
    pub fn set_secret(
        &mut self,
        name: VariableName,
        revision: SecretRevisionId,
    ) -> Option<ManifestEntry> {
        self.entries
            .insert(name, ManifestEntry::Secret { revision })
    }

    /// Sets (or replaces) a brokered entry.
    pub fn set_brokered(
        &mut self,
        name: VariableName,
        credential: CredentialRef,
        revision: SecretRevisionId,
    ) -> Option<ManifestEntry> {
        self.entries.insert(
            name,
            ManifestEntry::Brokered {
                credential,
                revision,
            },
        )
    }

    /// Sets (or replaces) a dynamic-provider entry.
    pub fn set_dynamic(
        &mut self,
        name: VariableName,
        provider: DynamicProviderRef,
    ) -> Option<ManifestEntry> {
        self.entries
            .insert(name, ManifestEntry::Dynamic { provider })
    }

    /// Removes an entry, returning whatever was bound before.
    pub fn remove(&mut self, name: &VariableName) -> Option<ManifestEntry> {
        self.entries.remove(name)
    }

    /// Borrows the entry bound to `name`, if any.
    #[must_use]
    pub fn get(&self, name: &VariableName) -> Option<&ManifestEntry> {
        self.entries.get(name)
    }

    /// Binds `name` to the policy document stored under `policy_object`.
    pub fn set_policy(&mut self, name: PolicyName, policy_object: ObjectId) -> Option<ObjectId> {
        self.policies.insert(name, policy_object)
    }

    /// Unbinds a policy, returning the previously referenced object.
    pub fn remove_policy(&mut self, name: &PolicyName) -> Option<ObjectId> {
        self.policies.remove(name)
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

    #[test]
    fn dynamic_provider_ref_validation() {
        assert!(DynamicProviderRef::parse("aws.secrets-manager").is_ok());
        assert!(DynamicProviderRef::parse("broker/dyn_db-1").is_ok());
        assert_eq!(
            DynamicProviderRef::parse(""),
            Err(vaultx_types::TypeError::Empty)
        );
        assert_eq!(
            DynamicProviderRef::parse("AWS Bad"),
            Err(vaultx_types::TypeError::InvalidCharacters)
        );
        assert_eq!(
            DynamicProviderRef::parse(&"a".repeat(129)),
            Err(vaultx_types::TypeError::TooLong { max: 128 })
        );
        assert!(DynamicProviderRef::parse(&"a".repeat(128)).is_ok());
    }

    #[test]
    fn entry_kind_maps_to_variable_kind() {
        let cases = [
            (
                ManifestEntry::Config {
                    object: obj("obj_a"),
                },
                VariableKind::Config,
            ),
            (
                ManifestEntry::Secret {
                    revision: rev("sec_rev_1"),
                },
                VariableKind::Secret,
            ),
            (
                ManifestEntry::Brokered {
                    credential: cred("deploy-token"),
                    revision: rev("sec_rev_2"),
                },
                VariableKind::Brokered,
            ),
            (
                ManifestEntry::Dynamic {
                    provider: DynamicProviderRef::parse("aws.ssm").unwrap(),
                },
                VariableKind::Dynamic,
            ),
        ];
        for (entry, expected) in cases {
            assert_eq!(entry.kind(), expected);
        }
    }

    #[test]
    fn entry_crud_helpers_round_trip() {
        let mut manifest = Manifest::new();
        assert!(manifest.get(&var("DB_HOST")).is_none());

        manifest.set_config(var("DB_HOST"), obj("obj_host"));
        manifest.set_secret(var("DB_PASSWORD"), rev("sec_rev_7"));
        manifest.set_brokered(var("API_TOKEN"), cred("github-token"), rev("sec_rev_8"));
        manifest.set_dynamic(
            var("EPHEMERAL_DB_URL"),
            DynamicProviderRef::parse("broker/dynamic-postgres").unwrap(),
        );
        manifest.set_policy(PolicyName::parse("read_only").unwrap(), obj("obj_policy_1"));

        assert_eq!(
            manifest.get(&var("DB_HOST")).map(ManifestEntry::kind),
            Some(VariableKind::Config)
        );
        assert_eq!(
            manifest.get(&var("DB_PASSWORD")).map(ManifestEntry::kind),
            Some(VariableKind::Secret)
        );
        assert_eq!(
            manifest.get(&var("API_TOKEN")).map(ManifestEntry::kind),
            Some(VariableKind::Brokered)
        );
        assert_eq!(
            manifest
                .get(&var("EPHEMERAL_DB_URL"))
                .map(ManifestEntry::kind),
            Some(VariableKind::Dynamic)
        );

        // Replace returns prior binding.
        let previous = manifest.set_config(var("DB_HOST"), obj("obj_host_v2"));
        assert_eq!(
            previous,
            Some(ManifestEntry::Config {
                object: obj("obj_host")
            })
        );

        // Removal returns the removed entry and empties the slot.
        let removed = manifest.remove(&var("DB_HOST"));
        assert_eq!(
            removed,
            Some(ManifestEntry::Config {
                object: obj("obj_host_v2")
            })
        );
        assert!(manifest.get(&var("DB_HOST")).is_none());

        // Policy helpers.
        assert_eq!(
            manifest.set_policy(PolicyName::parse("read_only").unwrap(), obj("obj_policy_2")),
            Some(obj("obj_policy_1"))
        );
        assert_eq!(
            manifest.remove_policy(&PolicyName::parse("read_only").unwrap()),
            Some(obj("obj_policy_2"))
        );
    }

    #[test]
    fn manifest_serializes_deterministically_with_sorted_keys() {
        let mut first = Manifest::new();
        first.set_config(var("ZULU"), obj("obj_z"));
        first.set_secret(var("ALPHA"), rev("sec_rev_a"));
        first.set_config(var("MIKE"), obj("obj_m"));

        // Rebuild with different insertion order.
        let mut second = Manifest::new();
        second.set_secret(var("ALPHA"), rev("sec_rev_a"));
        second.set_config(var("MIKE"), obj("obj_m"));
        second.set_config(var("ZULU"), obj("obj_z"));

        let bytes_first = serde_json::to_vec(&first).unwrap();
        let bytes_second = serde_json::to_vec(&second).unwrap();

        assert_eq!(bytes_first, bytes_second, "insertion order must not matter");

        // Keys appear in sorted order in the encoded JSON.
        let text = String::from_utf8(bytes_first).unwrap();
        let alpha_pos = text.find("\"ALPHA\"").expect("alpha key");
        let mike_pos = text.find("\"MIKE\"").expect("mike key");
        let zulu_pos = text.find("\"ZULU\"").expect("zulu key");
        assert!(alpha_pos < mike_pos && mike_pos < zulu_pos);

        // Round trip preserves equality.
        let decoded: Manifest =
            serde_json::from_slice(&serde_json::to_vec(&first).unwrap()).unwrap();
        assert_eq!(decoded, first);
    }

    #[test]
    fn entry_json_shape_is_internally_tagged_and_stable() {
        let entry = ManifestEntry::Secret {
            revision: rev("sec_rev_42"),
        };
        assert_eq!(
            serde_json::to_string(&entry).unwrap(),
            "{\"kind\":\"secret\",\"revision\":\"sec_rev_42\"}"
        );

        let brokered = ManifestEntry::Brokered {
            credential: cred("deploy-token"),
            revision: rev("sec_rev_43"),
        };
        assert_eq!(
            serde_json::to_string(&brokered).unwrap(),
            "{\"kind\":\"brokered\",\"credential\":\"deploy-token\",\"revision\":\"sec_rev_43\"}"
        );

        // Unknown kinds fail loudly rather than silently degrading.
        assert!(serde_json::from_str::<ManifestEntry>("{\"kind\":\"mystery\"}").is_err());
    }

    #[test]
    fn deserialization_rejects_invalid_nested_ids() {
        assert!(serde_json::from_str::<Manifest>(
            r#"{"entries":{"BAD_NAME":{"kind":"config","object":"nope"}},"policies":{}}"#
        )
        .is_err());
    }
}

/// Property tests for manifest canonical serialization (plan §43:
/// `decode(encode(x)) == x` for canonical domain objects, "hash
/// canonicalization is stable" under differing insertion orderings).
#[cfg(test)]
mod proptests {
    use super::*;
    use crate::object::{hash_canonical, object_id, ObjectEnvelope, ObjectType};
    use proptest::prelude::*;

    /// Content for generated IDs. The first character is drawn from
    /// letters that begin no registered ID prefix (`s`, `w`, `p`, `e`,
    /// `c`, `o`, `a` are avoided) so prefixed-ID parsing never rejects a
    /// generated value for nested-family embedding.
    fn safe_id_content() -> impl Strategy<Value = String> {
        "(b|d|f|g|h|i|j|k|l|m|n|q|r|t|u|v|x|y|z)[a-z0-9_]{2,12}"
    }

    fn variable_names() -> impl Strategy<Value = VariableName> {
        "[A-Z][A-Z0-9_]{0,11}".prop_map(|name| VariableName::parse(&name).unwrap())
    }

    fn policy_names() -> impl Strategy<Value = PolicyName> {
        "[a-z][a-z0-9_]{1,11}".prop_map(|name| PolicyName::parse(&name).unwrap())
    }

    fn any_entry() -> impl Strategy<Value = ManifestEntry> {
        prop_oneof![
            safe_id_content().prop_map(|content| ManifestEntry::Config {
                object: ObjectId::parse(&format!("obj_{content}")).unwrap(),
            }),
            safe_id_content().prop_map(|content| ManifestEntry::Secret {
                revision: SecretRevisionId::parse(&format!("sec_rev_{content}")).unwrap(),
            }),
            (safe_id_content(), safe_id_content()).prop_map(|(credential, revision)| {
                ManifestEntry::Brokered {
                    credential: CredentialRef::parse(&credential).unwrap(),
                    revision: SecretRevisionId::parse(&format!("sec_rev_{revision}")).unwrap(),
                }
            }),
            "[a-z][a-z0-9./_-]{2,15}".prop_map(|provider| ManifestEntry::Dynamic {
                provider: DynamicProviderRef::parse(&provider).unwrap(),
            }),
        ]
    }

    /// Builds a manifest by folding generated `(name, entry)` pairs into
    /// the underlying maps; duplicate names collapse map-style.
    fn build_manifest(
        entries: Vec<(VariableName, ManifestEntry)>,
        policies: Vec<(PolicyName, String)>,
    ) -> Manifest {
        let mut manifest = Manifest::new();
        for (name, entry) in entries {
            manifest.entries.insert(name, entry);
        }
        for (name, content) in policies {
            manifest
                .policies
                .insert(name, ObjectId::parse(&format!("obj_{content}")).unwrap());
        }
        manifest
    }

    fn envelope_of(manifest: &Manifest) -> (ObjectEnvelope, [u8; 32], ObjectId) {
        let payload = serde_json::to_vec(manifest).unwrap();
        let envelope = ObjectEnvelope::new(ObjectType::Manifest, payload);
        let bytes = envelope.canonical_bytes().unwrap();
        let digest = hash_canonical(&bytes);
        let id = object_id(&bytes).unwrap();
        (envelope, digest, id)
    }

    proptest! {
        /// P1: random manifests mixing all four entry kinds plus policy
        /// bindings survive JSON encode → decode and the typed
        /// envelope-payload decode path with full equality.
        #[test]
        fn manifest_round_trips_through_json_and_envelope(
            entries in proptest::collection::vec((variable_names(), any_entry()), 0..=6usize),
            policies in proptest::collection::vec((policy_names(), safe_id_content()), 0..=4usize),
        ) {
            let manifest = build_manifest(entries, policies);

            let bytes = serde_json::to_vec(&manifest).unwrap();
            let decoded: Manifest = serde_json::from_slice(&bytes).unwrap();
            prop_assert_eq!(&decoded, &manifest);

            // Re-encoding is byte-stable.
            prop_assert_eq!(serde_json::to_vec(&decoded).unwrap(), bytes);

            // And the repository envelope path recovers the same manifest.
            let envelope =
                ObjectEnvelope::new(ObjectType::Manifest, serde_json::to_vec(&manifest).unwrap());
            prop_assert_eq!(&envelope.decode_payload::<Manifest>().unwrap(), &manifest);
        }

        /// P2: the same logical manifest built with opposite insertion
        /// orderings serializes to identical bytes and hashes to the same
        /// object ID — key ordering must never influence content
        /// addressing.
        #[test]
        fn hash_is_stable_under_differing_insertion_order(
            entries in proptest::collection::vec((variable_names(), any_entry()), 1..=6usize),
            policies in proptest::collection::vec((policy_names(), safe_id_content()), 0..=4usize),
        ) {
            let forward = build_manifest(entries.clone(), policies.clone());

            // Reverse insertion of the *resolved* map contents: identical
            // logical content regardless of how duplicates collapsed.
            let mut backward = Manifest::new();
            for (name, entry) in forward.entries.iter().rev() {
                backward.entries.insert(name.clone(), entry.clone());
            }
            for (name, object) in forward.policies.iter().rev() {
                backward.policies.insert(name.clone(), object.clone());
            }
            prop_assert_eq!(&forward, &backward);

            let (_, digest_forward, id_forward) = envelope_of(&forward);
            let (_, digest_backward, id_backward) = envelope_of(&backward);
            prop_assert_eq!(digest_forward, digest_backward);
            prop_assert_eq!(id_forward, id_backward);
        }
    }
}
