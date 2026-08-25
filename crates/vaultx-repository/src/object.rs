//! Canonical object encoding and content addressing.
//!
//! # Canonical form v1
//!
//! The canonical byte form of any repository object is the exact output of
//! `serde_json::to_vec` applied to its typed representation, under these
//! rules:
//!
//! 1. **Struct fields** serialize in declaration order.
//! 2. **Maps** are `BTreeMap`s; keys serialize in ascending lexicographic
//!    order (`serde_json`'s default map is `BTreeMap`-backed because the
//!    non-default `preserve_order` feature is deliberately not enabled).
//! 3. **Binary payloads** are encoded as lowercase hexadecimal strings so
//!    canonical JSON stays compact and human-inspectable while remaining
//!    fully deterministic.
//!
//! An object's identifier is `sha256(canonical_bytes)`, rendered as an
//! [`ObjectId`] with the `obj_` prefix plus the 64 lowercase hex digits.
//! Identical content therefore always yields identical bytes and identical
//! IDs — the property that makes the object store content-addressed and its
//! integrity checks meaningful.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vaultx_types::ObjectId;

use crate::error::RepoError;

/// Version of the canonical object envelope format written by this crate.
pub const OBJECT_FORMAT_VERSION: u16 = 1;

/// Categories of objects addressable in the object store.
///
/// Plaintext secret values are excluded from content-addressed objects:
/// secret-bearing categories only ever reference revisions by ID or carry
/// metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectType {
    /// A single resolved config value (non-secret).
    ConfigValue,
    /// A manifest mapping variable names to entries and policies to objects.
    Manifest,
    /// A signed commit pointing at a manifest object.
    Commit,
    /// A policy definition document.
    Policy,
    /// A reference binding a policy pack into a project.
    PolicyPackReference,
    /// An environment definition document.
    EnvironmentDefinition,
    /// Metadata about a stored secret revision (never the value itself).
    SecretRevisionMetadata,
}

mod payload_hex {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        hex::encode(bytes).serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        hex::decode(&text).map_err(serde::de::Error::custom)
    }
}

/// The wire/canonical envelope wrapping every stored object: a format
/// version tag, the object category, and the opaque-but-canonical payload
/// bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectEnvelope {
    /// Envelope format version; currently always
    /// [`OBJECT_FORMAT_VERSION`] (=1).
    pub format: u16,
    /// Which category of object this envelope holds.
    pub object_type: ObjectType,
    /// Canonical payload bytes, hex-encoded in JSON for determinism.
    #[serde(with = "payload_hex")]
    pub payload: Vec<u8>,
}

impl ObjectEnvelope {
    /// Builds a new envelope at the current format version.
    #[must_use]
    pub fn new(object_type: ObjectType, payload: Vec<u8>) -> Self {
        Self {
            format: OBJECT_FORMAT_VERSION,
            object_type,
            payload,
        }
    }

    /// Canonical v1 bytes of this envelope (see module docs).
    ///
    /// # Errors
    /// Propagates serialization failures as [`RepoError::Json`].
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RepoError> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Decodes a typed payload out of the envelope.
    ///
    /// # Type Parameters
    /// * `T`: the expected payload type.
    ///
    /// # Errors
    /// [`RepoError::Json`] when the payload does not decode as `T`.
    pub fn decode_payload<T: serde::de::DeserializeOwned>(&self) -> Result<T, RepoError> {
        Ok(serde_json::from_slice(&self.payload)?)
    }
}

/// SHA-256 digest over canonical bytes.
#[must_use]
pub fn hash_canonical(canonical: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(canonical);
    hasher.finalize().into()
}

/// Content ID derived from canonical bytes: `obj_<64 lowercase hex>`.
///
/// # Errors
/// [`RepoError::IdConstruction`] if the typed-ID parser rejects the
/// constructed string (cannot happen with valid hex input; kept total).
pub fn object_id(canonical: &[u8]) -> Result<ObjectId, RepoError> {
    ObjectId::parse(&format!(
        "{}{}",
        ObjectId::PREFIX,
        hex::encode(hash_canonical(canonical))
    ))
    .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest_envelope() -> ObjectEnvelope {
        ObjectEnvelope::new(
            ObjectType::Manifest,
            br#"{"entries":{},"policies":{}}"#.to_vec(),
        )
    }

    #[test]
    fn object_type_serializes_snake_case() {
        for (kind, expected) in [
            (ObjectType::ConfigValue, "\"config_value\""),
            (ObjectType::Manifest, "\"manifest\""),
            (ObjectType::Commit, "\"commit\""),
            (ObjectType::Policy, "\"policy\""),
            (ObjectType::PolicyPackReference, "\"policy_pack_reference\""),
            (
                ObjectType::EnvironmentDefinition,
                "\"environment_definition\"",
            ),
            (
                ObjectType::SecretRevisionMetadata,
                "\"secret_revision_metadata\"",
            ),
        ] {
            assert_eq!(serde_json::to_string(&kind).unwrap(), expected);
            assert_eq!(serde_json::from_str::<ObjectType>(expected).unwrap(), kind);
        }
    }

    #[test]
    fn canonical_encoding_is_stable_and_deterministic() {
        let first = sample_manifest_envelope();
        let second = sample_manifest_envelope();
        assert_eq!(
            first.canonical_bytes().unwrap(),
            second.canonical_bytes().unwrap()
        );

        let id_first = object_id(&first.canonical_bytes().unwrap()).unwrap();
        let id_second = object_id(&second.canonical_bytes().unwrap()).unwrap();
        assert_eq!(id_first, id_second);
        assert!(id_first.as_str().starts_with("obj_"));
        // obj_ + 64 hex chars.
        assert_eq!(id_first.as_str().len(), 4 + 64);
    }

    #[test]
    fn different_content_yields_different_ids() {
        let a = ObjectEnvelope::new(ObjectType::Manifest, b"one".to_vec());
        let b = ObjectEnvelope::new(ObjectType::Manifest, b"two".to_vec());
        assert_ne!(
            object_id(&a.canonical_bytes().unwrap()).unwrap(),
            object_id(&b.canonical_bytes().unwrap()).unwrap()
        );
        // Even same bytes but different type differ.
        let c = ObjectEnvelope::new(ObjectType::Policy, b"two".to_vec());
        assert_ne!(
            object_id(&b.canonical_bytes().unwrap()).unwrap(),
            object_id(&c.canonical_bytes().unwrap()).unwrap()
        );
    }

    #[test]
    fn envelope_round_trips_through_canonical_bytes() {
        let envelope = sample_manifest_envelope();
        let bytes = envelope.canonical_bytes().unwrap();
        let decoded: ObjectEnvelope = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded, envelope);

        // Payload is rendered as a lowercase hex string in canonical JSON.
        let json = String::from_utf8(bytes).unwrap();
        assert!(json.contains("\"payload\":\""));
        assert!(json.contains("7b22656e"));
    }

    #[test]
    fn decode_payload_recovers_typed_data() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Inner {
            version: u8,
        }
        let inner = Inner { version: 3 };
        let payload = serde_json::to_vec(&inner).unwrap();
        let envelope = ObjectEnvelope::new(ObjectType::EnvironmentDefinition, payload);
        assert_eq!(envelope.decode_payload::<Inner>().unwrap(), inner);
    }
}

/// Property tests for canonical encoding and content addressing
/// (plan §43: `decode(encode(x)) == x`, "hash canonicalization is
/// stable").
#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn any_object_type() -> impl Strategy<Value = ObjectType> {
        prop_oneof![
            Just(ObjectType::ConfigValue),
            Just(ObjectType::Manifest),
            Just(ObjectType::Commit),
            Just(ObjectType::Policy),
            Just(ObjectType::PolicyPackReference),
            Just(ObjectType::EnvironmentDefinition),
            Just(ObjectType::SecretRevisionMetadata),
        ]
    }

    proptest! {
        /// P1: every envelope — arbitrary payloads across all seven
        /// categories — survives encode → decode with byte-exact payload
        /// and identical re-encoded canonical bytes.
        #[test]
        fn envelope_round_trips_through_canonical_bytes(
            kind in any_object_type(),
            payload in proptest::collection::vec(any::<u8>(), 0..=512usize),
        ) {
            let envelope = ObjectEnvelope::new(kind, payload);
            let bytes = envelope.canonical_bytes().unwrap();
            let decoded: ObjectEnvelope = serde_json::from_slice(&bytes).unwrap();

            prop_assert_eq!(&decoded.object_type, &envelope.object_type);
            prop_assert_eq!(&decoded.format, &envelope.format);
            prop_assert_eq!(&decoded.payload, &envelope.payload);
            prop_assert_eq!(&decoded, &envelope);

            // The canonical form is a fixed point of its own decoder.
            prop_assert_eq!(decoded.canonical_bytes().unwrap(), bytes);
        }

        /// P2: independently constructed instances of the same logical
        /// envelope always hash to the same digest and object ID.
        #[test]
        fn hash_and_object_id_are_stable_across_fresh_instances(
            kind in any_object_type(),
            payload in proptest::collection::vec(any::<u8>(), 0..=512usize),
        ) {
            let first = ObjectEnvelope::new(kind, payload.clone());
            let second = ObjectEnvelope::new(kind, payload);

            let bytes_first = first.canonical_bytes().unwrap();
            let bytes_second = second.canonical_bytes().unwrap();
            prop_assert_eq!(
                hash_canonical(&bytes_first),
                hash_canonical(&bytes_second)
            );
            prop_assert_eq!(
                object_id(&bytes_first).unwrap(),
                object_id(&bytes_second).unwrap()
            );
        }

        /// Sanity direction of P2: distinct content must not collide on
        /// IDs (256 random pairs; SHA-256 makes accidental collision a
        /// non-event while still catching encoding bugs that merge
        /// different payloads).
        #[test]
        fn distinct_envelopes_hash_differently(
            kind_a in any_object_type(),
            kind_b in any_object_type(),
            payload_a in proptest::collection::vec(any::<u8>(), 1..=512usize),
            payload_b in proptest::collection::vec(any::<u8>(), 1..=512usize),
        ) {
            prop_assume!(payload_a != payload_b);
            let id = |kind: ObjectType, payload: &[u8]| {
                object_id(&ObjectEnvelope::new(kind, payload.to_vec()).canonical_bytes().unwrap())
                    .unwrap()
            };
            prop_assert_ne!(id(kind_a, &payload_a), id(kind_b, &payload_b));
        }
    }
}
