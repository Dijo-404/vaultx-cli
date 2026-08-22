//! Canonical object encoding, object store, refs, staging, commits,
//! branches, diff, merge, integrity verification.
//!
//! # Layout
//!
//! - [`object`]: canonical v1 encoding ([`ObjectEnvelope`]) and content
//!   addressing (`sha256` over canonical bytes).
//! - [`store`]: [`FileSystemObjectStore`] — atomic writes, hash-verified
//!   reads, whole-store sweeps.
//! - [`manifest`]: [`Manifest`] / [`ManifestEntry`] with typed helpers.
//!   Plaintext secret values never enter this crate: entries carry
//!   revisions and references only.
//! - [`commit`]: signed [`Commit`]s (Ed25519 via `vaultx-crypto`) whose
//!   [`CommitId`](vaultx_types::CommitId) shares its digest with the
//!   backing object ID.
//! - [`refs`]: branch/environment refs plus symbolic `HEAD`; environment
//!   refs carry protection metadata that refuses unforced moves.
//! - [`staging`]: persisted intent-to-change index (`.vaultx/index.json`).
//! - [`diff`]: metadata-only change classification between manifests.
//! - [`merge`]: three-way merge where secret revisions and policies always
//!   require explicit resolution.
//! - [`history`]: first-parent log walking and parent validation.
//! - [`repo`]: the [`Repository`] facade tying everything together.
//!
//! Canonical form v1: `serde_json` output with struct fields in
//! declaration order and `BTreeMap` keys lexicographically sorted; binary
//! payloads hex-encoded. See the [`object`] module for the full contract.

pub mod commit;
pub mod diff;
pub mod error;
pub mod history;
pub mod manifest;
pub mod merge;
pub mod object;
pub mod refs;
pub mod repo;
pub mod staging;
pub mod store;

pub use commit::Commit;
pub use diff::{compute_diff, render_diff, DiffEntry};
pub use error::RepoError;
pub use manifest::{DynamicProviderRef, Manifest, ManifestEntry};
pub use merge::{three_way_merge, Conflict};
pub use object::{hash_canonical, object_id, ObjectEnvelope, ObjectType};
pub use refs::{EnvironmentProtection, HeadTarget, RefNamespace, RefStore};
pub use repo::{Repository, StatusReport};
pub use staging::{StagedChange, StagingIndex};
pub use store::FileSystemObjectStore;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_api_surface_smoke() {
        // A tiny end-to-end pulse across re-exported types to guarantee
        // the facade stays importable as documented.
        let envelope = ObjectEnvelope::new(ObjectType::Manifest, b"{}".to_vec());
        let id = object_id(&envelope.canonical_bytes().unwrap()).unwrap();
        assert!(id.as_str().starts_with("obj_"));
        assert_eq!(hash_canonical(b"").len(), 32);

        let manifest = Manifest::new();
        assert!(Manifest::default() == manifest);

        let index = StagingIndex::default();
        assert!(index.is_empty());

        let empty_diff = compute_diff(&manifest, &manifest);
        assert!(empty_diff.is_empty());
        assert_eq!(render_diff(&empty_diff), "");

        assert!(matches!(
            Conflict::ConfigConflict {
                name: vaultx_types::VariableName::parse("X").unwrap(),
            },
            Conflict::ConfigConflict { .. }
        ));
    }
}
