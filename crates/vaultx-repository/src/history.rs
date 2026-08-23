//! Commit history traversal and ancestry validation.
//!
//! History is walked **first-parent** from a head commit (newest first) —
//! the linear view familiar from `git log --first-parent`. Merge commits
//! carry additional parents, which are validated on creation but not
//! expanded by the default walk; use [`History::find_commit`] to inspect
//! any reachable commit directly. A visited-set guards against cycles in
//! corrupted repositories, and a broken chain surfaces as an error rather
//! than being silently truncated.

use vaultx_types::CommitId;

use crate::commit::Commit;
use crate::error::RepoError;
use crate::object::ObjectType;
use crate::store::FileSystemObjectStore;

/// Read-only helpers over the object store for commit history.
#[derive(Clone, Copy, Debug)]
pub struct History<'a> {
    store: &'a FileSystemObjectStore,
}

impl<'a> History<'a> {
    /// Binds history helpers to an object store.
    #[must_use]
    pub fn new(store: &'a FileSystemObjectStore) -> Self {
        Self { store }
    }

    /// Loads and decodes the commit identified by `id`.
    ///
    /// Because [`CommitId`] and the backing object's
    /// [`ObjectId`](vaultx_types::ObjectId) share one
    /// digest (see `commit` module docs), resolution needs no indirection.
    ///
    /// # Errors
    /// * [`RepoError::ObjectNotFound`] when absent.
    /// * [`RepoError::CorruptObject`] when stored bytes fail integrity or
    ///   decode as something other than a commit.
    pub fn find_commit(&self, id: &CommitId) -> Result<Commit, RepoError> {
        let object_id = vaultx_types::ObjectId::parse(&format!(
            "{}{}",
            vaultx_types::ObjectId::PREFIX,
            &id.as_str()[CommitId::PREFIX.len()..]
        ))?;
        let envelope = self.store.get(&object_id)?;
        if envelope.object_type != ObjectType::Commit {
            return Err(RepoError::CorruptObject {
                id: object_id,
                reason: format!("expected a commit object, found {:?}", envelope.object_type),
            });
        }
        Ok(serde_json::from_slice(&envelope.payload)?)
    }

    /// Walks the first-parent chain starting at `head`, newest first,
    /// returning at most `limit` entries (`limit` 0 yields none).
    ///
    /// # Errors
    /// Propagates lookup/decode failures for any visited commit, including
    /// missing parents deeper in the chain.
    pub fn log(&self, head: &CommitId, limit: usize) -> Result<Vec<(CommitId, Commit)>, RepoError> {
        let mut out = Vec::new();
        let mut cursor = Some(head.clone());
        let mut visited = std::collections::BTreeSet::new();

        while let Some(id) = cursor {
            if out.len() >= limit || !visited.insert(id.clone()) {
                break;
            }
            let commit = self.find_commit(&id)?;
            cursor = commit.parents.first().cloned();
            out.push((id, commit));
        }
        Ok(out)
    }

    /// Validates that every declared parent exists and decodes as a commit
    /// object. Called before a new commit is persisted so history can
    /// never gain a dangling reference.
    ///
    /// # Errors
    /// [`RepoError::ParentNotFound`] naming the first failing parent.
    pub fn validate_parents(&self, parents: &[CommitId]) -> Result<(), RepoError> {
        for parent in parents {
            if self.find_commit(parent).is_err() {
                return Err(RepoError::ParentNotFound(parent.clone()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commit::commit_envelope;
    use crate::object::ObjectEnvelope;
    use vaultx_crypto::signature::SigningKeyPair;
    use vaultx_types::{IdentityRef, ObjectId};

    struct Fixture {
        _guard: tempfile::TempDir,
        store: FileSystemObjectStore,
    }

    fn setup() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let objects_dir = dir.path().join("objects");
        Fixture {
            _guard: dir,
            store: FileSystemObjectStore::new(objects_dir),
        }
    }

    fn signed_commit(parents: Vec<CommitId>, tag: &str, pair: &SigningKeyPair) -> Commit {
        Commit::new(
            parents,
            ObjectId::parse("obj_manifest").unwrap(),
            IdentityRef::parse("user:test").unwrap(),
            format!("commit {tag}"),
        )
        .sign_with(pair)
        .unwrap()
    }

    fn put_commit(store: &FileSystemObjectStore, commit: &Commit) -> CommitId {
        let envelope = commit_envelope(commit).unwrap();
        let stored_id = store.put(&envelope).unwrap();
        let derived_id = commit.commit_id().unwrap();
        assert_eq!(&stored_id.as_str()[4..], &derived_id.as_str()[4..]);
        derived_id
    }

    #[test]
    fn find_commit_round_trips_through_the_object_store() {
        let fx = setup();
        let pair = SigningKeyPair::generate();
        let commit = signed_commit(Vec::new(), "root", &pair);
        let id = put_commit(&fx.store, &commit);

        let found = History::new(&fx.store).find_commit(&id).unwrap();
        assert_eq!(found, commit);
    }

    #[test]
    fn find_commit_rejects_missing_and_wrong_type() {
        let fx = setup();
        let history = History::new(&fx.store);

        let missing = CommitId::parse("cmt_nope").unwrap();
        assert!(matches!(
            history.find_commit(&missing),
            Err(RepoError::ObjectNotFound(_))
        ));

        // Store a manifest where a commit should be.
        let envelope = ObjectEnvelope::new(
            ObjectType::Manifest,
            br#"{"entries":{},"policies":{}}"#.to_vec(),
        );
        let oid = fx.store.put(&envelope).unwrap();
        let wrong_type = CommitId::parse(&format!("cmt_{}", &oid.as_str()[4..])).unwrap();
        match history.find_commit(&wrong_type) {
            Err(RepoError::CorruptObject { reason, .. }) => {
                assert!(reason.contains("expected a commit object"));
            }
            other => panic!("expected wrong-type corruption, got {other:?}"),
        }
    }

    #[test]
    fn log_walks_first_parent_chain_newest_first() {
        let fx = setup();
        let pair = SigningKeyPair::generate();
        let history = History::new(&fx.store);

        let c1 = signed_commit(Vec::new(), "one", &pair);
        let id1 = put_commit(&fx.store, &c1);
        let c2 = signed_commit(vec![id1.clone()], "two", &pair);
        let id2 = put_commit(&fx.store, &c2);
        let c3 = signed_commit(vec![id2.clone()], "three", &pair);
        let id3 = put_commit(&fx.store, &c3);

        let full = history.log(&id3, usize::MAX).unwrap();
        assert_eq!(
            full.iter()
                .map(|(id, c)| (id.clone(), c.message.clone()))
                .collect::<Vec<_>>(),
            vec![
                (id3.clone(), "commit three".to_owned()),
                (id2.clone(), "commit two".to_owned()),
                (id1.clone(), "commit one".to_owned()),
            ]
        );

        // Limit truncates from the oldest side.
        assert_eq!(history.log(&id3, 2).unwrap().len(), 2);
        assert_eq!(history.log(&id3, 0).unwrap().len(), 0);

        // A merge-style second parent does not extend the default walk:
        // first-parent only reaches three commits.
        let merge = signed_commit(vec![id3.clone(), id1.clone()], "merge", &pair);
        let mid = put_commit(&fx.store, &merge);
        assert_eq!(history.log(&mid, usize::MAX).unwrap().len(), 4);
    }

    #[test]
    fn log_surfaces_broken_chains_loudly() {
        // A commit whose parent ID was never persisted must produce an
        // error rather than silently truncating history.
        let fx = setup();
        let pair = SigningKeyPair::generate();

        let ghost =
            CommitId::parse("cmt_ghost00000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        let orphan = signed_commit(vec![ghost], "orphan", &pair);
        let orphan_id = put_commit(&fx.store, &orphan);

        match History::new(&fx.store).log(&orphan_id, usize::MAX) {
            Err(RepoError::ObjectNotFound(missing)) => {
                assert!(
                    missing.as_str().starts_with("obj_ghost"),
                    "missing parent surfaced as {}",
                    missing
                );
            }
            other => panic!("expected broken-chain error, got {other:?}"),
        }
    }

    #[test]
    fn validate_parents_accepts_existing_and_rejects_missing() {
        let fx = setup();
        let pair = SigningKeyPair::generate();
        let root = signed_commit(Vec::new(), "root", &pair);
        let root_id = put_commit(&fx.store, &root);

        let history = History::new(&fx.store);
        history
            .validate_parents(std::slice::from_ref(&root_id))
            .unwrap();
        history.validate_parents(&[]).unwrap();

        let ghost =
            CommitId::parse("cmt_ghost00000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        assert!(matches!(
            history.validate_parents(&[ghost]),
            Err(RepoError::ParentNotFound(_))
        ));
    }
}
