//! Error type for the repository crate.
//!
//! No variant ever carries secret material: the repository layer only ever
//! handles identifiers, revision IDs, and metadata — never plaintext secret
//! values.

use thiserror::Error;
use vaultx_types::{CommitId, ObjectId};

use crate::merge::Conflict;

/// Errors surfaced by the object store, refs, staging index, commits,
/// diff/merge helpers, and the [`Repository`](crate::Repository) facade.
#[derive(Debug, Error)]
pub enum RepoError {
    /// A referenced object is missing from the object store.
    #[error("object {0} not found")]
    ObjectNotFound(ObjectId),
    /// An object exists but its stored bytes fail hash verification or
    /// canonical decoding.
    #[error("object {id} is corrupt: {reason}")]
    CorruptObject {
        /// ID of the offending object.
        id: ObjectId,
        /// Human-readable reason; never contains secret material.
        reason: String,
    },
    /// A ref name (branch or environment) does not exist.
    #[error("ref `{0}` not found")]
    RefNotFound(String),
    /// Attempted to create a ref that already exists.
    #[error("ref `{0}` already exists")]
    RefAlreadyExists(String),
    /// The ref name violates naming rules.
    #[error("invalid ref `{0}`")]
    InvalidRef(String),
    /// An operation would move or remove an explicitly protected
    /// environment ref without the required force flag.
    #[error("environment ref `{0}` is protected; pass force to override")]
    ProtectedRef(String),
    /// A commit was requested while the staging index held no changes.
    #[error("staging index is empty; nothing to commit")]
    StagingEmpty,
    /// A manifest-level invariant was violated.
    #[error("manifest mismatch: {0}")]
    ManifestMismatch(String),
    /// A merge produced conflicts that require explicit resolution.
    #[error(
        "merge produced {} conflict(s): {}",
        .0.len(),
        .0.iter().map(|c| c.to_string()).collect::<Vec<_>>().join("; ")
    )]
    MergeConflict(Vec<Conflict>),
    /// Commit signature verification failed.
    #[error("commit signature invalid")]
    SignatureInvalid,
    /// A declared parent commit does not exist in history.
    #[error("parent commit {0} not found")]
    ParentNotFound(CommitId),
    /// A typed identifier could not be constructed from validated content.
    #[error(transparent)]
    IdConstruction(#[from] vaultx_types::TypeError),
    /// Filesystem failure.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// JSON encoding/decoding failure.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use vaultx_types::{CommitId, ObjectId};

    fn assert_no_secret_leak(err: &RepoError) {
        let rendered = err.to_string();
        assert!(!rendered.contains("hunter2"));
    }

    #[test]
    fn display_messages_are_stable_and_secret_safe() {
        let cases: Vec<RepoError> = vec![
            RepoError::ObjectNotFound(ObjectId::parse("obj_abc").unwrap()),
            RepoError::CorruptObject {
                id: ObjectId::parse("obj_abc").unwrap(),
                reason: "hash mismatch".to_owned(),
            },
            RepoError::RefNotFound("heads/main".to_owned()),
            RepoError::RefAlreadyExists("heads/feature".to_owned()),
            RepoError::InvalidRef("bad//name".to_owned()),
            RepoError::ProtectedRef("production".to_owned()),
            RepoError::StagingEmpty,
            RepoError::ManifestMismatch("duplicate entry".to_owned()),
            RepoError::SignatureInvalid,
            RepoError::ParentNotFound(CommitId::parse("cmt_deadbeef").unwrap()),
        ];
        for err in &cases {
            assert_no_secret_leak(err);
            assert!(!err.to_string().is_empty());
        }
        // Spot-check exact renderings for stability.
        assert_eq!(
            RepoError::ObjectNotFound(ObjectId::parse("obj_abc").unwrap()).to_string(),
            "object obj_abc not found"
        );
        assert_eq!(
            RepoError::StagingEmpty.to_string(),
            "staging index is empty; nothing to commit"
        );
    }

    #[test]
    fn io_and_json_errors_are_transparent() {
        let io_err: RepoError = std::io::Error::new(std::io::ErrorKind::NotFound, "missing").into();
        assert_eq!(io_err.to_string(), "missing");
        let json_err: RepoError = serde_json::from_str::<String>("{not json}")
            .expect_err("must fail")
            .into();
        assert!(!json_err.to_string().is_empty());
    }
}
