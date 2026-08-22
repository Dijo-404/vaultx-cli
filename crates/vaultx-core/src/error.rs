//! The [`CoreError`] type surfaced by every vaultx-core service.
//!
//! No variant ever carries secret material: core services handle
//! identifiers, config values, and metadata only (secret values are not
//! stored in v1; see the crate-level docs for the deferral).

use std::path::PathBuf;

use thiserror::Error;

use vaultx_audit::AuditError;
use vaultx_crypto::error::CryptoError;
use vaultx_policy::PolicyError;
use vaultx_repository::RepoError;
use vaultx_types::TypeError;

/// Result alias used throughout vaultx-core.
pub type CoreResult<T> = Result<T, CoreError>;

/// Errors produced by the application services shared by CLI and TUI.
#[derive(Debug, Error)]
pub enum CoreError {
    /// The target directory does not hold an initialized vaultx project.
    #[error("not a vaultx repository: {0}")]
    NotARepository(PathBuf),
    /// The target directory already holds an initialized project.
    #[error("already initialized: {0}")]
    AlreadyInitialized(PathBuf),
    /// A variable name failed validation.
    #[error("invalid variable name `{0}`")]
    InvalidVariableName(String),
    /// A variable was expected to exist but is not bound.
    #[error("variable `{0}` not found")]
    VariableNotFound(String),
    /// A policy document could not be parsed, validated, or matched the
    /// requested name.
    #[error("policy load failed: {0}")]
    PolicyLoadFailed(String),
    /// An agent identity file does not exist.
    #[error("agent `{0}` not found")]
    AgentNotFound(String),
    /// An environment ref does not exist.
    #[error("environment `{0}` not found")]
    EnvironmentNotFound(String),
    /// The operation is intentionally unavailable in this build of the
    /// services (e.g. blocked on a deferred integration).
    #[error("unsupported operation: {0}")]
    UnsupportedOperation(String),
    /// A file or ref that was expected to be unique already exists.
    #[error("`{0}` already exists")]
    AlreadyExists(String),
    /// Underlying repository failure.
    #[error(transparent)]
    Repo(#[from] RepoError),
    /// Underlying cryptographic failure.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// Underlying policy-engine failure.
    #[error(transparent)]
    Policy(#[from] PolicyError),
    /// Underlying audit-store failure.
    #[error(transparent)]
    Audit(#[from] AuditError),
    /// A typed identifier or name failed validation.
    #[error(transparent)]
    Id(#[from] TypeError),
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

    fn assert_display_is_secret_safe(err: &CoreError) {
        let rendered = err.to_string();
        assert!(!rendered.contains("hunter2"));
        assert!(!rendered.is_empty());
    }

    #[test]
    fn display_messages_are_stable_and_secret_safe() {
        let cases: Vec<CoreError> = vec![
            CoreError::NotARepository(PathBuf::from("/tmp/project")),
            CoreError::AlreadyInitialized(PathBuf::from("/tmp/project")),
            CoreError::InvalidVariableName("bad-name".to_owned()),
            CoreError::VariableNotFound("DB_HOST".to_owned()),
            CoreError::PolicyLoadFailed("parse error".to_owned()),
            CoreError::AgentNotFound("ghost".to_owned()),
            CoreError::EnvironmentNotFound("production".to_owned()),
            CoreError::UnsupportedOperation("not yet".to_owned()),
            CoreError::AlreadyExists("agent `ci`".to_owned()),
            CoreError::Repo(RepoError::StagingEmpty),
            CoreError::Id(TypeError::Empty),
        ];
        for err in &cases {
            assert_display_is_secret_safe(err);
        }
        assert_eq!(
            CoreError::NotARepository(PathBuf::from("/tmp/project")).to_string(),
            "not a vaultx repository: /tmp/project"
        );
        assert_eq!(
            CoreError::VariableNotFound("DB_HOST".to_owned()).to_string(),
            "variable `DB_HOST` not found"
        );
    }

    #[test]
    fn transparent_conversions_render_inner_messages() {
        let io_err: CoreError = std::io::Error::new(std::io::ErrorKind::NotFound, "gone").into();
        assert_eq!(io_err.to_string(), "gone");

        let repo_err: CoreError = RepoError::StagingEmpty.into();
        assert_eq!(
            repo_err.to_string(),
            "staging index is empty; nothing to commit"
        );
    }
}
