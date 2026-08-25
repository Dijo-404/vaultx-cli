//! Errors produced by the sync client.
//!
//! Display strings never embed tokens, assertions, or payload material.

use thiserror::Error;
use vaultx_crypto::error::CryptoError;

use crate::RefConflict;

/// Error type for [`crate::SyncService`] operations.
#[derive(Debug, Error)]
pub enum SyncError {
    /// The transport layer failed (network, encoding, in-process plumbing).
    #[error("transport failure: {0}")]
    Transport(String),

    /// The control plane rejected the request with this HTTP status. The
    /// server's reason text is deliberately not propagated verbatim so
    /// logs cannot leak request material echoed by a hostile endpoint.
    #[error("control plane returned status {status}")]
    Api {
        /// HTTP status of the rejection.
        status: u16,
    },

    /// The response did not conform to the sync protocol.
    #[error("protocol violation: {0}")]
    Protocol(&'static str),

    /// A downloaded object's recomputed canonical hash disagreed with its
    /// claimed id/hash; the object was not applied locally.
    #[error("content hash mismatch for {object}")]
    HashMismatch {
        /// Object id whose verification failed.
        object: String,
    },

    /// The control plane rejected the signed device identity.
    #[error("device signature rejected")]
    SignatureRejected,

    /// Local key storage failed while loading or creating the device seed.
    #[error(transparent)]
    Keyring(#[from] CryptoError),

    /// The local repository refused an operation.
    #[error("local repository error: {0}")]
    Repository(String),
}

impl From<vaultx_repository::RepoError> for SyncError {
    fn from(value: vaultx_repository::RepoError) -> Self {
        // RepoError displays secret-free static descriptions; flatten to a
        // String so the variant stays independent of the repository crate's
        // error evolution.
        Self::Repository(value.to_string())
    }
}

impl From<std::io::Error> for SyncError {
    fn from(value: std::io::Error) -> Self {
        Self::Repository(value.to_string())
    }
}

/// Convenience alias for client results.
pub type SyncResultOf<T> = Result<T, SyncError>;

/// Helper used by callers distinguishing conflicts from hard failures.
#[must_use]
pub fn conflict_summary(conflicts: &[RefConflict]) -> String {
    conflicts
        .iter()
        .map(|c| format!("{}/{} ({})", c.namespace_name(), c.name, c.reason))
        .collect::<Vec<_>>()
        .join(", ")
}

impl RefConflict {
    /// Namespace rendered as its wire name (`heads`/`environments`).
    #[must_use]
    pub fn namespace_name(&self) -> &'static str {
        match self.namespace {
            crate::RefNamespace::Heads => "heads",
            crate::RefNamespace::Environments => "environments",
        }
    }
}
