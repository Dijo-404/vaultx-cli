//! Setup errors for the shared sync plumbing (session, remotes,
//! transport construction).
//!
//! `Usage` marks operator-fixable configuration problems (not logged in,
//! unknown remote name, server/remote mismatch); `Io` wraps filesystem
//! and client-construction failures. Display strings never embed token
//! material.

use thiserror::Error;

/// Error raised while assembling a control-plane session.
#[derive(Debug, Error)]
pub enum SyncSetupError {
    /// Operator-fixable configuration problem; payload is the message.
    #[error("{0}")]
    Usage(String),

    /// Filesystem or HTTP-client failure.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Convenience alias for setup results.
pub type SyncSetupResult<T> = Result<T, SyncSetupError>;

/// Wraps a plain message into an [`SyncSetupError::Io`], mirroring the
/// historical "runtime message" error shape of the CLI surface.
pub(crate) fn io_message(message: impl Into<String>) -> SyncSetupError {
    SyncSetupError::Io(std::io::Error::other(message.into()))
}
