//! Failures surfaced by the terminal UI layer.
//!
//! Messages carry only transport, service-classification, or
//! policy-validation text; no variant ever embeds secret values.

use thiserror::Error;

/// Errors returned by [`crate::run`].
#[derive(Debug, Error)]
pub enum TuiError {
    /// Terminal setup, event polling, or rendering failed.
    #[error("terminal i/o failure: {0}")]
    Terminal(#[from] std::io::Error),
}
