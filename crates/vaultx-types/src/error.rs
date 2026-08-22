//! Error type shared by vaultx identifier and name validation.

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TypeError {
    #[error("value must not be empty")]
    Empty,
    #[error("value must start with `{expected}`")]
    InvalidPrefix { expected: String },
    #[error("value contains invalid characters")]
    InvalidCharacters,
    #[error("value exceeds maximum length of {max}")]
    TooLong { max: usize },
}
