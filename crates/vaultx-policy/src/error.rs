//! Error type for the policy crate.
//!
//! No variant ever carries secret material: the policy layer only ever
//! handles identifiers, hostnames, header names, and path patterns.

use thiserror::Error;

/// Errors surfaced by the policy loader, validator, and rule engine.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// The YAML document could not be parsed. The message carries serde
    /// diagnostics (including line/column when available) but never the
    /// surrounding file content.
    #[error("failed to parse policy: {0}")]
    ParseError(String),
    /// A field of an otherwise well-formed document failed semantic
    /// validation.
    #[error("invalid policy field `{field}`: {reason}")]
    InvalidPolicy {
        /// Dotted path of the offending field (e.g. `http.hosts`).
        field: String,
        /// Why the value is invalid.
        reason: String,
    },
    /// A request-path pattern violates the pattern grammar.
    #[error("invalid path pattern `{0}`")]
    InvalidPattern(String),
    /// Filesystem failure while reading a policy file.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl From<serde_yaml::Error> for PolicyError {
    fn from(err: serde_yaml::Error) -> Self {
        Self::ParseError(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_no_secret_leak(err: &PolicyError) {
        let rendered = err.to_string();
        assert!(!rendered.contains("hunter2"));
    }

    #[test]
    fn display_messages_are_stable_and_secret_safe() {
        let cases = vec![
            PolicyError::ParseError("unknown field `foo` at line 1 column 1".to_owned()),
            PolicyError::InvalidPolicy {
                field: "http.hosts".to_owned(),
                reason: "must contain at least one entry".to_owned(),
            },
            PolicyError::InvalidPattern("/repos/../**".to_owned()),
            PolicyError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "missing")),
        ];
        for err in &cases {
            assert_no_secret_leak(err);
            assert!(!err.to_string().is_empty());
        }
        assert_eq!(
            PolicyError::InvalidPattern("/a/**/b".to_owned()).to_string(),
            "invalid path pattern `/a/**/b`"
        );
    }

    #[test]
    fn serde_yaml_errors_map_to_parse_error() {
        let err: PolicyError = serde_yaml::from_str::<String>("name: [unclosed")
            .expect_err("must fail")
            .into();
        assert!(matches!(err, PolicyError::ParseError(_)));
    }
}
