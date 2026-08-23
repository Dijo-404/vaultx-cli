//! Errors surfaced by pack parsing, validation, compilation, and loading.
//!
//! No variant ever carries secret material: packs describe identifiers,
//! hostnames, header names, and patterns only.

use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PackError {
    /// The YAML document could not be parsed (including unknown-field
    /// rejections from `deny_unknown_fields`).
    #[error("failed to parse policy pack: {0}")]
    Parse(String),
    /// A field of an otherwise well-formed pack failed semantic
    /// validation.
    #[error("invalid pack field `{field}`: {reason}")]
    InvalidField {
        /// Dotted path of the offending field.
        field: String,
        /// Why the value is invalid.
        reason: String,
    },
    /// The pack requests a credential injection template the broker does
    /// not implement yet (or that packs may not select).
    #[error("injection template `{injection}` cannot be used in a policy pack: {reason}")]
    UnsupportedInjection {
        /// Canonical kebab-case name of the rejected template.
        injection: String,
        /// Why the template is unavailable.
        reason: String,
    },
    /// A host is syntactically valid but forbidden by broker invariants
    /// (private names, literal IPs, cloud metadata endpoints).
    #[error("`{host}` cannot be targeted by a policy pack: {reason}")]
    ForbiddenHost {
        /// The offending hostname.
        host: String,
        /// Why the host is forbidden.
        reason: String,
    },
    /// A declared body-size limit exceeds its global cap.
    #[error("`{field}` limit of {value} bytes exceeds the global cap of {max} bytes")]
    LimitTooLarge {
        /// Dotted path of the offending limit.
        field: String,
        /// Declared value.
        value: u64,
        /// Maximum permitted value.
        max: u64,
    },
    /// A path placeholder has no entry in the declared `variables` map.
    #[error("path `{path}` uses placeholder `{{{placeholder}}}` that is missing from `request.variables`")]
    UndeclaredPlaceholder {
        /// Path template containing the placeholder.
        path: String,
        /// Placeholder name without braces.
        placeholder: String,
    },
    /// Two files in one directory declare the same capability name.
    #[error("duplicate capability name `{0}`")]
    DuplicateCapability(String),
    /// Two capability names differing only in their dot/underscore
    /// layout (`a.b` vs `a_b`) derive to the same policy name; directory
    /// loading rejects such collisions up front.
    #[error(
        "capability name `{0}` maps onto a policy name already claimed by another capability; \
         rename one of them using either dots or underscores consistently"
    )]
    AmbiguousCapabilityName(String),
    /// A per-file failure inside a directory scan; names the offending
    /// file so aggregate operations point at the right input.
    #[error("{path}: {source}")]
    File {
        /// File being processed.
        path: PathBuf,
        /// Underlying parse/validation failure.
        #[source]
        source: Box<PackError>,
    },
    /// Filesystem failure while reading a pack file or directory.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl From<serde_yaml::Error> for PackError {
    fn from(err: serde_yaml::Error) -> Self {
        Self::Parse(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_messages_are_secret_safe_and_stable() {
        let cases = [
            PackError::Parse("unknown field `foo` at line 1".to_owned()),
            PackError::InvalidField {
                field: "format".to_owned(),
                reason: "must be 1".to_owned(),
            },
            PackError::UnsupportedInjection {
                injection: "aws-sigv4".to_owned(),
                reason: "not implemented".to_owned(),
            },
            PackError::ForbiddenHost {
                host: "localhost".to_owned(),
                reason: "loopback".to_owned(),
            },
            PackError::LimitTooLarge {
                field: "constraints.max_body_bytes".to_owned(),
                value: 9,
                max: 1,
            },
            PackError::UndeclaredPlaceholder {
                path: "/a/{b}".to_owned(),
                placeholder: "b".to_owned(),
            },
            PackError::DuplicateCapability("x.y".to_owned()),
            PackError::AmbiguousCapabilityName("a.b_c".to_owned()),
            PackError::File {
                path: "dir/bad.yaml".into(),
                source: Box::new(PackError::InvalidField {
                    field: "format".to_owned(),
                    reason: "must be 1".to_owned(),
                }),
            },
            PackError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "missing")),
        ];
        for err in &cases {
            let rendered = err.to_string();
            assert!(!rendered.is_empty(), "{err:?}");
            assert!(!rendered.to_lowercase().contains("hunter2"));
        }
    }

    #[test]
    fn serde_yaml_errors_map_to_parse_error() {
        let err: PackError = serde_yaml::from_str::<String>("a: [unclosed")
            .expect_err("must fail")
            .into();
        assert!(matches!(err, PackError::Parse(_)));
    }
}
