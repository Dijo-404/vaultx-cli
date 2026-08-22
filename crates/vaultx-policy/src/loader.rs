//! Loading, parsing, and validating human-editable policy documents
//! (plan §23).
//!
//! YAML documents are deserialized into a [`PolicyDocument`] (which already
//! validates typed fields on deserialize) and then run through semantic
//! validation: hostnames and header names must be canonical lowercase,
//! path patterns must satisfy the matcher grammar, size limits must be
//! positive, and every policy needs at least one host and one allow rule.

use std::path::Path;

use crate::error::PolicyError;
use crate::matcher::validate_pattern;
use crate::model::{HttpRules, PolicyDocument};

/// Parses `text` as a YAML [`PolicyDocument`] and validates it.
///
/// # Errors
/// Returns [`PolicyError::ParseError`] for malformed YAML (serde
/// diagnostics only — never file content) and [`PolicyError::InvalidPolicy`]
/// / [`PolicyError::InvalidPattern`] for semantic violations.
pub fn parse_policy_yaml(text: &str) -> Result<PolicyDocument, PolicyError> {
    let document: PolicyDocument =
        serde_yaml::from_str(text).map_err(|err| PolicyError::ParseError(err.to_string()))?;
    validate_policy(&document)?;
    Ok(document)
}

/// Reads `path` from disk and parses it via [`parse_policy_yaml`].
///
/// # Errors
/// Propagates I/O errors ([`PolicyError::Io`]) plus anything returned by
/// [`parse_policy_yaml`].
pub fn load_policy_file(path: &Path) -> Result<PolicyDocument, PolicyError> {
    let text = std::fs::read_to_string(path)?;
    parse_policy_yaml(&text)
}

/// Validates a policy document's semantic constraints.
///
/// Called by [`parse_policy_yaml`] and by [`crate::engine::CompiledPolicy`]
/// so programmatically constructed documents get identical checks.
///
/// # Errors
/// See the module documentation for the enforced invariants.
pub fn validate_policy(document: &PolicyDocument) -> Result<(), PolicyError> {
    let HttpRules { hosts, allow, deny } = &document.http;

    if hosts.is_empty() {
        return Err(PolicyError::InvalidPolicy {
            field: "http.hosts".to_owned(),
            reason: "must contain at least one entry".to_owned(),
        });
    }
    for host in hosts {
        validate_hostname(host)?;
    }

    if allow.is_empty() {
        return Err(PolicyError::InvalidPolicy {
            field: "http.allow".to_owned(),
            reason: "must contain at least one rule".to_owned(),
        });
    }
    validate_rules("http.allow", allow)?;
    validate_rules("http.deny", deny)?;

    if document.request.max_body_bytes == Some(0) {
        return Err(PolicyError::InvalidPolicy {
            field: "request.max_body_bytes".to_owned(),
            reason: "must be greater than zero".to_owned(),
        });
    }
    validate_header_names("request.deny_headers", &document.request.deny_headers)?;

    if document.response.max_body_bytes == Some(0) {
        return Err(PolicyError::InvalidPolicy {
            field: "response.max_body_bytes".to_owned(),
            reason: "must be greater than zero".to_owned(),
        });
    }
    validate_header_names("response.redact_headers", &document.response.redact_headers)?;

    Ok(())
}

fn validate_rules(
    field_prefix: &str,
    rules: &[crate::model::MethodPathRule],
) -> Result<(), PolicyError> {
    for (rule_index, rule) in rules.iter().enumerate() {
        if rule.methods.is_empty() {
            return Err(PolicyError::InvalidPolicy {
                field: format!("{field_prefix}[{rule_index}].methods"),
                reason: "must contain at least one method".to_owned(),
            });
        }
        if rule.paths.is_empty() {
            return Err(PolicyError::InvalidPolicy {
                field: format!("{field_prefix}[{rule_index}].paths"),
                reason: "must contain at least one pattern".to_owned(),
            });
        }
        for pattern in &rule.paths {
            validate_pattern(pattern)?;
        }
    }
    Ok(())
}

const HEADER_TOKEN_EXTRA_CHARS: &str = "!#$%&'*+-.^_`|~";

fn is_lowercase_header_token(name: &str) -> bool {
    !name.is_empty()
        && name.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || HEADER_TOKEN_EXTRA_CHARS.contains(c)
        })
}

fn validate_header_names(field: &str, names: &[String]) -> Result<(), PolicyError> {
    for name in names {
        if !is_lowercase_header_token(name) {
            return Err(PolicyError::InvalidPolicy {
                field: field.to_owned(),
                reason: format!("`{name}` is not a lowercase HTTP header token"),
            });
        }
    }
    Ok(())
}

fn validate_hostname(host: &str) -> Result<(), PolicyError> {
    let invalid = |reason: String| PolicyError::InvalidPolicy {
        field: "http.hosts".to_owned(),
        reason,
    };
    if host.is_empty() {
        return Err(invalid("must not be empty".to_owned()));
    }
    if !host
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
    {
        // Uppercase or any other character breaks canonical form.
        return Err(invalid(format!(
            "`{host}` must be a lowercase hostname using only a-z, 0-9, '.', and '-'"
        )));
    }
    if host.starts_with('.') || host.ends_with('.') {
        return Err(invalid(format!("`{host}` has a leading or trailing '.'")));
    }
    for label in host.split('.') {
        if label.is_empty() {
            return Err(invalid(format!("`{host}` contains an empty label")));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(invalid(format!(
                "`{host}` contains a label with a leading or trailing '-'"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{HttpMethod, Principal};
    use std::io::Write;
    use vaultx_types::EnvironmentId;

    const VALID_YAML: &str = r#"
name: coding-agent-github
principal: agent:coding-agent
credential: github-work-token
environment:
  allow: [env_development]
http:
  hosts: [api.github.com]
  allow:
    - methods: [GET]
      paths: [/repos/acme/backend/**]
request:
  max_body_bytes: 262144
"#;

    #[test]
    fn parses_valid_document() {
        let doc = parse_policy_yaml(VALID_YAML).unwrap();
        assert_eq!(doc.name.as_str(), "coding-agent-github");
        assert_eq!(
            doc.principal,
            Principal::parse("agent:coding-agent").unwrap()
        );
        assert_eq!(
            doc.environment.allow,
            vec![EnvironmentId::parse("env_development").unwrap()]
        );
        assert_eq!(doc.http.hosts, vec!["api.github.com".to_owned()]);
        assert_eq!(doc.http.allow[0].methods, vec![HttpMethod::GET]);
    }

    #[test]
    fn malformed_yaml_reports_parse_error_without_content() {
        let err = parse_policy_yaml("name: [unclosed").unwrap_err();
        assert!(matches!(err, PolicyError::ParseError(_)));
        let rendered = err.to_string();
        assert!(!rendered.contains("hunter2"));
        assert!(!rendered.contains("secret-value"));
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let yaml = format!("{VALID_YAML}\nextra_field: true\n");
        assert!(matches!(
            parse_policy_yaml(&yaml),
            Err(PolicyError::ParseError(_))
        ));
    }

    #[test]
    fn typed_field_validation_runs_on_deserialize() {
        let bad_principal = r#"
name: bad-principal
principal: user:alice
credential: github-work-token
http:
  hosts: [api.github.com]
  allow:
    - methods: [GET]
      paths: ["/x"]
"#;
        let err = parse_policy_yaml(bad_principal).unwrap_err();
        assert!(err.to_string().contains("principal"), "{err}");

        let bad_credential = r#"
name: bad-credential
principal: agent:a
credential: "Bad Name"
http:
  hosts: [api.github.com]
  allow:
    - methods: [GET]
      paths: ["/x"]
"#;
        assert!(parse_policy_yaml(bad_credential).is_err());

        let bad_name = r#"
name: Bad-Policy-Name
principal: agent:a
credential: github-work-token
http:
  hosts: [api.github.com]
  allow:
    - methods: [GET]
      paths: ["/x"]
"#;
        assert!(parse_policy_yaml(bad_name).is_err());
    }

    #[test]
    fn rejects_uppercase_hosts_and_bad_hostname_shapes() {
        for hosts in [
            "[Api.GitHub.com]",
            "[api.github.com, EVIL.com]",
            "[-leading.example]",
            "[trailing-.example]",
            "[double..dot.example]",
            "[]",
        ] {
            let yaml = format!(
                r#"
name: host-check
principal: agent:a
credential: token
http:
  hosts: {hosts}
  allow:
    - methods: [GET]
      paths: ["/x"]
"#
            );
            let err = parse_policy_yaml(&yaml).unwrap_err();
            assert!(
                matches!(err, PolicyError::InvalidPolicy { ref field, .. } if field == "http.hosts"),
                "{hosts}: {err}"
            );
        }
    }

    #[test]
    fn rejects_uppercase_and_invalid_header_names() {
        let deny_headers = r#"
name: header-check
principal: agent:a
credential: token
http:
  hosts: [api.github.com]
  allow:
    - methods: [GET]
      paths: ["/x"]
request:
  deny_headers: [Authorization]
"#;
        let err = parse_policy_yaml(deny_headers).unwrap_err();
        assert!(
            matches!(err, PolicyError::InvalidPolicy { ref field, .. } if field == "request.deny_headers"),
            "{err}"
        );

        let redact_headers = r#"
name: header-check2
principal: agent:a
credential: token
http:
  hosts: [api.github.com]
  allow:
    - methods: [GET]
      paths: ["/x"]
response:
  redact_headers: ["set cookie"]
"#;
        let err = parse_policy_yaml(redact_headers).unwrap_err();
        assert!(
            matches!(err, PolicyError::InvalidPolicy { ref field, .. } if field == "response.redact_headers"),
            "{err}"
        );

        // Valid lowercase headers pass.
        let ok = r#"
name: header-check3
principal: agent:a
credential: token
http:
  hosts: [api.github.com]
  allow:
    - methods: [GET]
      paths: ["/x"]
response:
  redact_headers: [set-cookie, x-request-id]
"#;
        assert!(parse_policy_yaml(ok).is_ok());
    }

    #[test]
    fn rejects_zero_max_sizes() {
        let yaml = format!("{VALID_YAML}\nresponse:\n  max_body_bytes: 0\n");
        let err = parse_policy_yaml(&yaml).unwrap_err();
        assert!(
            matches!(err, PolicyError::InvalidPolicy { ref field, .. } if field == "response.max_body_bytes"),
            "{err}"
        );

        let request_zero = VALID_YAML.replace("  max_body_bytes: 262144", "  max_body_bytes: 0");
        let err = parse_policy_yaml(&request_zero).unwrap_err();
        assert!(
            matches!(err, PolicyError::InvalidPolicy { ref field, .. } if field == "request.max_body_bytes"),
            "{err}"
        );
    }

    #[test]
    fn requires_at_least_one_host_and_one_allow_rule() {
        let no_hosts = r#"
name: no-hosts
principal: agent:a
credential: token
http:
  hosts: []
  allow:
    - methods: [GET]
      paths: ["/x"]
"#;
        let err = parse_policy_yaml(no_hosts).unwrap_err();
        assert!(
            matches!(err, PolicyError::InvalidPolicy { ref field, .. } if field == "http.hosts")
        );

        let no_allow = r#"
name: no-allow
principal: agent:a
credential: token
http:
  hosts: [api.github.com]
  allow: []
"#;
        let err = parse_policy_yaml(no_allow).unwrap_err();
        assert!(
            matches!(err, PolicyError::InvalidPolicy { ref field, .. } if field == "http.allow")
        );

        // Missing allow key entirely fails the same check.
        let missing_allow = r#"
name: missing-allow
principal: agent:a
credential: token
http:
  hosts: [api.github.com]
"#;
        let err = parse_policy_yaml(missing_allow).unwrap_err();
        assert!(
            matches!(err, PolicyError::InvalidPolicy { ref field, .. } if field == "http.allow")
        );
    }

    #[test]
    fn rejects_invalid_path_patterns_in_rules() {
        for pattern in ["repos/**", "/a/../b", "/x/**/y", ""] {
            let yaml = format!(
                r#"
name: pattern-check
principal: agent:a
credential: token
http:
  hosts: [api.github.com]
  allow:
    - methods: [GET]
      paths: [{pattern:?}]
"#
            );
            let err = parse_policy_yaml(&yaml).unwrap_err();
            assert!(
                matches!(err, PolicyError::InvalidPattern(_)),
                "`{pattern}`: {err}"
            );
        }

        // Empty method/path lists are rejected too.
        let empty_methods = r#"
name: empty-methods
principal: agent:a
credential: token
http:
  hosts: [api.github.com]
  allow:
    - methods: []
      paths: ["/x"]
"#;
        let err = parse_policy_yaml(empty_methods).unwrap_err();
        assert!(err.to_string().contains("methods"), "{err}");
    }

    #[test]
    fn policy_document_round_trips_through_yaml() {
        let original = parse_policy_yaml(VALID_YAML).unwrap();
        let serialized = serde_yaml::to_string(&original).expect("serialize");
        let reparsed = serde_yaml::from_str::<PolicyDocument>(&serialized).expect("deserialize");
        assert_eq!(reparsed, original);
        // Round trip through parse_policy_yaml keeps validation green.
        assert_eq!(parse_policy_yaml(&serialized).unwrap(), original);
    }

    #[test]
    fn loads_policy_from_file() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(VALID_YAML.as_bytes()).unwrap();
        file.flush().unwrap();

        let loaded = load_policy_file(file.path()).unwrap();
        assert_eq!(loaded.name.as_str(), "coding-agent-github");

        let missing = load_policy_file(Path::new("/nonexistent/vaultx/policy.yaml"));
        assert!(matches!(missing, Err(PolicyError::Io(_))));
    }
}
