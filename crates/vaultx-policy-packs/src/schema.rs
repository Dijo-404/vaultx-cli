//! Declarative pack schema: a YAML capability description compiled into
//! generic broker constraints (plan §24).
//!
//! Packs are *semantic* descriptions — "this capability calls this API"
//! — and the compiler lowers them into the same primitives the
//! [`vaultx_policy::RuleEngine`] consumes. A pack can never weaken
//! broker invariants: validation rejects unsupported injection
//! templates, forbidden hosts, oversized limits, and unknown fields
//! (`deny_unknown_fields`), while compilation force-redacts `set-cookie`
//! on every response.
//!
//! Injection template values accept both the kebab-case spelling used by
//! [`vaultx_types`] (`github-bearer`) and the snake_case spelling used by
//! broker persistence (`github_bearer`); serialization is always
//! kebab-case.

use std::collections::BTreeMap;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use vaultx_policy::HttpMethod;
use vaultx_types::model::{InjectionTemplateId as TemplateId, InjectionTemplateId};
use vaultx_types::{CredentialRef, ProviderName};

use crate::error::PackError;

/// The only pack format version this parser accepts.
pub const PACK_FORMAT_VERSION: u16 = 1;
/// Global ceiling for `constraints.max_body_bytes` (256 KiB).
pub const MAX_REQUEST_BODY_BYTES_CAP: u64 = 256 * 1024;
/// Global ceiling for `response.max_body_bytes` (1 MiB).
pub const MAX_RESPONSE_BODY_BYTES_CAP: u64 = 1024 * 1024;
/// Response header redaction that packs can never disable.
pub const FORCED_REDACT_HEADER: &str = "set-cookie";
/// Longest accepted capability name; keeps derived policy names within
/// [`vaultx_types::PolicyName`]'s own length budget.
const CAPABILITY_MAX_LEN: usize = 120;

const METADATA_IPV4_HOST: &str = "169.254.169.254";
const METADATA_IPV6_HOST: &str = "fd00:ec2::254";

/// One declarative capability pack.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPack {
    /// Pack format version; must be [`PACK_FORMAT_VERSION`].
    pub format: u16,
    /// Dotted capability name, e.g. `github.pull_request.create`.
    pub name: String,
    /// Credential provider this capability belongs to.
    pub provider: ProviderName,
    /// Hosts, methods, path templates, and query constraints.
    pub request: PackRequestTemplate,
    /// Credential reference plus injection template binding.
    pub credential: PackCredentialBinding,
    /// Request-side body/type constraints (all optional).
    #[serde(default)]
    pub constraints: PackConstraints,
    /// Optional response-side rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<PackResponseRules>,
}

/// Request shape declared by a pack.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackRequestTemplate {
    /// Exact hostnames this capability may be exercised against.
    pub hosts: Vec<String>,
    /// HTTP methods the capability uses (at least one).
    pub methods: Vec<HttpMethod>,
    /// Path templates with `{placeholder}` segments (at least one).
    pub paths: Vec<String>,
    /// Query parameter names the capability may send; absent means no
    /// query constraint is declared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_allowlist: Option<Vec<String>>,
    /// Documentation/validation map for placeholders; when present every
    /// placeholder used in `paths` must appear here as a key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variables: Option<BTreeMap<String, String>>,
}

/// Credential binding declared by a pack.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackCredentialBinding {
    /// Logical ID of the brokered credential to use.
    pub credential_ref: CredentialRef,
    /// How the credential material enters the outbound request.
    #[serde(deserialize_with = "deserialize_injection_template")]
    pub injection: InjectionTemplateId,
}

/// Request-side constraints declared by a pack.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackConstraints {
    /// Maximum request body size; capped at
    /// [`MAX_REQUEST_BODY_BYTES_CAP`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_body_bytes: Option<u64>,
    /// Allowed content-type values (`type/subtype`, lowercased at
    /// compile time); absent means unconstrained by the pack.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_types: Option<Vec<String>>,
}

/// Response-side rules declared by a pack.
///
/// Compilation force-includes [`FORCED_REDACT_HEADER`] in the redaction
/// list regardless of what is declared here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackResponseRules {
    /// Maximum response body size; capped at
    /// [`MAX_RESPONSE_BODY_BYTES_CAP`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_body_bytes: Option<u64>,
    /// Lowercase header names redacted from responses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redact_headers: Vec<String>,
    /// JSON field selectors redacted from response bodies (dotted paths,
    /// e.g. `items[].secret_note`); consumed by the response sanitizer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redact_fields: Vec<String>,
}

/// Accepts both canonical kebab-case names (`github-bearer`) and the
/// snake_case spellings used by broker persistence (`github_bearer`).
fn deserialize_injection_template<'de, D>(deserializer: D) -> Result<InjectionTemplateId, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    parse_injection_template(&raw)
        .ok_or_else(|| D::Error::custom(format!("unknown injection template `{raw}`")))
}

/// Maps an injection-template string onto its enum value.
fn parse_injection_template(raw: &str) -> Option<InjectionTemplateId> {
    match raw {
        "bearer" => Some(TemplateId::Bearer),
        "basic-password" | "basic_password" => Some(TemplateId::BasicPassword),
        "api-key-header" | "api_key_header" => Some(TemplateId::ApiKeyHeader),
        "github-bearer" | "github_bearer" => Some(TemplateId::GithubBearer),
        "query-parameter" | "query_parameter" => Some(TemplateId::QueryParameter),
        "aws-sigv4" | "aws_sigv4" => Some(TemplateId::AwsSigv4),
        "custom-static-header-plus-secret" | "custom_static_header_plus_secret" => {
            Some(TemplateId::CustomStaticHeaderPlusSecret)
        }
        _ => None,
    }
}

impl PolicyPack {
    /// Runs all semantic validation invariants over an already-parsed
    /// pack.
    ///
    /// # Errors
    /// Returns the first violated invariant as a typed
    /// [`PackError`] variant.
    pub fn validate(&self) -> Result<(), PackError> {
        self.validate_format()?;
        self.validate_name()?;
        self.validate_request()?;
        self.validate_credential()?;
        self.validate_constraints()?;
        self.validate_response()?;
        Ok(())
    }

    fn validate_format(&self) -> Result<(), PackError> {
        if self.format == PACK_FORMAT_VERSION {
            return Ok(());
        }
        Err(PackError::InvalidField {
            field: "format".to_owned(),
            reason: format!("must be {PACK_FORMAT_VERSION}, found {}", self.format),
        })
    }

    fn validate_name(&self) -> Result<(), PackError> {
        let invalid = |reason: String| PackError::InvalidField {
            field: "name".to_owned(),
            reason,
        };
        if self.name.is_empty() {
            return Err(invalid("must not be empty".to_owned()));
        }
        if self.name.len() > CAPABILITY_MAX_LEN {
            return Err(invalid(format!(
                "must be at most {CAPABILITY_MAX_LEN} bytes"
            )));
        }
        for segment in self.name.split('.') {
            if segment.is_empty()
                || !segment
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
                || segment.starts_with('-')
                || segment.ends_with('-')
            {
                return Err(invalid(format!(
                    "`{}` must be dot-separated segments of lowercase letters, digits, `_`, \
                     and interior `-`",
                    self.name
                )));
            }
        }
        Ok(())
    }

    fn validate_request(&self) -> Result<(), PackError> {
        if self.request.hosts.is_empty() {
            return Err(PackError::InvalidField {
                field: "request.hosts".to_owned(),
                reason: "must contain at least one host".to_owned(),
            });
        }
        for host in &self.request.hosts {
            validate_pack_host(host)?;
        }
        if self.request.methods.is_empty() {
            return Err(PackError::InvalidField {
                field: "request.methods".to_owned(),
                reason: "must contain at least one method".to_owned(),
            });
        }
        if self.request.paths.is_empty() {
            return Err(PackError::InvalidField {
                field: "request.paths".to_owned(),
                reason: "must contain at least one path template".to_owned(),
            });
        }
        let mut used_placeholders = Vec::new();
        for path in &self.request.paths {
            used_placeholders.extend(validate_path_template(path)?);
        }
        if let Some(allowlist) = &self.request.query_allowlist {
            for key in allowlist {
                validate_query_key(key)?;
            }
        }
        if let Some(variables) = &self.request.variables {
            for key in variables.keys() {
                if !is_placeholder_charset(key) {
                    return Err(PackError::InvalidField {
                        field: "request.variables".to_owned(),
                        reason: format!("`{key}` must contain only A-Z, a-z, 0-9, `_`, and `-`"),
                    });
                }
            }
            for (path, placeholder) in &used_placeholders {
                if !variables.contains_key(placeholder) {
                    return Err(PackError::UndeclaredPlaceholder {
                        path: path.clone(),
                        placeholder: placeholder.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    fn validate_credential(&self) -> Result<(), PackError> {
        if self.credential.injection != InjectionTemplateId::AwsSigv4 {
            return Ok(());
        }
        Err(PackError::UnsupportedInjection {
            injection: "aws-sigv4".to_owned(),
            reason: "AWS SigV4 signing is not implemented by the credential broker yet".to_owned(),
        })
    }

    fn validate_constraints(&self) -> Result<(), PackError> {
        validate_size_limit(
            "constraints.max_body_bytes",
            self.constraints.max_body_bytes,
            MAX_REQUEST_BODY_BYTES_CAP,
        )?;
        for media_type in self.constraints.content_types.iter().flatten() {
            validate_content_type(media_type)?;
        }
        Ok(())
    }

    fn validate_response(&self) -> Result<(), PackError> {
        let Some(response) = &self.response else {
            return Ok(());
        };
        validate_size_limit(
            "response.max_body_bytes",
            response.max_body_bytes,
            MAX_RESPONSE_BODY_BYTES_CAP,
        )?;
        for header in &response.redact_headers {
            if !is_lowercase_header_token(header) {
                return Err(PackError::InvalidField {
                    field: "response.redact_headers".to_owned(),
                    reason: format!("`{header}` is not a lowercase HTTP header token"),
                });
            }
        }
        for field in &response.redact_fields {
            if field.is_empty() || field.chars().any(|c| c.is_control() || c.is_whitespace()) {
                return Err(PackError::InvalidField {
                    field: "response.redact_fields".to_owned(),
                    reason: format!("`{field}` is not a usable field selector"),
                });
            }
        }
        Ok(())
    }
}

/// Validates one body-size limit against its global cap.
fn validate_size_limit(field: &str, value: Option<u64>, max: u64) -> Result<(), PackError> {
    match value {
        None => Ok(()),
        Some(0) => Err(PackError::InvalidField {
            field: field.to_owned(),
            reason: "must be greater than zero".to_owned(),
        }),
        Some(value) if value > max => Err(PackError::LimitTooLarge {
            field: field.to_owned(),
            value,
            max,
        }),
        Some(_) => Ok(()),
    }
}

/// True for lowercase RFC 7230-style header tokens (subset sufficient
/// for redaction lists).
fn is_lowercase_header_token(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Placeholder charset shared by path templates and `variables` keys.
fn is_placeholder_charset(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Validates a query-parameter key from the allowlist.
fn validate_query_key(key: &str) -> Result<(), PackError> {
    if key.is_empty()
        || key.contains('=')
        || key.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(PackError::InvalidField {
            field: "request.query_allowlist".to_owned(),
            reason: format!("`{key}` is not a bare query parameter key"),
        });
    }
    Ok(())
}

/// Validates a media type entry (`type/subtype`, both non-empty).
fn validate_content_type(media_type: &str) -> Result<(), PackError> {
    let invalid = || PackError::InvalidField {
        field: "constraints.content_types".to_owned(),
        reason: format!("`{media_type}` is not a `type/subtype` media type"),
    };
    let (main, sub) = media_type.split_once('/').ok_or_else(invalid)?;
    let ok_part = |part: &str| !part.is_empty() && part.chars().all(|c| c.is_ascii_graphic());
    if !ok_part(main) || !ok_part(sub) || main.contains('/') {
        return Err(invalid());
    }
    Ok(())
}

/// Validates one path template and returns its `(path, placeholder)`
/// pairs.
///
/// Rules: absolute path; placeholders occupy whole segments written
/// `{name}` with `[A-Za-z0-9_-]` names; literal segments may not contain
/// braces; the remaining grammar (empty/`..`/mid-path `**`) is enforced
/// by [`vaultx_policy::matcher::validate_pattern`] so templates stay a
/// strict subset of engine patterns.
fn validate_path_template(path: &str) -> Result<Vec<(String, String)>, PackError> {
    let reject = |reason: String| PackError::InvalidField {
        field: "request.paths".to_owned(),
        reason: format!("`{path}`: {reason}"),
    };
    if !path.starts_with('/') {
        return Err(reject("must start with `/`".to_owned()));
    }
    let mut placeholders = Vec::new();
    for segment in path.split('/').skip(1) {
        if segment.is_empty() {
            continue;
        }
        if segment.starts_with('{') {
            let inner = segment
                .strip_prefix('{')
                .and_then(|rest| rest.strip_suffix('}'))
                .ok_or_else(|| {
                    reject(format!(
                        "`{segment}` mixes placeholder braces with literal text"
                    ))
                })?;
            if !is_placeholder_charset(inner) {
                return Err(reject(format!(
                    "placeholder `{inner}` must be non-empty and contain only A-Z, a-z, \
                     0-9, `_`, and `-`"
                )));
            }
            placeholders.push((path.to_owned(), inner.to_owned()));
        } else if segment.contains('{') || segment.contains('}') {
            return Err(reject("stray brace outside a placeholder".to_owned()));
        }
    }
    vaultx_policy::validate_pattern(path).map_err(|err| reject(err.to_string()))?;
    Ok(placeholders)
}

/// Validates a pack target hostname.
///
/// Hosts must be registrable-looking public hostnames: two or more
/// labels, lowercase, no ports, no wildcard characters, no literal IPs,
/// no loopback/link-local/private-suffix names, and never a cloud
/// metadata endpoint.
pub(crate) fn validate_pack_host(host: &str) -> Result<(), PackError> {
    let reject = |reason: &str| PackError::ForbiddenHost {
        host: host.to_owned(),
        reason: reason.to_owned(),
    };
    if host == METADATA_IPV4_HOST || host.eq_ignore_ascii_case(METADATA_IPV6_HOST) {
        return Err(reject("cloud metadata endpoints are never allowed"));
    }
    if host.is_empty() || host.len() > 253 {
        return Err(reject("hostname length must be 1-253 bytes"));
    }
    if !host
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
    {
        return Err(reject(
            "must be a lowercase hostname using only a-z, 0-9, '.', and '-'",
        ));
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return Err(reject(
            "must be a fully qualified name with at least two labels",
        ));
    }
    if labels
        .iter()
        .any(|label| label.is_empty() || label.starts_with('-') || label.ends_with('-'))
    {
        return Err(reject("labels must be non-empty without edge hyphens"));
    }
    if host == "localhost" || host.ends_with(".localhost") {
        return Err(reject("loopback names are not routable targets"));
    }
    if host.ends_with(".local") || host.ends_with(".internal") {
        return Err(reject(
            "private link-local/internal suffixes are not allowed",
        ));
    }
    if labels
        .iter()
        .all(|label| !label.is_empty() && label.chars().all(|c| c.is_ascii_digit()))
    {
        return Err(reject("literal IP addresses are not allowed"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_pack() -> PolicyPack {
        let yaml = r#"
format: 1
name: test.capability.call
provider: github
request:
  hosts: [api.github.com]
  methods: [GET]
  paths: ["/repos/{owner}/{repo}"]
credential:
  credential_ref: github-work-token
  injection: bearer
"#;
        crate::parse_pack_yaml(yaml).expect("minimal pack parses")
    }

    #[test]
    fn injection_accepts_kebab_and_snake_spellings() {
        for (raw, expected) in [
            ("bearer", TemplateId::Bearer),
            ("basic-password", TemplateId::BasicPassword),
            ("basic_password", TemplateId::BasicPassword),
            ("api-key-header", TemplateId::ApiKeyHeader),
            ("api_key_header", TemplateId::ApiKeyHeader),
            ("github-bearer", TemplateId::GithubBearer),
            ("github_bearer", TemplateId::GithubBearer),
            ("query-parameter", TemplateId::QueryParameter),
            ("query_parameter", TemplateId::QueryParameter),
            (
                "custom-static-header-plus-secret",
                TemplateId::CustomStaticHeaderPlusSecret,
            ),
            (
                "custom_static_header_plus_secret",
                TemplateId::CustomStaticHeaderPlusSecret,
            ),
            ("aws-sigv4", TemplateId::AwsSigv4),
            ("aws_sigv4", TemplateId::AwsSigv4),
        ] {
            assert_eq!(parse_injection_template(raw), Some(expected), "{raw}");
        }
        assert_eq!(parse_injection_template("mystery"), None);

        // Serialization stays canonical kebab-case even when the value was
        // parsed from a snake_case alias.
        assert_eq!(
            serde_yaml::to_string(&TemplateId::GithubBearer)
                .unwrap()
                .trim_end(),
            "github-bearer"
        );
    }

    #[test]
    fn host_rules_reject_private_and_metadata_targets() {
        for host in [
            METADATA_IPV4_HOST,
            METADATA_IPV6_HOST,
            "localhost",
            "my.service.local",
            "svc.internal",
            "10.0.0.8",
            "192.168.1.4",
            "api.github.com:443",
            "Api.GitHub.com",
            "single-label",
            "-lead.example.com",
            "trail-.example.com",
            "",
        ] {
            let err = validate_pack_host(host).unwrap_err();
            assert!(
                matches!(err, PackError::ForbiddenHost { .. }),
                "{host}: {err}"
            );
        }
        for host in ["api.github.com", "api.example-corp.dev"] {
            assert!(validate_pack_host(host).is_ok(), "{host}");
        }
    }

    #[test]
    fn path_templates_validate_placeholders_and_grammar() {
        let placeholders = validate_path_template("/repos/{owner}/{repo}/**").unwrap();
        assert_eq!(placeholders.len(), 2);
        assert!(validate_path_template("/**").is_ok());

        for bad in [
            "repos/acme",
            "/repos/{owner}/x/",
            "/repos//acme",
            "/repos/../escape",
            "/repos/{ow ner}/x",
            "/repos/{}/x",
            "/repos/{owner/x",
            "/repos/owner}/x",
            "/repos/a{x}/b",
            "/repos/**/pulls",
        ] {
            assert!(
                validate_path_template(bad).is_err(),
                "`{bad}` must be rejected"
            );
        }
    }

    #[test]
    fn size_limit_validation_enforces_caps_and_nonzero() {
        assert!(validate_size_limit("f", None, 100).is_ok());
        assert!(validate_size_limit("f", Some(1), 100).is_ok());
        assert!(validate_size_limit("f", Some(100), 100).is_ok());
        assert!(matches!(
            validate_size_limit("f", Some(101), 100),
            Err(PackError::LimitTooLarge { .. })
        ));
        assert!(matches!(
            validate_size_limit("f", Some(0), 100),
            Err(PackError::InvalidField { .. })
        ));
    }

    #[test]
    fn content_types_must_be_type_subtype_pairs() {
        assert!(validate_content_type("application/json").is_ok());
        assert!(validate_content_type("text/plain").is_ok());
        assert!(validate_content_type("json").is_err());
        assert!(validate_content_type("/json").is_err());
        assert!(validate_content_type("application/").is_err());
        assert!(validate_content_type("a b/json").is_err());
    }

    #[test]
    fn pack_caps_match_broker_size_limit_defaults() {
        // The pack ceilings exist to mirror vaultx_http::SizeLimits
        // defaults; this test fails if either side drifts.
        let limits = vaultx_http::SizeLimits::default();
        assert_eq!(MAX_REQUEST_BODY_BYTES_CAP, limits.max_request_body_bytes);
        assert_eq!(MAX_RESPONSE_BODY_BYTES_CAP, limits.max_response_body_bytes);
    }

    #[test]
    fn capability_names_allow_dotted_kebab_segments_only() {
        let mut pack = minimal_pack();
        pack.name = "github.pull_request.create".to_owned();
        assert!(pack.validate_name().is_ok());

        for bad in [
            "",
            "nodashes-.example",
            "UPPER.case",
            ".leading.dot",
            "trailing.",
            "double..dot",
            "sp ace.seg",
        ] {
            pack.name = bad.to_owned();
            assert!(pack.validate_name().is_err(), "{bad}");
        }
    }

    #[test]
    fn variables_keys_share_the_placeholder_charset() {
        let yaml = r#"
format: 1
name: test.vars.call
provider: github
request:
  hosts: [api.github.com]
  methods: [GET]
  paths: ["/repos/{owner}"]
  variables:
    "bad key": string
credential:
  credential_ref: token
  injection: bearer
"#;
        let err = crate::parse_pack_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("`bad key`"), "{err}");
    }

    #[test]
    fn format_versions_other_than_one_are_rejected() {
        for version in [0, 2, 99] {
            let mut pack = minimal_pack();
            pack.format = version;
            let err = pack.validate().unwrap_err();
            assert!(
                matches!(&err, PackError::InvalidField { field, .. } if field == "format"),
                "{version}: {err}"
            );
            assert!(err.to_string().contains("must be 1"), "{err}");
        }
    }

    #[test]
    fn unknown_fields_are_rejected_at_every_level() {
        // Top-level smuggle attempt.
        let yaml = minimal_yaml() + "\nrequired_headers: [authorization]\n";
        let err = crate::parse_pack_yaml(&yaml).unwrap_err();
        assert!(matches!(err, PackError::Parse(_)), "{err}");
        assert!(err.to_string().contains("required_headers"), "{err}");

        // The sensitive-header invariant: packs can never declare required
        // hop/auth headers because no such field exists anywhere in the
        // request/constraint schemas.
        let nested = minimal_yaml().replace(
            "request:\n",
            "request:\n  required_headers: [authorization, host]\n",
        );
        let err = crate::parse_pack_yaml(&nested).unwrap_err();
        assert!(matches!(err, PackError::Parse(_)), "{err}");
        assert!(err.to_string().contains("required_headers"), "{err}");

        let response_level = minimal_yaml() + "response:\n  deny_headers: [set-cookie]\n";
        assert!(crate::parse_pack_yaml(&response_level).is_err());
    }

    #[test]
    fn oversized_body_limits_exceeding_global_caps_are_rejected() {
        let mut pack = minimal_pack();
        pack.constraints.max_body_bytes = Some(MAX_REQUEST_BODY_BYTES_CAP + 1);
        let err = pack.validate().unwrap_err();
        assert!(
            matches!(
                &err,
                PackError::LimitTooLarge { value, max, .. }
                    if *value == MAX_REQUEST_BODY_BYTES_CAP + 1
                        && *max == MAX_REQUEST_BODY_BYTES_CAP
            ),
            "{err}"
        );

        let mut pack = minimal_pack();
        pack.response = Some(PackResponseRules {
            max_body_bytes: Some(MAX_RESPONSE_BODY_BYTES_CAP + 1),
            redact_headers: vec![],
            redact_fields: vec![],
        });
        let err = pack.validate().unwrap_err();
        assert!(
            matches!(
                &err,
                PackError::LimitTooLarge {
                    max: MAX_RESPONSE_BODY_BYTES_CAP,
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn aws_sigv4_injection_is_rejected_in_both_spellings() {
        for spelling in ["aws-sigv4", "aws_sigv4"] {
            let yaml =
                minimal_yaml().replace("injection: bearer", &format!("injection: {spelling}"));
            let err = crate::parse_pack_yaml(&yaml).unwrap_err();
            assert!(
                matches!(&err, PackError::UnsupportedInjection { injection, .. }
                    if injection == "aws-sigv4"),
                "{spelling}: {err}"
            );
            assert!(
                err.to_string()
                    .contains("AWS SigV4 signing is not implemented"),
                "{err}"
            );
        }
    }

    #[test]
    fn placeholders_without_variable_declarations_are_rejected_only_when_map_exists() {
        // No variables map: placeholders are unconstrained patterns.
        assert!(crate::parse_pack_yaml(&minimal_yaml()).is_ok());

        let missing =
            minimal_yaml().replace("request:\n", "request:\n  variables:\n    repo: string\n");
        let err = crate::parse_pack_yaml(&missing).unwrap_err();
        assert!(
            matches!(&err, PackError::UndeclaredPlaceholder { placeholder, .. }
                if placeholder == "owner" || placeholder == "repo"),
            "{err}"
        );
        assert!(err.to_string().contains("request.variables"), "{err}");
    }

    /// Minimal valid pack YAML with two path placeholders.
    fn minimal_yaml() -> String {
        r#"
format: 1
name: test.minimal.call
provider: github
request:
  hosts: [api.github.com]
  methods: [GET]
  paths: ["/repos/{owner}/{repo}"]
credential:
  credential_ref: token
  injection: bearer
"#
        .to_owned()
    }
}
