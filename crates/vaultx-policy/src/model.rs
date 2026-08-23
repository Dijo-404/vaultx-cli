//! Authorization model for the vaultx policy crate (plan §22–§23).
//!
//! The broker maps these concepts as follows:
//!
//! | Model concept        | Broker meaning                                        |
//! |----------------------|-------------------------------------------------------|
//! | [`Principal`]        | agent or session identity making the request          |
//! | [`Action::HttpRequest`]| the HTTP proxy action                               |
//! | [`Resource`]         | logical ID of the brokered credential                 |
//! | [`AuthorizationContext`] | canonical host/method/path/query/body metadata and the active environment |

use std::collections::BTreeMap;
use std::fmt;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use vaultx_types::{CredentialRef, EnvironmentId, PolicyName};

use crate::error::PolicyError;

/// Scheme prefix identifying an agent principal.
pub const PRINCIPAL_AGENT_PREFIX: &str = "agent:";
/// Scheme prefix identifying a session principal.
pub const PRINCIPAL_SESSION_PREFIX: &str = "session:";

/// Maximum length of a serialized [`Principal`], generous enough for
/// session IDs while keeping log lines bounded.
pub const PRINCIPAL_MAX_LEN: usize = 255;

/// Identity of the requester: `agent:<name>` or `session:<id>`.
///
/// The scheme prefix is mandatory so principals from different identity
/// families can never collide; the remainder must be non-empty and free of
/// control characters.
#[derive(Clone, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct Principal(String);

impl Principal {
    /// Parses and validates a `scheme:remainder` principal string.
    ///
    /// # Errors
    /// Returns [`PolicyError::InvalidPolicy`] when the value is empty,
    /// lacks a known scheme prefix, has an empty remainder, contains
    /// control characters, or exceeds 255 characters.
    pub fn parse(value: &str) -> Result<Self, PolicyError> {
        let invalid = |reason: String| PolicyError::InvalidPolicy {
            field: "principal".to_owned(),
            reason,
        };
        if value.is_empty() {
            return Err(invalid("must not be empty".to_owned()));
        }
        if value.len() > PRINCIPAL_MAX_LEN {
            return Err(invalid(format!(
                "must be at most {PRINCIPAL_MAX_LEN} bytes"
            )));
        }
        let remainder = value
            .strip_prefix(PRINCIPAL_AGENT_PREFIX)
            .or_else(|| value.strip_prefix(PRINCIPAL_SESSION_PREFIX))
            .ok_or_else(|| {
                invalid(format!(
                    "must start with `{PRINCIPAL_AGENT_PREFIX}` or `{PRINCIPAL_SESSION_PREFIX}`"
                ))
            })?;
        if remainder.is_empty() {
            return Err(invalid(
                "must have a non-empty identity after the scheme".to_owned(),
            ));
        }
        if remainder.chars().any(|c| c.is_control()) {
            return Err(invalid("must not contain control characters".to_owned()));
        }
        Ok(Self(value.to_owned()))
    }

    /// Returns the canonical string form (`agent:<name>` / `session:<id>`).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for Principal {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Principal {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(D::Error::custom)
    }
}

/// The operation being authorized.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Action {
    /// Proxying an HTTP request through the broker.
    #[serde(rename = "http.request")]
    HttpRequest,
}

/// Resource being authorized: the logical ID of a brokered credential.
///
/// Deliberately reuses [`vaultx_types::CredentialRef`] so policy documents
/// and manifests agree on credential naming without any translation layer.
pub type Resource = CredentialRef;

/// HTTP methods understood by path rules.
///
/// Serialization uses the uppercase method token itself (`GET`, `POST`, ...).
/// The default is `GET`, the least-privileged method.
#[derive(
    Clone, Copy, Default, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
pub enum HttpMethod {
    #[default]
    GET,
    POST,
    PUT,
    PATCH,
    DELETE,
    HEAD,
    OPTIONS,
}

impl HttpMethod {
    /// Canonical wire token for the method.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GET => "GET",
            Self::POST => "POST",
            Self::PUT => "PUT",
            Self::PATCH => "PATCH",
            Self::DELETE => "DELETE",
            Self::HEAD => "HEAD",
            Self::OPTIONS => "OPTIONS",
        }
    }
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Request context evaluated against a policy document.
///
/// # Canonicalization contract
///
/// The engine performs no normalization: matching is literal and
/// segment-based. The caller (broker transport layer) MUST construct this
/// struct from an already-canonicalized request —
///
/// * `path` percent-decoded with dot segments (`.` / `..`) resolved,
/// * `host` lowercased and stripped of any port.
///
/// Non-canonical values are rejected by [`AuthorizationContext::validate`]
/// before any policy rule runs; they are never normalized silently, because
/// upstream normalization drift is a deny-evasion vector.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuthorizationContext {
    /// Lowercase hostname of the outbound request target (no port).
    pub host: String,
    /// HTTP method of the outbound request.
    pub method: HttpMethod,
    /// Absolute request path (starts with `/`), case-sensitive.
    pub path: String,
    /// Decoded query parameters, ordered by key.
    pub query: BTreeMap<String, String>,
    /// Declared body length in bytes (0 when there is no body).
    pub body_len_bytes: u64,
    /// Deployed environment the agent/session operates in, when known.
    pub environment: Option<EnvironmentId>,
}

/// Error describing a non-canonical [`AuthorizationContext`].
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ContextError {
    /// Host is empty, non-lowercase, or otherwise not a valid hostname
    /// (ports are not allowed in host entries).
    #[error("context host `{0}` is not a lowercase valid hostname (no ports)")]
    InvalidHost(String),
    /// Path is relative, contains empty segments (`//`, trailing `/`), or
    /// retains `.` / `..` dot segments.
    #[error(
        "context path `{0}` is not canonical: must start with '/' and contain no empty, '.', or '..' segments"
    )]
    InvalidPath(String),
}

impl AuthorizationContext {
    /// Validates the canonical-form contract documented on the struct.
    ///
    /// The rule engine runs this before any policy evaluation and denies
    /// non-canonical contexts outright.
    ///
    /// # Errors
    /// Returns [`ContextError::InvalidHost`] or
    /// [`ContextError::InvalidPath`] describing the first violation.
    pub fn validate(&self) -> Result<(), ContextError> {
        if !is_valid_hostname(&self.host) {
            return Err(ContextError::InvalidHost(self.host.clone()));
        }
        if !is_canonical_path(&self.path) {
            return Err(ContextError::InvalidPath(self.path.clone()));
        }
        Ok(())
    }
}

/// True when `host` is a lowercase hostname built from `a-z`, `0-9`, `.`,
/// and `-`, with no empty labels and no leading/trailing `.` or `-`.
///
/// Ports are deliberately invalid: host entries are plain hostnames.
pub(crate) fn is_valid_hostname(host: &str) -> bool {
    if host.is_empty() || host.starts_with('.') || host.ends_with('.') {
        return false;
    }
    if !host
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
    {
        return false;
    }
    host.split('.')
        .all(|label| !label.is_empty() && !label.starts_with('-') && !label.ends_with('-'))
}

/// True when `path` is an absolute path with no empty segments (`//`,
/// trailing `/`) and no unresolved `.` / `..` segments. The bare root `/`
/// is the one canonical zero-segment path.
fn is_canonical_path(path: &str) -> bool {
    if !path.starts_with('/') {
        return false;
    }
    if path == "/" {
        return true;
    }
    let rest = &path[1..];
    rest.split('/')
        .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

/// Human-editable policy document compiled into rules (plan §23).
///
/// Every field validates on deserialization; semantic validation (hostnames,
/// header names, patterns, non-empty rule sets) happens during loading via
/// [`crate::loader::validate_policy`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocument {
    /// Unique human-facing policy name.
    pub name: PolicyName,
    /// Principal this policy applies to.
    pub principal: Principal,
    /// Credential logical ID this policy gates access to.
    pub credential: CredentialRef,
    /// Environment allowlist; absent or empty means every environment is
    /// permitted.
    #[serde(default)]
    pub environment: EnvironmentRules,
    /// Host gate plus explicit deny/allow method+path rules.
    pub http: HttpRules,
    /// Constraints applied to the proxied request.
    #[serde(default)]
    pub request: RequestConstraints,
    /// Constraints applied to the proxied response.
    #[serde(default)]
    pub response: ResponseConstraints,
}

/// Environment allowlist attached to a policy document.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentRules {
    /// Environments the principal may operate in. An empty list means
    /// unconstrained.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<EnvironmentId>,
}

/// Host gate and method+path rules for one policy document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRules {
    /// Lowercase hostnames the policy may be exercised against.
    pub hosts: Vec<String>,
    /// Allow rules; at least one must match for a request to be allowed.
    #[serde(default)]
    pub allow: Vec<MethodPathRule>,
    /// Deny rules; evaluated before allow rules and always win.
    #[serde(default)]
    pub deny: Vec<MethodPathRule>,
}

/// Size limits and header controls applied to the proxied request.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestConstraints {
    /// Maximum accepted request body size in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_body_bytes: Option<u64>,
    /// Header names the broker refuses to forward (lowercase).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_headers: Vec<String>,
}

/// Size limits and header controls applied to the proxied response.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseConstraints {
    /// Maximum accepted response body size in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_body_bytes: Option<u64>,
    /// Header names redacted from the response before delivery (lowercase).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redact_headers: Vec<String>,
}

/// One method+path rule inside an allow or deny list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MethodPathRule {
    /// Methods the rule applies to.
    pub methods: Vec<HttpMethod>,
    /// Path patterns the rule applies to (see the `matcher` module).
    pub paths: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::validate_pattern;

    fn assert_round_trip<T>(value: T, yaml: &str)
    where
        T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let encoded = serde_yaml::to_string(&value).unwrap();
        assert_eq!(encoded.trim_end(), yaml);
        let decoded: T = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn principal_accepts_known_schemes() {
        assert_eq!(
            Principal::parse("agent:coding-agent").unwrap().as_str(),
            "agent:coding-agent"
        );
        assert_eq!(
            Principal::parse("session:sess_a1b2c3").unwrap().as_str(),
            "session:sess_a1b2c3"
        );
        assert!(matches!(
            Principal::parse("user:alice"),
            Err(PolicyError::InvalidPolicy { .. })
        ));
        assert!(matches!(
            Principal::parse("agent:"),
            Err(PolicyError::InvalidPolicy { .. })
        ));
        assert!(matches!(
            Principal::parse(""),
            Err(PolicyError::InvalidPolicy { .. })
        ));
        assert!(matches!(
            Principal::parse("agent:bad\u{1}name"),
            Err(PolicyError::InvalidPolicy { .. })
        ));
        let overlong = format!("agent:{}", "a".repeat(250));
        assert!(matches!(
            Principal::parse(&overlong),
            Err(PolicyError::InvalidPolicy { .. })
        ));
    }

    #[test]
    fn principal_round_trips_through_yaml() {
        assert_round_trip(
            Principal::parse("agent:coding-agent").unwrap(),
            "agent:coding-agent",
        );
    }

    #[test]
    fn action_serializes_to_http_request() {
        let encoded = serde_yaml::to_string(&Action::HttpRequest).unwrap();
        assert_eq!(encoded.trim_end(), "http.request");
        let decoded: Action = serde_yaml::from_str("http.request").unwrap();
        assert_eq!(decoded, Action::HttpRequest);
        assert!(serde_yaml::from_str::<Action>("http-request").is_err());
    }

    #[test]
    fn resource_is_credential_ref() {
        // Resource is a type alias; validation comes straight from
        // vaultx_types.
        let parsed = Resource::parse("github-work-token").unwrap();
        assert_eq!(parsed.as_str(), "github-work-token");
        assert!(Resource::parse("Bad Name").is_err());
    }

    #[test]
    fn http_method_tokens_are_stable() {
        assert_eq!(HttpMethod::GET.as_str(), "GET");
        assert_eq!(HttpMethod::OPTIONS.as_str(), "OPTIONS");
        let encoded = serde_yaml::to_string(&[HttpMethod::POST]).unwrap();
        assert_eq!(encoded.trim_end(), "- POST");
        let decoded: Vec<HttpMethod> = serde_yaml::from_str("[GET, PATCH]").expect("methods parse");
        assert_eq!(decoded, vec![HttpMethod::GET, HttpMethod::PATCH]);
    }

    #[test]
    fn context_defaults_to_deny_friendly_values() {
        let ctx = AuthorizationContext::default();
        assert_eq!(ctx.body_len_bytes, 0);
        assert_eq!(ctx.environment, None);
        assert_eq!(ctx.host, "");
        assert_eq!(ctx.path, "");
        assert!(ctx.query.is_empty());
    }

    #[test]
    fn context_validation_enforces_canonical_form() {
        let canonical = AuthorizationContext {
            host: "api.github.com".to_owned(),
            method: HttpMethod::GET,
            path: "/repos/acme/backend/issues".to_owned(),
            query: BTreeMap::new(),
            body_len_bytes: 0,
            environment: None,
        };
        assert_eq!(canonical.validate(), Ok(()));

        // Bare root is the one canonical zero-segment path.
        let root = AuthorizationContext {
            path: "/".to_owned(),
            ..canonical.clone()
        };
        assert_eq!(root.validate(), Ok(()));

        for bad_path in [
            "repos/acme",
            "//acme",
            "/a//b",
            "/repos/acme/",
            "/repos/../secrets",
            "/./current",
            "",
        ] {
            let bad = AuthorizationContext {
                path: bad_path.to_owned(),
                ..canonical.clone()
            };
            assert_eq!(
                bad.validate(),
                Err(ContextError::InvalidPath(bad_path.to_owned())),
                "{bad_path}"
            );
        }

        for bad_host in [
            "",
            "API.GitHub.com",
            "api.github.com:8444",
            "-lead.example",
            "trail-.example",
            "double..dot",
        ] {
            let bad = AuthorizationContext {
                host: bad_host.to_owned(),
                ..canonical.clone()
            };
            assert_eq!(
                bad.validate(),
                Err(ContextError::InvalidHost(bad_host.to_owned())),
                "{bad_host}"
            );
        }
    }

    #[test]
    fn method_path_rule_validates_patterns_upstream() {
        let rule = MethodPathRule {
            methods: vec![HttpMethod::GET],
            paths: vec!["/repos/**".to_owned()],
        };
        for pattern in &rule.paths {
            assert!(validate_pattern(pattern).is_ok());
        }
    }
}
