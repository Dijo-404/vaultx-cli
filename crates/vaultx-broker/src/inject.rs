//! Credential injection templates (plan §21).
//!
//! Credential material enters the outbound request only inside the
//! broker: an injector receives the resolved secret through the
//! zeroizing [`SecretBytes`] handle and writes it into the
//! [`OutboundRequest`]. Nothing else in this crate — and nothing in the
//! agent process — ever sees plaintext (INV-018).
//!
//! The agent chooses a *logical credential reference*; the template is a
//! property of the stored credential, never an agent choice.

use std::collections::HashMap;

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use vaultx_crypto::secret::SecretBytes;
use vaultx_http::CanonicalUrl;
use vaultx_policy::HttpMethod;

use crate::error::BrokerError;
use crate::request::BrokerBody;

/// Canonical names of the built-in injection templates (plan §21).
///
/// Serialized in snake_case so credentials can persist their template
/// choice verbatim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InjectionTemplateId {
    /// `Authorization: Bearer <secret>`.
    Bearer,
    /// `Authorization: Basic base64(username:secret)`.
    BasicPassword,
    /// `<header_name>: <secret>` with the header name from metadata.
    ApiKeyHeader,
    /// `Authorization: token <secret>` (GitHub convention).
    GithubBearer,
    /// `<query_param_name>=<percent-encoded secret>`.
    QueryParameter,
    /// `<header_name>: <static_prefix><secret>`.
    CustomStaticHeaderPlusSecret,
    /// AWS SigV4 request signing — **deferred**; see [`AwsSigv4Injector`].
    AwsSigv4,
}

impl InjectionTemplateId {
    /// Canonical snake_case name of this template.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bearer => "bearer",
            Self::BasicPassword => "basic_password",
            Self::ApiKeyHeader => "api_key_header",
            Self::GithubBearer => "github_bearer",
            Self::QueryParameter => "query_parameter",
            Self::CustomStaticHeaderPlusSecret => "custom_static_header_plus_secret",
            Self::AwsSigv4 => "aws_sigv4",
        }
    }
}

// ---------------------------------------------------------------------------
// Metadata + outbound shape
// ---------------------------------------------------------------------------

/// Non-secret configuration attached to a credential, consumed by
/// injection templates that need placement information.
///
/// Present names must be lowercase RFC 7230 token characters; validation
/// happens on every use so a hand-edited store fails at injection time,
/// not silently.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialMetadata {
    /// Username for `basic_password`.
    pub username: Option<String>,
    /// Header name for `api_key_header` /
    /// `custom_static_header_plus_secret`.
    pub header_name: Option<String>,
    /// Query parameter name for `query_parameter`.
    pub query_param_name: Option<String>,
    /// Static value prefix for `custom_static_header_plus_secret`.
    pub static_prefix: Option<String>,
}

fn is_lowercase_token_char(c: char) -> bool {
    c.is_ascii_lowercase()
        || c.is_ascii_digit()
        || matches!(
            c,
            '!' | '#'
                | '$'
                | '%'
                | '&'
                | '\''
                | '*'
                | '+'
                | '-'
                | '.'
                | '^'
                | '_'
                | '`'
                | '|'
                | '~'
        )
}

/// Validates an optional name field: when present it must be non-empty
/// and consist solely of lowercase token characters.
fn validate_optional_name(field: &Option<String>, label: &str) -> Result<(), BrokerError> {
    if let Some(name) = field {
        let invalid = || {
            BrokerError::InjectionError(format!(
                "credential metadata `{label}` must be non-empty lowercase token characters"
            ))
        };
        if name.is_empty() || !name.chars().all(is_lowercase_token_char) {
            return Err(invalid());
        }
    }
    Ok(())
}

impl CredentialMetadata {
    /// Validates every present field against the lowercase-token rule.
    ///
    /// # Errors
    /// Returns [`BrokerError::InjectionError`] naming the offending
    /// field. Messages quote only the field label, never the value.
    pub fn validate(&self) -> Result<(), BrokerError> {
        validate_optional_name(&self.username, "username")?;
        validate_optional_name(&self.header_name, "header_name")?;
        validate_optional_name(&self.query_param_name, "query_param_name")?;
        // The static prefix is arbitrary header *value* content (e.g.
        // "Bearer "), not a name — no token grammar applies to it.
        Ok(())
    }
}

/// Fully constructed outbound request awaiting transport execution.
///
/// This is the only structure into which secret material is written, and
/// only via [`CredentialInjector::apply`].
#[derive(Clone, Debug)]
pub struct OutboundRequest {
    /// Canonical destination (shared object used by authorization).
    pub canonical_url: CanonicalUrl,
    /// HTTP method of the outbound request.
    pub method: HttpMethod,
    /// Headers to transmit (lowercased names). Injection appends or
    /// replaces auth headers here.
    pub headers: Vec<(String, String)>,
    /// Request body.
    pub body: BrokerBody,
}

// ---------------------------------------------------------------------------
// Injector seam
// ---------------------------------------------------------------------------

/// One injection template (plan §21). Implementations write the resolved
/// secret into the outbound request; they must never copy it anywhere
/// else nor include it in error messages.
pub trait CredentialInjector: Send + Sync {
    /// Template implemented by this injector.
    fn template(&self) -> InjectionTemplateId;

    /// Applies this template's material placement.
    ///
    /// # Errors
    /// Returns [`BrokerError::InjectionError`] for missing/invalid
    /// metadata and [`BrokerError::TemplateUnsupported`] for templates
    /// this build cannot perform.
    fn apply(
        &self,
        req: &mut OutboundRequest,
        secret: &SecretBytes,
        meta: &CredentialMetadata,
    ) -> Result<(), BrokerError>;
}

/// Removes any existing header with `name` (case-insensitive), then
/// appends `(name_lower, value)`. Guarantees exactly one authoritative
/// occurrence of broker-owned headers (defense in depth for INV-004).
fn replace_header(headers: &mut Vec<(String, String)>, name: &str, value: String) {
    let lowered = name.to_ascii_lowercase();
    headers.retain(|(existing, _)| !existing.eq_ignore_ascii_case(&lowered));
    headers.push((lowered, value));
}

fn secret_as_string(secret: &SecretBytes) -> String {
    secret.expose(|bytes| String::from_utf8_lossy(bytes).into_owned())
}

// ---------------------------------------------------------------------------
// Built-in templates
// ---------------------------------------------------------------------------

/// `Authorization: Bearer <secret>`.
#[derive(Debug, Default, Clone, Copy)]
pub struct BearerInjector;

impl CredentialInjector for BearerInjector {
    fn template(&self) -> InjectionTemplateId {
        InjectionTemplateId::Bearer
    }

    fn apply(
        &self,
        req: &mut OutboundRequest,
        secret: &SecretBytes,
        _meta: &CredentialMetadata,
    ) -> Result<(), BrokerError> {
        let value = format!("Bearer {}", secret_as_string(secret));
        replace_header(&mut req.headers, "authorization", value);
        Ok(())
    }
}

/// `Authorization: token <secret>` — GitHub's personal-access-token
/// convention (`github_bearer`).
#[derive(Debug, Default, Clone, Copy)]
pub struct GithubBearerInjector;

impl CredentialInjector for GithubBearerInjector {
    fn template(&self) -> InjectionTemplateId {
        InjectionTemplateId::GithubBearer
    }

    fn apply(
        &self,
        req: &mut OutboundRequest,
        secret: &SecretBytes,
        _meta: &CredentialMetadata,
    ) -> Result<(), BrokerError> {
        let value = format!("token {}", secret_as_string(secret));
        replace_header(&mut req.headers, "authorization", value);
        Ok(())
    }
}

/// `<header_name>: <secret>`, header name taken from metadata.
#[derive(Debug, Default, Clone, Copy)]
pub struct ApiKeyHeaderInjector;

impl CredentialInjector for ApiKeyHeaderInjector {
    fn template(&self) -> InjectionTemplateId {
        InjectionTemplateId::ApiKeyHeader
    }

    fn apply(
        &self,
        req: &mut OutboundRequest,
        secret: &SecretBytes,
        meta: &CredentialMetadata,
    ) -> Result<(), BrokerError> {
        meta.validate()?;
        let header = meta.header_name.clone().ok_or_else(|| {
            BrokerError::InjectionError("api_key_header requires metadata.header_name".to_owned())
        })?;
        let value = secret_as_string(secret);
        replace_header(&mut req.headers, &header, value);
        Ok(())
    }
}

/// `Authorization: Basic base64(username:secret)` — username required
/// from metadata.
#[derive(Debug, Default, Clone, Copy)]
pub struct BasicPasswordInjector;

impl CredentialInjector for BasicPasswordInjector {
    fn template(&self) -> InjectionTemplateId {
        InjectionTemplateId::BasicPassword
    }

    fn apply(
        &self,
        req: &mut OutboundRequest,
        secret: &SecretBytes,
        meta: &CredentialMetadata,
    ) -> Result<(), BrokerError> {
        meta.validate()?;
        let username = meta.username.clone().ok_or_else(|| {
            BrokerError::InjectionError("basic_password requires metadata.username".to_owned())
        })?;
        // The combined userpass string exists only inside this closure
        // scope and is dropped immediately after encoding.
        let encoded = secret.expose(|bytes| {
            let mut userpass = Vec::with_capacity(username.len() + bytes.len() + 1);
            userpass.extend_from_slice(username.as_bytes());
            userpass.push(b':');
            userpass.extend_from_slice(bytes);
            BASE64_STANDARD.encode(userpass)
        });
        let value = format!("Basic {encoded}");
        replace_header(&mut req.headers, "authorization", value);
        Ok(())
    }
}

/// `<query_param_name>=<percent-encoded secret>` appended to the
/// canonical URL query.
///
/// The canonical URL is immutable by design (it is the same object
/// authorization approved), so injection rebuilds it from parts via
/// [`CanonicalUrl::from_parts`], which re-runs the full canonicalization
/// pipeline — a rebuilt URL can never be less strict than the original.
#[derive(Debug, Default, Clone, Copy)]
pub struct QueryParameterInjector;

/// Percent-encodes a query-component value using the RFC 3986 unreserved
/// set as safe characters. Deliberately conservative ("minimal" in code,
/// maximal in escaping): every byte outside `A-Z a-z 0-9 - . _ ~` becomes
/// `%XX`, so separators (`&`, `=`, `#`), spaces, plus signs, and non-ASCII
/// bytes cannot alter URL structure.
fn percent_encode_query_value(value: &[u8]) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(*byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn append_query_parameter(
    url: &CanonicalUrl,
    name: &str,
    encoded_value: &str,
) -> Result<CanonicalUrl, BrokerError> {
    let inner = url.as_url();
    // Rebuild path + query from parts (query kept as its raw serialized
    // form so pre-existing percent-encoding is preserved verbatim).
    let appended = match inner.query() {
        Some(existing) => {
            format!("{}?{existing}&{name}={encoded_value}", inner.path())
        }
        None => format!("{}?{name}={encoded_value}", inner.path()),
    };
    // Port: pass the *explicit* port option through so the default-443
    // normalization stays identical to the original serialization.
    CanonicalUrl::from_parts(url.host(), inner.port(), &appended)
        .map_err(|e| BrokerError::InjectionError(format!("rebuilt url rejected: {e}")))
}

impl CredentialInjector for QueryParameterInjector {
    fn template(&self) -> InjectionTemplateId {
        InjectionTemplateId::QueryParameter
    }

    fn apply(
        &self,
        req: &mut OutboundRequest,
        secret: &SecretBytes,
        meta: &CredentialMetadata,
    ) -> Result<(), BrokerError> {
        meta.validate()?;
        let param = meta.query_param_name.clone().ok_or_else(|| {
            BrokerError::InjectionError(
                "query_parameter requires metadata.query_param_name".to_owned(),
            )
        })?;
        let encoded = secret.expose(percent_encode_query_value);
        req.canonical_url = append_query_parameter(&req.canonical_url, &param, &encoded)?;
        Ok(())
    }
}

/// `<header_name>: <static_prefix><secret>` — both pieces from metadata
/// (e.g. prefix `"Bearer "` against a custom vendor header).
#[derive(Debug, Default, Clone, Copy)]
pub struct CustomStaticHeaderPlusSecretInjector;

impl CredentialInjector for CustomStaticHeaderPlusSecretInjector {
    fn template(&self) -> InjectionTemplateId {
        InjectionTemplateId::CustomStaticHeaderPlusSecret
    }

    fn apply(
        &self,
        req: &mut OutboundRequest,
        secret: &SecretBytes,
        meta: &CredentialMetadata,
    ) -> Result<(), BrokerError> {
        meta.validate()?;
        let header = meta.header_name.clone().ok_or_else(|| {
            BrokerError::InjectionError(
                "custom_static_header_plus_secret requires metadata.header_name".to_owned(),
            )
        })?;
        let prefix = meta.static_prefix.clone().ok_or_else(|| {
            BrokerError::InjectionError(
                "custom_static_header_plus_secret requires metadata.static_prefix".to_owned(),
            )
        })?;
        let value = format!("{prefix}{}", secret_as_string(secret));
        replace_header(&mut req.headers, &header, value);
        Ok(())
    }
}

/// AWS SigV4 request signing — **deferred**.
///
/// SigV4 is not simple field injection: the credential participates in
/// signing the canonical request itself (canonical headers ordering,
/// payload hash, clock-skew-bounded date headers). Doing it correctly
/// requires integration with the real transport layer (payload hashing
/// before send, signed-date control, region/service binding). Until that
/// lands (same task as the hardened HTTP client), any attempt returns
/// [`BrokerError::TemplateUnsupported`] rather than a silently broken or
/// insecure approximation (plan §21 notes specialized code is justified
/// precisely because of this request-signing coupling).
#[derive(Debug, Default, Clone, Copy)]
pub struct AwsSigv4Injector;

impl CredentialInjector for AwsSigv4Injector {
    fn template(&self) -> InjectionTemplateId {
        InjectionTemplateId::AwsSigv4
    }

    fn apply(
        &self,
        _req: &mut OutboundRequest,
        _secret: &SecretBytes,
        _meta: &CredentialMetadata,
    ) -> Result<(), BrokerError> {
        Err(BrokerError::TemplateUnsupported(
            "aws_sigv4 deferred".to_owned(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Lookup table of built-in injectors keyed by template id.
#[derive(Default)]
pub struct InjectorRegistry {
    injectors: HashMap<InjectionTemplateId, Box<dyn CredentialInjector>>,
}

impl std::fmt::Debug for InjectorRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Trait objects are not Debug; report the registered template
        // names instead (never any credential material).
        let mut templates: Vec<&str> = self
            .injectors
            .keys()
            .map(|template| template.as_str())
            .collect();
        templates.sort_unstable();
        f.debug_struct("InjectorRegistry")
            .field("templates", &templates)
            .finish()
    }
}

impl InjectorRegistry {
    /// Creates a registry with all built-in templates registered.
    #[must_use]
    pub fn new() -> Self {
        let mut registry = Self::default();
        for injector in [
            Box::new(BearerInjector) as Box<dyn CredentialInjector>,
            Box::new(BasicPasswordInjector),
            Box::new(ApiKeyHeaderInjector),
            Box::new(GithubBearerInjector),
            Box::new(QueryParameterInjector),
            Box::new(CustomStaticHeaderPlusSecretInjector),
            Box::new(AwsSigv4Injector),
        ] {
            registry.injectors.insert(injector.template(), injector);
        }
        registry
    }

    /// Looks up the injector for `template`.
    #[must_use]
    pub fn get(&self, template: InjectionTemplateId) -> Option<&dyn CredentialInjector> {
        self.injectors.get(&template).map(AsRef::as_ref)
    }

    /// Convenience wrapper resolving `template` then applying it.
    ///
    /// # Errors
    /// Returns [`BrokerError::TemplateUnsupported`] for unknown templates
    /// (including deferred ones like `aws_sigv4`); otherwise propagates
    /// the injector's errors.
    pub fn apply_for(
        &self,
        template: InjectionTemplateId,
        req: &mut OutboundRequest,
        secret: &SecretBytes,
        meta: &CredentialMetadata,
    ) -> Result<(), BrokerError> {
        let injector = self
            .get(template)
            .ok_or_else(|| BrokerError::TemplateUnsupported(template.as_str().to_owned()))?;
        injector.apply(req, secret, meta)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "s3cr3t-token-value";
    const CANARY: &str = SECRET;

    fn secret() -> SecretBytes {
        SecretBytes::from_bytes(SECRET.as_bytes())
    }

    fn outbound(url: &str) -> OutboundRequest {
        OutboundRequest {
            canonical_url: CanonicalUrl::parse(url).unwrap(),
            method: HttpMethod::GET,
            headers: vec![("accept".to_owned(), "application/json".to_owned())],
            body: BrokerBody::None,
        }
    }

    fn find_header<'a>(req: &'a OutboundRequest, name: &str) -> &'a str {
        req.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
            .unwrap_or_else(|| panic!("header {name} missing"))
    }

    #[test]
    fn template_ids_serialize_to_canonical_names() {
        for (id, name) in [
            (InjectionTemplateId::Bearer, "bearer"),
            (InjectionTemplateId::BasicPassword, "basic_password"),
            (InjectionTemplateId::ApiKeyHeader, "api_key_header"),
            (InjectionTemplateId::GithubBearer, "github_bearer"),
            (InjectionTemplateId::QueryParameter, "query_parameter"),
            (
                InjectionTemplateId::CustomStaticHeaderPlusSecret,
                "custom_static_header_plus_secret",
            ),
            (InjectionTemplateId::AwsSigv4, "aws_sigv4"),
        ] {
            assert_eq!(id.as_str(), name);
            assert_eq!(serde_json::to_string(&id).unwrap(), format!("\"{name}\""));
            assert_eq!(
                serde_json::from_str::<InjectionTemplateId>(&format!("\"{name}\"")).unwrap(),
                id
            );
        }
    }

    #[test]
    fn bearer_injector_writes_exact_header_and_replaces_existing() {
        let mut req = outbound("https://api.example.com/x");
        req.headers
            .push(("AUTHORIZATION".to_owned(), "Bearer evil".to_owned()));
        BearerInjector
            .apply(&mut req, &secret(), &CredentialMetadata::default())
            .unwrap();
        assert_eq!(
            find_header(&req, "authorization"),
            "Bearer s3cr3t-token-value"
        );
        assert_eq!(
            req.headers
                .iter()
                .filter(|(n, _)| n == "authorization")
                .count(),
            1,
            "exactly one authorization header must survive"
        );
    }

    #[test]
    fn github_bearer_injector_uses_github_token_convention() {
        let mut req = outbound("https://api.github.com/repos/acme/backend");
        GithubBearerInjector
            .apply(&mut req, &secret(), &CredentialMetadata::default())
            .unwrap();
        assert_eq!(
            find_header(&req, "authorization"),
            "token s3cr3t-token-value"
        );
    }

    #[test]
    fn api_key_injector_requires_header_name() {
        let mut req = outbound("https://vendor.example.com/v1");
        let missing = CredentialMetadata::default();
        let err = ApiKeyHeaderInjector
            .apply(&mut req, &secret(), &missing)
            .unwrap_err();
        assert!(matches!(err, BrokerError::InjectionError(ref msg) if msg.contains("header_name")));
        assert!(
            !err.to_string().contains(CANARY),
            "errors must not echo secret values"
        );

        let meta = CredentialMetadata {
            header_name: Some("x-api-key".to_owned()),
            ..CredentialMetadata::default()
        };
        ApiKeyHeaderInjector
            .apply(&mut req, &secret(), &meta)
            .unwrap();
        assert_eq!(find_header(&req, "x-api-key"), SECRET);

        // Uppercase or malformed names are refused before injection.
        let upper = CredentialMetadata {
            header_name: Some("X-API-Key".to_owned()),
            ..CredentialMetadata::default()
        };
        assert!(ApiKeyHeaderInjector
            .apply(&mut req, &secret(), &upper)
            .is_err());
    }

    #[test]
    fn basic_password_injector_encodes_username_and_secret() {
        let mut req = outbound("https://proxy.example.com/");
        let meta = CredentialMetadata {
            username: Some("svc-bot".to_owned()),
            ..CredentialMetadata::default()
        };
        BasicPasswordInjector
            .apply(&mut req, &secret(), &meta)
            .unwrap();

        let expected = BASE64_STANDARD.encode(format!("svc-bot:{SECRET}"));
        assert_eq!(
            find_header(&req, "authorization"),
            format!("Basic {expected}")
        );

        // Missing username is an explicit injection error.
        let err = BasicPasswordInjector
            .apply(&mut req, &secret(), &CredentialMetadata::default())
            .unwrap_err();
        assert!(matches!(err, BrokerError::InjectionError(msg) if msg.contains("username")));
    }

    #[test]
    fn query_parameter_injector_appends_encoded_value() {
        // Existing query gains the parameter.
        let mut req = outbound("https://collector.example.com/ingest?a=1");
        let meta = CredentialMetadata {
            query_param_name: Some("token".to_owned()),
            ..CredentialMetadata::default()
        };
        QueryParameterInjector
            .apply(&mut req, &secret(), &meta)
            .unwrap();
        let raw = req.canonical_url.as_url().as_str();
        assert_eq!(
            raw,
            "https://collector.example.com/ingest?a=1&token=s3cr3t-token-value"
        );
        assert_eq!(req.canonical_url.host(), "collector.example.com");

        // Hostile secret bytes cannot break query structure.
        let hostile = SecretBytes::from_bytes(b"a&b=c d%e+f#g?h\ti\x7f");
        let mut req2 = outbound("https://collector.example.com/ingest");
        QueryParameterInjector
            .apply(&mut req2, &hostile, &meta)
            .unwrap();
        let raw2 = req2.canonical_url.as_url().as_str();
        assert_eq!(
            raw2,
            "https://collector.example.com/ingest?token=a%26b%3Dc%20d%25e%2Bf%23g%3Fh%09i%7F"
        );
        // Round-trip through the parser recovers the original value.
        assert!(req2
            .canonical_url
            .query_pairs()
            .contains(&("token".to_owned(), "a&b=c d%e+f#g?h\ti\u{7f}".to_owned())));

        // No pre-existing query also works.
        let mut req3 = outbound("https://collector.example.com/ingest");
        QueryParameterInjector
            .apply(&mut req3, &secret(), &meta)
            .unwrap();
        assert!(req3
            .canonical_url
            .as_url()
            .as_str()
            .ends_with("/ingest?token=s3cr3t-token-value"));

        // Missing parameter name is an explicit error.
        let err = QueryParameterInjector
            .apply(&mut req, &secret(), &CredentialMetadata::default())
            .unwrap_err();
        assert!(
            matches!(err, BrokerError::InjectionError(msg) if msg.contains("query_param_name"))
        );

        // Explicit ports survive the rebuild.
        let mut req4 = outbound("https://collector.example.com:8443/i");
        QueryParameterInjector
            .apply(&mut req4, &secret(), &meta)
            .unwrap();
        assert_eq!(
            req4.canonical_url.as_url().as_str(),
            "https://collector.example.com:8443/i?token=s3cr3t-token-value"
        );
    }

    #[test]
    fn custom_static_injector_requires_both_metadata_pieces() {
        let mut req = outbound("https://vendor.example.com/api");
        let err = CustomStaticHeaderPlusSecretInjector
            .apply(&mut req, &secret(), &CredentialMetadata::default())
            .unwrap_err();
        assert!(matches!(err, BrokerError::InjectionError(msg) if msg.contains("header_name")));

        let partial = CredentialMetadata {
            header_name: Some("x-vendor-auth".to_owned()),
            ..CredentialMetadata::default()
        };
        let err = CustomStaticHeaderPlusSecretInjector
            .apply(&mut req, &secret(), &partial)
            .unwrap_err();
        assert!(matches!(err, BrokerError::InjectionError(msg) if msg.contains("static_prefix")));

        let full = CredentialMetadata {
            static_prefix: Some("Prefix ".to_owned()),
            ..partial
        };
        CustomStaticHeaderPlusSecretInjector
            .apply(&mut req, &secret(), &full)
            .unwrap();
        assert_eq!(
            find_header(&req, "x-vendor-auth"),
            "Prefix s3cr3t-token-value"
        );
    }

    #[test]
    fn aws_sigv4_is_explicitly_unsupported_with_deferred_reason() {
        let mut req = outbound("https://s3.amazonaws.com/bucket");
        let err = AwsSigv4Injector
            .apply(&mut req, &secret(), &CredentialMetadata::default())
            .unwrap_err();
        assert!(matches!(
            err,
            BrokerError::TemplateUnsupported(ref msg) if msg.contains("aws_sigv4") && msg.contains("deferred")
        ));
        assert!(!req.canonical_url.as_url().as_str().contains(CANARY));
        assert!(req.headers.iter().all(|(n, _)| n != "authorization"));
    }

    #[test]
    fn registry_resolves_every_builtin_template() {
        let registry = InjectorRegistry::new();
        for template in [
            InjectionTemplateId::Bearer,
            InjectionTemplateId::BasicPassword,
            InjectionTemplateId::ApiKeyHeader,
            InjectionTemplateId::GithubBearer,
            InjectionTemplateId::QueryParameter,
            InjectionTemplateId::CustomStaticHeaderPlusSecret,
            InjectionTemplateId::AwsSigv4,
        ] {
            let injector = registry.get(template).expect("builtin registered");
            assert_eq!(injector.template(), template);
        }
        assert!(registry.get(InjectionTemplateId::Bearer).is_some());

        // apply_for routes to the right implementation...
        let mut req = outbound("https://api.example.com/");
        registry
            .apply_for(
                InjectionTemplateId::GithubBearer,
                &mut req,
                &secret(),
                &CredentialMetadata::default(),
            )
            .unwrap();
        assert_eq!(
            find_header(&req, "authorization"),
            "token s3cr3t-token-value"
        );

        // ...and surfaces TemplateUnsupported for the deferred template.
        let err = registry
            .apply_for(
                InjectionTemplateId::AwsSigv4,
                &mut req,
                &secret(),
                &CredentialMetadata::default(),
            )
            .unwrap_err();
        assert!(matches!(err, BrokerError::TemplateUnsupported(_)));
    }

    #[test]
    fn metadata_validation_rejects_non_lowercase_or_invalid_names() {
        for bad in ["UPPER", "has space", "", "with/slash", "tab\tchar"] {
            let meta = CredentialMetadata {
                header_name: Some(bad.to_owned()),
                ..CredentialMetadata::default()
            };
            assert!(meta.validate().is_err(), "{bad:?} should fail validation");
        }
        let ok = CredentialMetadata {
            username: Some("svc_bot-1".to_owned()),
            query_param_name: Some("api.key-2".to_owned()),
            ..CredentialMetadata::default()
        };
        assert!(ok.validate().is_ok());
        // Empty metadata validates trivially.
        assert!(CredentialMetadata::default().validate().is_ok());
    }

    #[test]
    fn metadata_serde_round_trips() {
        let meta = CredentialMetadata {
            username: Some("bot".to_owned()),
            header_name: Some("x-key".to_owned()),
            ..CredentialMetadata::default()
        };
        let decoded: CredentialMetadata =
            serde_json::from_str(&serde_json::to_string(&meta).unwrap()).unwrap();
        assert_eq!(decoded, meta);
    }

    #[test]
    fn injected_headers_carry_lowercase_names() {
        let mut req = outbound("https://api.example.com/");
        let meta = CredentialMetadata {
            header_name: Some("x-custom".to_owned()),
            ..CredentialMetadata::default()
        };
        ApiKeyHeaderInjector
            .apply(&mut req, &secret(), &meta)
            .unwrap();
        assert!(req
            .headers
            .iter()
            .any(|(n, _)| n == "x-custom" && n.chars().all(|c| !c.is_ascii_uppercase())));
    }
}
