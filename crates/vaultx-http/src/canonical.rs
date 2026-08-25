//! URL canonicalization: one canonical destination representation shared
//! by authorization *and* transport.
//!
//! # Canonicalization contract
//!
//! The canonical form of a destination is the [`url::Url`] serialization
//! produced by this module after the restrictions below are applied.
//! Policy evaluation and the eventual broker transport **must** both use
//! this same value (plan §20: "Policy evaluates the same canonical
//! destination that transport uses"). Any drift between the two is a
//! deny-evasion vector, so callers never re-parse raw strings after
//! [`CanonicalUrl::parse`]; they pass the `CanonicalUrl` itself onward.
//!
//! Enforced on every parse:
//!
//! * scheme must be exactly `https` (cleartext and custom schemes are
//!   rejected — see [`crate::error::HttpPolicyError::UnsupportedScheme`]);
//! * no userinfo (`user[:password]@`) may appear;
//! * the host must be present, ASCII-only, lowercase, and free of
//!   underscores and empty labels. Non-ASCII hostnames are rejected in v1
//!   (IDNA is not performed): callers must supply pre-encoded punycode
//!   (`xn--…`) if they need internationalized names;
//! * explicit ports are allowed when syntactically valid; the default
//!   port (`443`) is normalized away by the `url` crate;
//! * fragments are stripped silently — they are client-side only and are
//!   never transmitted to a server;
//! * dot segments (`.` / `..`) are resolved via `url`'s RFC 3986-style
//!   serialization, and percent escapes are normalized to uppercase hex
//!   (the `url` crate preserves the case of pre-existing escapes, so this
//!   crate applies the final pass itself).
//!
//! # Numeric host spellings
//!
//! Hosts that end in a number are normalized by the `url` crate's WHATWG
//! IPv4 parser *before* validation, with full radix detection: `2130706433`,
//! `0x7f000001`, `127.1`, and octal `010.0.0.1` all become `127.0.0.1` /
//! `8.0.0.1`. This closes the classic `inet_aton` SSRF gap at the
//! canonicalization boundary: policy never sees an ambiguous numeric
//! hostname that a resolver could reinterpret into different bytes than
//! [`crate::netpolicy::EgressGuard::check_host`] classified. Spellings
//! that cannot be parsed as IPv4 (`example.1`, `4294967296`) fail
//! outright rather than passing through as opaque names. The regression
//! tests below pin this behavior; if a `url` upgrade changes it, treat
//! that as a security-relevant change.

use url::Url;

use crate::error::HttpPolicyError;

/// A validated, canonical HTTPS destination.
///
/// Construct only through [`CanonicalUrl::parse`] or
/// [`CanonicalUrl::from_parts`]; both apply identical validation so the
/// two constructors cannot diverge.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CanonicalUrl {
    inner: Url,
}

impl CanonicalUrl {
    /// Parses and canonicalizes a raw URL string.
    ///
    /// # Errors
    /// Returns:
    /// * [`HttpPolicyError::UnsupportedScheme`] for any scheme other than
    ///   `https` (including plain `http`);
    /// * [`HttpPolicyError::UserInfoDisallowed`] when the authority
    ///   carries userinfo;
    /// * [`HttpPolicyError::InvalidPort`] when an embedded port is not a
    ///   valid `u16` or is `0` (ports must be `1..=65535`);
    /// * [`HttpPolicyError::InvalidUrl`] for malformed input, missing or
    ///   non-ASCII/percent-encoded hosts, underscored or empty hostname
    ///   labels, or a missing path component.
    pub fn parse(raw: &str) -> Result<Self, HttpPolicyError> {
        // Reject anything in the raw authority that could smuggle a
        // hostname past IDNA processing (unicode code points), hide
        // structure via percent-encoding, or carry userinfo. Any `@` in
        // the authority is userinfo by definition — including degenerate
        // forms like `:@host`, which the `url` crate would silently
        // normalize away.
        let authority = raw.split_once("://").map(|(_, rest)| rest);
        if let Some(authority) = authority {
            let end = authority.find(['/', '?', '#']).unwrap_or(authority.len());
            let authority = &authority[..end];
            if !authority.is_ascii() || authority.contains('%') {
                return Err(HttpPolicyError::InvalidUrl(
                    "hostnames must be pre-encoded ASCII (no unicode or percent escapes)"
                        .to_owned(),
                ));
            }
            if authority.contains('@') {
                return Err(HttpPolicyError::UserInfoDisallowed);
            }
        }

        // The error may never echo the raw URL: query strings and paths
        // routinely carry credential material (`?token=…`), and the
        // crate-level contract keeps errors secret-blind.
        let mut parsed = Url::parse(raw).map_err(|err| match err {
            url::ParseError::InvalidPort => HttpPolicyError::InvalidPort(offending_port_token(raw)),
            other => HttpPolicyError::InvalidUrl(other.to_string()),
        })?;

        let scheme = parsed.scheme().to_owned();
        if scheme != "https" {
            return Err(HttpPolicyError::UnsupportedScheme(scheme));
        }
        // The WHATWG parser accepts port 0; policy requires `1..=65535`
        // (mirroring `from_parts`), so the explicit-port guard lives here.
        if parsed.port() == Some(0) {
            return Err(HttpPolicyError::InvalidPort("0".to_owned()));
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(HttpPolicyError::UserInfoDisallowed);
        }

        let Some(host) = parsed.host_str() else {
            return Err(HttpPolicyError::InvalidUrl("missing host".to_owned()));
        };
        validate_host(host)?;

        // Fragments are never sent to the server; drop them so the
        // canonical form cannot differ from the wire form.
        parsed.set_fragment(None);

        // Normalize pre-existing percent-escapes to uppercase hex so two
        // spellings of one resource share a single canonical string.
        let normalized = normalize_percent_case(parsed.as_str());
        let inner =
            Url::parse(&normalized).map_err(|err| HttpPolicyError::InvalidUrl(err.to_string()))?;

        Ok(Self { inner })
    }

    /// Builds a canonical URL from already-matched components.
    ///
    /// Intended for the broker, which matches policy against individual
    /// components (host, optional explicit port, path+query) and needs to
    /// hand transport a single canonical object afterwards. Runs the exact
    /// same validation pipeline as [`CanonicalUrl::parse`].
    ///
    /// # Errors
    /// Same variants as [`CanonicalUrl::parse`], plus
    /// [`HttpPolicyError::InvalidPort`] when `port` is `0`, and
    /// [`HttpPolicyError::InvalidUrl`] when `path_and_query` is neither
    /// empty nor starts with `/`.
    pub fn from_parts(
        host: &str,
        port: Option<u16>,
        path_and_query: &str,
    ) -> Result<Self, HttpPolicyError> {
        if let Some(0) = port {
            return Err(HttpPolicyError::InvalidPort("0".to_owned()));
        }
        if !path_and_query.is_empty() && !path_and_query.starts_with('/') {
            return Err(HttpPolicyError::InvalidUrl(format!(
                "path must start with `/`: {path_and_query}"
            )));
        }
        let port_suffix = port.map_or_else(String::new, |p| format!(":{p}"));
        let path = if path_and_query.is_empty() {
            "/"
        } else {
            path_and_query
        };
        Self::parse(&format!("https://{host}{port_suffix}{path}"))
    }

    /// The lowercased host (IPv6 literals keep their brackets).
    #[must_use]
    pub fn host(&self) -> &str {
        // `validate_host` guarantees presence at construction time.
        self.inner.host_str().unwrap_or_default()
    }

    /// The effective port: the explicit port when present, otherwise the
    /// HTTPS default `443`.
    #[must_use]
    pub fn port_or_default(&self) -> u16 {
        // The scheme is always `https`, so the known-default lookup can
        // only miss on non-special URLs, which cannot occur here.
        self.inner.port_or_known_default().unwrap_or(443)
    }

    /// The request path, always starting with `/`.
    #[must_use]
    pub fn path(&self) -> String {
        self.inner.path().to_owned()
    }

    /// The query string decoded into ordered `(name, value)` pairs.
    /// Repeated keys appear once per occurrence, preserving order.
    #[must_use]
    pub fn query_pairs(&self) -> Vec<(String, String)> {
        self.inner
            .query_pairs()
            .into_iter()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }

    /// Read access to the underlying canonical `url::Url` (the canonical
    /// form per the module contract).
    #[must_use]
    pub const fn as_url(&self) -> &Url {
        &self.inner
    }
}

/// Hostname grammar enforced post-canonicalization.
fn validate_host(host: &str) -> Result<(), HttpPolicyError> {
    // IPv6 literals arrive bracketed; validate the inner address instead.
    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return if inner.parse::<std::net::Ipv6Addr>().is_ok() {
            Ok(())
        } else {
            Err(HttpPolicyError::InvalidUrl(format!(
                "invalid ipv6 literal `{inner}`"
            )))
        };
    }
    if !host.is_ascii() {
        return Err(HttpPolicyError::InvalidUrl(format!(
            "hostname must be ASCII: `{host}`"
        )));
    }
    for label in host.split('.') {
        if label.is_empty() {
            // Catches both interior empty labels (`a..b`) and a trailing
            // root dot (`example.com.`), which are rejected to keep the
            // canonical host unambiguous.
            return Err(HttpPolicyError::InvalidUrl(format!(
                "hostname contains an empty label: `{host}`"
            )));
        }
        if label.contains('_') {
            return Err(HttpPolicyError::InvalidUrl(format!(
                "hostname labels may not contain `_`: `{host}`"
            )));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(HttpPolicyError::InvalidUrl(format!(
                "hostname contains characters outside [a-z0-9-]: `{host}`"
            )));
        }
    }
    Ok(())
}

/// Uppercases the hex digits of every percent-escape in a URL string.
///
/// The `url` crate emits uppercase hex for escapes it adds itself but
/// preserves the case of escapes already present in the input; this pass
/// closes that gap so `%2f` and `%2F` collapse to one canonical spelling.
/// Case changes never alter semantics, and the serialization is ASCII
/// (the `url` crate percent-encodes all non-ASCII), so byte-wise handling
/// is safe.
fn normalize_percent_case(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            out.push('%');
            out.push((bytes[i + 1] as char).to_ascii_uppercase());
            out.push((bytes[i + 2] as char).to_ascii_uppercase());
            i += 3;
        } else {
            // The serialization is ASCII (`url` percent-encodes all
            // non-ASCII), so byte-to-char promotion is lossless.
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

/// Extracts just the malformed port token for [`HttpPolicyError::InvalidPort`].
///
/// Only the port substring inside the raw authority is surfaced; when it
/// cannot be isolated (no `://`, empty token) a fixed placeholder is used
/// instead. The authority window is cut at `/ ? # \` so paths, queries,
/// and fragments can never leak into an error message.
fn offending_port_token(raw: &str) -> String {
    let Some((_, rest)) = raw.split_once("://") else {
        return "*".to_owned();
    };
    let end = rest.find(['/', '?', '#', '\\']).unwrap_or(rest.len());
    let authority = &rest[..end];
    // For bracketed hosts (`[::1]:8443`) the relevant separator is the
    // colon *after* the closing bracket.
    let host_end = if authority.starts_with('[') {
        authority.find(']').map_or(0, |i| i + 1)
    } else {
        0
    };
    match authority[host_end..].rsplit_once(':') {
        Some((_, port)) if !port.is_empty() => {
            // Cap length defensively: a hostile token must not bloat logs.
            port.chars().take(16).collect()
        }
        _ => "*".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ok(raw: &str) -> CanonicalUrl {
        CanonicalUrl::parse(raw).unwrap_or_else(|e| panic!("expected Ok for {raw}: {e:?}"))
    }

    #[test]
    fn https_only_is_enforced() {
        for raw in [
            "http://example.com/",
            "ftp://example.com/file",
            "file:///etc/passwd",
            "unix:/run/socket",
            "ws://example.com/",
            "data:text/plain,hi",
        ] {
            let err = CanonicalUrl::parse(raw).expect_err(raw);
            assert!(
                matches!(err, HttpPolicyError::UnsupportedScheme(_)),
                "{raw} -> {err:?}"
            );
        }
        parse_ok("https://example.com/");
    }

    #[test]
    fn userinfo_is_rejected_in_every_shape() {
        for raw in [
            "https://user:pass@example.com/",
            "https://user@example.com/",
            "https://:pass@example.com/",
            "https://:@example.com/",
        ] {
            let err = CanonicalUrl::parse(raw).expect_err(raw);
            assert!(matches!(err, HttpPolicyError::UserInfoDisallowed), "{raw}");
        }
    }

    #[test]
    fn dot_segments_are_resolved() {
        let u = parse_ok("https://x.com/a/../b?q=1");
        assert_eq!(u.path(), "/b");
        assert_eq!(u.query_pairs(), vec![("q".to_owned(), "1".to_owned())]);

        let u = parse_ok("https://x.com/a/b/../../c");
        assert_eq!(u.path(), "/c");

        let u = parse_ok("https://x.com");
        assert_eq!(u.path(), "/");
    }

    #[test]
    fn percent_encoding_normalizes_to_uppercase_hex() {
        let u = parse_ok("https://x.com/a%2fb%3fc?k=%aa");
        assert_eq!(u.path(), "/a%2Fb%3Fc");
        assert_eq!(u.as_url().as_str(), "https://x.com/a%2Fb%3Fc?k=%AA");
    }

    #[test]
    fn fragments_are_stripped_silently() {
        let u = parse_ok("https://x.com/page#section-2");
        assert_eq!(u.path(), "/page");
        assert!(u.as_url().fragment().is_none());
        assert_eq!(u.as_url().as_str(), "https://x.com/page");
    }

    #[test]
    fn idna_unicode_hosts_are_rejected_but_punycode_passes() {
        let err = CanonicalUrl::parse("https://münchen.example/").expect_err("unicode host");
        assert!(matches!(err, HttpPolicyError::InvalidUrl(msg) if msg.contains("pre-encoded")));
        let err = CanonicalUrl::parse("https://ex%41mple.com/").expect_err("percent escape");
        assert!(matches!(err, HttpPolicyError::InvalidUrl(_)));
        // Pre-encoded punycode is the supported v1 spelling.
        let u = parse_ok("https://xn--mnchen-3ya.example/");
        assert_eq!(u.host(), "xn--mnchen-3ya.example");
    }

    #[test]
    fn underscore_and_empty_labels_are_rejected() {
        for raw in [
            "https://ex_ample.com/",
            "https://a..b.com/",
            "https://.example.com/",
            "https://example.com./", // trailing root dot -> empty final label
            "https://ex ample.com/",
            "https://exam ple.com/",
        ] {
            assert!(
                CanonicalUrl::parse(raw).is_err(),
                "expected rejection of `{raw}`"
            );
        }
        parse_ok("https://sub-domain-1.example.co/");
    }

    #[test]
    fn ports_are_validated_and_default_normalized() {
        let u = parse_ok("https://example.com:8443/p");
        assert_eq!(u.port_or_default(), 8443);
        assert_eq!(u.as_url().as_str(), "https://example.com:8443/p");

        // Default port 443 is normalized away by `url`.
        let u = parse_ok("https://example.com:443/p");
        assert_eq!(u.port_or_default(), 443);
        assert_eq!(u.as_url().as_str(), "https://example.com/p");

        let err = CanonicalUrl::parse("https://example.com:99999/").expect_err("port overflow");
        assert!(matches!(err, HttpPolicyError::InvalidPort(_)));

        // Regression: the WHATWG parser accepts port 0, but the
        // 1..=65535 contract must hold for `parse` too.
        let err = CanonicalUrl::parse("https://example.com:0/").expect_err("port zero");
        assert!(matches!(err, HttpPolicyError::InvalidPort(_)));

        let err = CanonicalUrl::from_parts("example.com", Some(0), "/").expect_err("port zero");
        assert!(matches!(err, HttpPolicyError::InvalidPort(_)));
    }

    #[test]
    fn invalid_port_errors_never_echo_url_secrets() {
        // Query strings routinely carry credential material; the error
        // must surface the port token only (crate secret-blindness
        // contract).
        let err = CanonicalUrl::parse("https://example.com:99999/?token=sk-hunter2").unwrap_err();
        assert_eq!(err.to_string(), "invalid port `99999`");
        let rendered = err.to_string();
        assert!(!rendered.contains("sk-hunter2"));
        assert!(!rendered.contains("example.com"));

        // Bracketed IPv6 with a bad port isolates the token after `]`.
        let err = CanonicalUrl::parse("https://[2001:db8::1]:abc/x?secret=1").unwrap_err();
        assert_eq!(err.to_string(), "invalid port `abc`");

        // No isolatable token falls back to a placeholder.
        let err = CanonicalUrl::parse("https://example.com:x/").unwrap_err();
        assert_eq!(err.to_string(), "invalid port `x`");
    }

    #[test]
    fn trailing_query_preserved_with_order_and_duplicates() {
        let u = parse_ok("https://x.com/search?a=1&b=two+words&a=3&flag");
        assert_eq!(
            u.query_pairs(),
            vec![
                ("a".to_owned(), "1".to_owned()),
                ("b".to_owned(), "two words".to_owned()),
                ("a".to_owned(), "3".to_owned()),
                ("flag".to_owned(), String::new()),
            ]
        );
    }

    #[test]
    fn malformed_urls_report_invalid_url() {
        for raw in ["https://", "not a url at all", ""] {
            let err = CanonicalUrl::parse(raw).expect_err(raw);
            assert!(matches!(err, HttpPolicyError::InvalidUrl(_)), "{raw}");
        }
    }

    #[test]
    fn from_parts_matches_parse_pipeline() {
        let built = CanonicalUrl::from_parts("Example.COM", Some(9443), "/v1/x?y=1").unwrap();
        let direct = CanonicalUrl::parse("https://example.com:9443/v1/x?y=1").unwrap();
        assert_eq!(built, direct);
        assert_eq!(built.host(), "example.com");

        let built = CanonicalUrl::from_parts("example.com", None, "").unwrap();
        assert_eq!(built.port_or_default(), 443);
        assert_eq!(built.path(), "/");

        let err = CanonicalUrl::from_parts("example.com", None, "v1/no-slash").unwrap_err();
        assert!(matches!(err, HttpPolicyError::InvalidUrl(_)));
    }

    #[test]
    fn ipv6_literal_hosts_are_accepted_and_guarded() {
        let u = parse_ok("https://[2001:db8::1]/x");
        assert_eq!(u.host(), "[2001:db8::1]");
        assert!(CanonicalUrl::parse("https://[not-an-ip]/").is_err());
    }

    /// Pins the WHATWG IPv4 normalization contract: numeric host
    /// spellings must resolve to exact dotted quads *inside the parser*
    /// so that `EgressGuard::check_host` classifies the same bytes a
    /// resolver would use. If a `url` upgrade starts passing these
    /// through as opaque names, this test fails and the change is
    /// security-relevant (see module docs).
    #[test]
    fn numeric_host_spellings_normalize_before_validation() {
        let loopback = |h: &str| {
            let u = parse_ok(h);
            assert_eq!(u.host(), "127.0.0.1", "{h} must normalize to 127.0.0.1");
        };
        loopback("https://2130706433/"); // decimal integer form
        loopback("https://0x7f000001/"); // hex integer form
        loopback("https://127.1/"); // partial quad
        loopback("https://0177.0.0.1/"); // dotted octal

        // Octal leading-zero quad: 010 == 8 decimal.
        assert_eq!(parse_ok("https://010.0.0.1/").host(), "8.0.0.1");

        // Hex-labeled quad normalizes to the metadata endpoint — which
        // downstream classification then denies; canonicalization itself
        // only guarantees byte-exactness.
        assert_eq!(
            parse_ok("https://0xA9.0xFE.0xA9.0xFE/").host(),
            "169.254.169.254"
        );

        // Spellings that cannot be IPv4 fail rather than passing through
        // as resolver-reinterpretable opaque names.
        for raw in [
            "https://example.1/",
            "https://a.b.1/",
            "https://99999999999/",
            "https://256.1.1.1/",
        ] {
            assert!(
                CanonicalUrl::parse(raw).is_err(),
                "expected rejection of `{raw}`"
            );
        }

        // Exact dotted-quad literals remain valid input for classification.
        assert_eq!(parse_ok("https://8.8.8.8/x").host(), "8.8.8.8");
    }
}

/// Property tests for spelling-invariance (plan §43: "denied canonical
/// request cannot become allowed through alternate URL spelling").
///
/// The invariant under test is INV-005's foundation: authorization runs on
/// exactly one canonical destination, so every alternate spelling of one
/// logical request must collapse to the identical [`CanonicalUrl`] — and
/// therefore to an identical policy decision, in both the deny direction
/// (spelling cannot rescue a denied request) and the allow direction
/// (spelling cannot flip an allow into a deny either).
#[cfg(test)]
mod proptests {
    use super::*;
    use crate::netpolicy::EgressGuard;
    use proptest::prelude::*;
    use std::collections::BTreeMap;
    use vaultx_policy::{
        parse_policy_yaml, Action, AuthorizationContext, AuthorizationDecision, Authorizer,
        HttpMethod, RuleEngine,
    };

    /// DNS-style hosts: 1–3 labels of `[a-z][a-z0-9]{1,7}` — valid under
    /// both the canonicalizer's host grammar and the policy engine's
    /// hostname validation.
    fn hosts() -> impl Strategy<Value = String> {
        proptest::collection::vec("[a-z][a-z0-9]{1,7}", 1..=3usize)
            .prop_map(|labels| labels.join("."))
            .boxed()
    }

    fn path_segments() -> impl Strategy<Value = Vec<String>> {
        proptest::collection::vec("[a-z0-9]{1,8}", 1..=3usize)
            .prop_filter("needs at least one segment", |segments| {
                !segments.is_empty()
            })
    }

    /// Flips the case of alphabetic characters at even indices — a
    /// spelling variant beyond plain full-uppercase.
    fn mixed_case(host: &str) -> String {
        host.chars()
            .enumerate()
            .map(|(index, c)| {
                if index % 2 == 0 {
                    c.to_ascii_uppercase()
                } else {
                    c
                }
            })
            .collect()
    }

    /// Alternate spellings of one logical `https://{host}/{path}?{query}`
    /// request: case variants of the host, default-port elision/addition,
    /// fragment addition/removal, dot-segment detours (`./`, `zz/../`),
    /// percent-escape case flips, and query presence held consistent per
    /// generated input (`?k=` with an empty value is a *different*
    /// resource from no query, so the two families never mix).
    ///
    /// The final path segment always carries `%2F`/`%2f` so escape-case
    /// normalization is exercised on every generated input.
    fn spellings(
        host: &str,
        segments: &[String],
        query_key: &str,
        query_value: &str,
        escape_uppercase: bool,
        with_query: bool,
    ) -> Vec<String> {
        let tail = if escape_uppercase {
            "esc%2Fape"
        } else {
            "esc%2fape"
        };
        let mut parts: Vec<&str> = segments.iter().map(String::as_str).collect();
        parts.push(tail);

        let suffix = if with_query {
            format!("?{query_key}={query_value}")
        } else {
            String::new()
        };
        let plain_path = format!("/{}", parts.join("/"));
        let dotted_path = format!("/./{}", parts.join("/"));
        let dotted_mid_path = if parts.len() > 2 {
            format!("/{}/zz/../{}", parts[0], parts[1..].join("/"))
        } else {
            dotted_path.clone()
        };

        vec![
            format!("https://{host}{plain_path}{suffix}"),
            format!("https://{}{plain_path}{suffix}", host.to_uppercase()),
            format!("https://{}{plain_path}{suffix}", mixed_case(host)),
            format!("https://{host}:443{plain_path}{suffix}"),
            format!("https://{host}{plain_path}{suffix}#anchor"),
            format!("https://{host}{dotted_path}{suffix}"),
            format!("https://{host}{dotted_mid_path}{suffix}"),
        ]
    }

    /// Builds the engine-facing context from a canonical URL, mirroring
    /// the broker transport obligation: values are taken from the
    /// canonical form only.
    fn context_of(url: &CanonicalUrl) -> AuthorizationContext {
        let mut query = BTreeMap::new();
        for (key, value) in url.query_pairs() {
            query.insert(key, value);
        }
        AuthorizationContext {
            host: url.host().to_owned(),
            method: HttpMethod::GET,
            path: url.path(),
            query,
            body_len_bytes: 0,
            environment: None,
        }
    }

    fn authorize_all(engine: &RuleEngine, urls: &[CanonicalUrl]) -> Vec<AuthorizationDecision> {
        urls.iter()
            .map(|url| {
                engine.authorize(&vaultx_policy::AuthorizationRequest {
                    principal: vaultx_policy::Principal::parse("agent:prop-agent").unwrap(),
                    action: Action::HttpRequest,
                    resource: vaultx_policy::Resource::parse("prop-token").unwrap(),
                    context: context_of(url),
                })
            })
            .collect()
    }

    fn engine_from_yaml(yaml: &str) -> RuleEngine {
        RuleEngine::from_documents([parse_policy_yaml(yaml).unwrap()]).unwrap()
    }

    fn allowing_yaml(host: &str) -> String {
        format!(
            "name: prop-allow\n\
             principal: agent:prop-agent\n\
             credential: prop-token\n\
             http:\n\
             \x20 hosts: [{host}]\n\
             \x20 allow:\n\
             \x20   - methods: [GET]\n\
             \x20     paths: [\"/**\"]\n"
        )
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Every spelling of one logical request parses successfully and
        /// collapses to the byte-identical canonical URL.
        #[test]
        fn alternate_spellings_share_one_canonical_url(
            host in hosts(),
            segments in path_segments(),
            query_key in "[a-z]{1,5}",
            query_value in "[a-z0-9]{1,5}",
            escape_uppercase in prop::bool::ANY,
            with_query in prop::bool::ANY,
        ) {
            let raws = spellings(&host, &segments, &query_key, &query_value, escape_uppercase, with_query);
            let base = CanonicalUrl::parse(&raws[0]).unwrap();
            for raw in &raws {
                let parsed = CanonicalUrl::parse(raw)
                    .unwrap_or_else(|err| panic!("spelling {raw} must parse: {err:?}"));
                prop_assert_eq!(&parsed, &base);
                prop_assert_eq!(parsed.host(), base.host());
                prop_assert_eq!(parsed.path(), base.path());
                prop_assert_eq!(parsed.query_pairs(), base.query_pairs());
            }
        }

        /// Deny direction: with no policies bound at all, every spelling
        /// yields the identical deny decision — spelling can never rescue
        /// a denied request.
        #[test]
        fn denied_request_stays_denied_under_every_spelling(
            host in hosts(),
            segments in path_segments(),
            query_key in "[a-z]{1,5}",
            query_value in "[a-z0-9]{1,5}",
            escape_uppercase in prop::bool::ANY,
            with_query in prop::bool::ANY,
        ) {
            let empty = RuleEngine::new();
            let wrong_host = engine_from_yaml(
                "name: prop-wrong-host\n\
                 principal: agent:prop-agent\n\
                 credential: prop-token\n\
                 http:\n\
                 \x20 hosts: [denied.example]\n\
                 \x20 allow:\n\
                 \x20   - methods: [GET]\n\
                 \x20     paths: [\"/**\"]\n",
            );

            let raws =
                spellings(&host, &segments, &query_key, &query_value, escape_uppercase, with_query);
            let urls: Vec<CanonicalUrl> = raws
                .iter()
                .map(|raw| CanonicalUrl::parse(raw).unwrap())
                .collect();

            for decisions in [
                authorize_all(&empty, &urls),
                authorize_all(&wrong_host, &urls),
            ] {
                let first = decisions.first().cloned().unwrap();
                assert!(matches!(first, AuthorizationDecision::Deny { .. }));
                for (raw, decision) in raws.iter().zip(&decisions) {
                    prop_assert_eq!(decision, &first, "decision drifted for spelling {}", raw);
                }
            }
        }

        /// Allow direction: when policy allows the canonical request,
        /// every spelling produces the identical allow — normalization
        /// never silently turns an allow into a deny either.
        #[test]
        fn allowed_request_stays_allowed_under_every_spelling(
            host in hosts(),
            segments in path_segments(),
            query_key in "[a-z]{1,5}",
            query_value in "[a-z0-9]{1,5}",
            escape_uppercase in prop::bool::ANY,
            with_query in prop::bool::ANY,
        ) {
            let engine = engine_from_yaml(&allowing_yaml(&host));

            let raws =
                spellings(&host, &segments, &query_key, &query_value, escape_uppercase, with_query);
            let urls: Vec<CanonicalUrl> = raws
                .iter()
                .map(|raw| CanonicalUrl::parse(raw).unwrap())
                .collect();

            let decisions = authorize_all(&engine, &urls);
            let first = decisions.first().cloned().unwrap();
            assert!(matches!(
                first,
                AuthorizationDecision::Allow { .. }
            ));
            for (raw, decision) in raws.iter().zip(&decisions) {
                prop_assert_eq!(decision, &first, "decision drifted for spelling {}", raw);
            }

            // Explicit-deny policies also bind on the canonical form only:
            // a GET deny rule denies all spellings identically even while
            // an allow rule exists in the same document.
            let denying_yaml = format!(
                "name: prop-deny\n\
                 principal: agent:prop-agent\n\
                 credential: prop-token\n\
                 http:\n\
                 \x20 hosts: [{host}]\n\
                 \x20 allow:\n\
                 \x20   - methods: [POST]\n\
                 \x20     paths: [\"/**\"]\n\
                 \x20 deny:\n\
                 \x20   - methods: [GET]\n\
                 \x20     paths: [\"/**\"]\n"
            );
            let denier = engine_from_yaml(&denying_yaml);
            let decisions = authorize_all(&denier, &urls);
            let first = decisions.first().cloned().unwrap();
            assert!(matches!(
                first,
                AuthorizationDecision::Deny { reason: vaultx_policy::DenyReason::ExplicitDeny, .. }
            ));
            for (raw, decision) in raws.iter().zip(&decisions) {
                prop_assert_eq!(decision, &first, "deny drifted for spelling {}", raw);
            }
        }

        /// Egress classification is computed after WHATWG IPv4
        /// normalization: decimal, hex (both cases), and partial-quad
        /// integer host spellings all canonicalize to the same dotted
        /// quad and therefore classify identically — a denied private
        /// address cannot become allowed through numeric respelling.
        #[test]
        fn numeric_host_spellings_classify_identically(address in any::<u32>()) {
            let octets = address.to_be_bytes();
            let dotted = format!(
                "{}.{}.{}.{}",
                octets[0], octets[1], octets[2], octets[3]
            );
            // Last component fills the remaining octets (WHATWG rule), so
            // `{a}.{b}.{c*256+d}` denotes the same address.
            let remainder = u16::from_be_bytes([octets[2], octets[3]]);
            let spellings = [
                dotted.clone(),
                address.to_string(),
                format!("0x{address:x}"),
                format!("0X{address:X}"),
                format!("{}.{}.{}", octets[0], octets[1], remainder),
            ];

            let guard = EgressGuard::new(false);
            let mut outcomes: Vec<Result<String, String>> = Vec::new();
            for spelling in &spellings {
                let url = CanonicalUrl::parse(&format!("https://{spelling}/p"))
                    .unwrap_or_else(|err| panic!("spelling {spelling} must parse: {err:?}"));
                prop_assert_eq!(url.host(), dotted.as_str());
                outcomes.push(
                    guard
                        .check_host(url.host())
                        .map(|class| class.to_string())
                        .map_err(|err| err.to_string()),
                );
            }
            for outcome in &outcomes {
                prop_assert_eq!(outcome, &outcomes[0]);
            }
        }
    }
}
