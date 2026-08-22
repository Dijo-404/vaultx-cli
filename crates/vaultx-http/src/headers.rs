//! Request header controls.
//!
//! Agent input may never influence hop-by-hop or credential-bearing
//! headers (plan §20): [`SENSITIVE_REQUEST_HEADERS`] lists the names that
//! the broker must synthesize itself or refuse outright. Filtering is
//! case-insensitive on the wire name and normalizes surviving names to
//! lowercase so duplicate-detection downstream is reliable.
//!
//! This module is pure logic — it validates and partitions header pairs;
//! attaching them to a real request happens in the broker transport.

use crate::error::HttpPolicyError;

/// Request headers callers may never set directly (compared
/// case-insensitively).
///
/// Credential headers (`authorization`, `proxy-authorization`) are owned
/// by the broker's credential broker; hop-by-hop and framing headers
/// (`host`, `connection`, `transfer-encoding`, `keep-alive`, `upgrade`,
/// `te`, `trailer`) plus request-smuggling enablers (`expect`) are
/// transport-owned.
pub const SENSITIVE_REQUEST_HEADERS: [&str; 10] = [
    "authorization",
    "proxy-authorization",
    "host",
    "connection",
    "transfer-encoding",
    "keep-alive",
    "upgrade",
    "te",
    "trailer",
    "expect",
];

/// RFC 7230 `tchar` set permitted in header field names.
fn is_tchar(c: char) -> bool {
    c.is_ascii_alphanumeric()
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

/// Validates one header pair against the RFC 7230 grammar.
///
/// The name must be non-empty and consist solely of token characters; it
/// is returned normalized to lowercase. The value must not contain any
/// control character except horizontal tab (`\t`), which blocks CR/LF/NUL
/// response-splitting and injection attempts at this boundary.
///
/// # Errors
/// Returns [`HttpPolicyError::InvalidHeaderValue`] describing which side
/// of the pair failed. The error message quotes the offending characters
/// by class only — values are echoed back verbatim otherwise because
/// request headers here are agent-controlled, not secret.
pub fn validate_header_pair(name: &str, value: &str) -> Result<(), HttpPolicyError> {
    if name.is_empty() {
        return Err(HttpPolicyError::InvalidHeaderValue(
            "header name is empty".to_owned(),
        ));
    }
    if !name.chars().all(is_tchar) {
        return Err(HttpPolicyError::InvalidHeaderValue(format!(
            "header name `{name}` contains characters outside the RFC 7230 token grammar"
        )));
    }
    if value.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7f) {
        return Err(HttpPolicyError::InvalidHeaderValue(format!(
            "header `{}` value contains forbidden control characters (CR/LF/NUL/DEL)",
            name.to_ascii_lowercase()
        )));
    }
    Ok(())
}

/// Partitions caller-supplied header pairs into transport-allowed and
/// rejected.
///
/// Returns `(allowed, rejected_names)` where:
///
/// * names matching [`SENSITIVE_REQUEST_HEADERS`] case-insensitively are
///   rejected;
/// * pairs failing [`validate_header_pair`] are also rejected (the strict
///   variant surfaces the underlying error);
/// * allowed names are emitted lowercased with their original values,
///   order preserved.
#[must_use]
pub fn filter_request_headers(input: &[(String, String)]) -> (Vec<(String, String)>, Vec<String>) {
    let mut allowed = Vec::new();
    let mut rejected = Vec::new();
    for (name, value) in input {
        let lowered = name.to_ascii_lowercase();
        if SENSITIVE_REQUEST_HEADERS.contains(&lowered.as_str()) {
            rejected.push(lowered);
        } else if validate_header_pair(&lowered, value).is_ok() {
            allowed.push((lowered, value.clone()));
        } else {
            rejected.push(lowered);
        }
    }
    (allowed, rejected)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs<const N: usize>(items: [(&str, &str); N]) -> Vec<(String, String)> {
        items
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect()
    }

    #[test]
    fn sensitive_headers_are_rejected_case_insensitively() {
        let input = pairs([
            ("AUTHORIZATION", "Bearer x"),
            ("Authorization", "Bearer y"),
            ("Proxy-Authorization", "Basic z"),
            ("HOST", "evil.example"),
            ("Transfer-Encoding", "chunked"),
            ("Connection", "close"),
            ("Keep-Alive", "timeout=5"),
            ("Upgrade", "h2c"),
            ("TE", "trailers"),
            ("Trailer", "X-Sum"),
            ("Expect", "100-continue"),
            ("authorization", "Bearer dup"),
        ]);
        let (allowed, rejected) = filter_request_headers(&input);
        assert!(allowed.is_empty());
        assert_eq!(rejected.len(), input.len());
        assert!(rejected
            .iter()
            .all(|r| r.chars().all(|c| !c.is_ascii_uppercase())));
    }

    #[test]
    fn valid_custom_headers_pass_and_are_lowercased() {
        let input = pairs([
            ("X-Custom-Trace", "abc-123"),
            ("Accept", "application/json"),
            ("User-Agent", "vaultx-agent/1.0"),
        ]);
        let (allowed, rejected) = filter_request_headers(&input);
        assert!(rejected.is_empty());
        assert_eq!(
            allowed,
            vec![
                ("x-custom-trace".to_owned(), "abc-123".to_owned()),
                ("accept".to_owned(), "application/json".to_owned()),
                ("user-agent".to_owned(), "vaultx-agent/1.0".to_owned()),
            ]
        );
    }

    #[test]
    fn malformed_pairs_land_in_the_rejected_list() {
        let input = pairs([
            ("Bad Name", "value"),        // space in token
            ("EmptyValueIsFine", "\r\n"), // CRLF injection attempt
        ]);
        let (_, rejected) = filter_request_headers(&input);
        assert_eq!(rejected.len(), 2);
    }

    #[test]
    fn validate_header_pair_rejects_injection_and_bad_tokens() {
        for (name, value) in [
            ("X-A", "ok\r\nHost: evil.example"), // CRLF smuggling
            ("X-B", "line1\nline2"),             // bare LF
            ("X-C", "nul\0byte"),                // NUL
            ("X-D", "del\x7f"),                  // DEL
            ("X-E", "vt\u{b}"),                  // vertical tab
            ("", "value"),                       // empty name
            ("With Space", "value"),             // non-token char
            ("Ünicode", "value"),                // non-ASCII token char
        ] {
            let err = validate_header_pair(name, value).expect_err("expected rejection");
            assert!(matches!(err, HttpPolicyError::InvalidHeaderValue(_)));
        }
    }

    #[test]
    fn validate_header_pair_accepts_grammar_conforming_pairs() {
        assert!(validate_header_pair("x-trace-id", "abc").is_ok());
        assert!(validate_header_pair("UPPERCASE-name", "").is_ok()); // empty value is legal
        assert!(validate_header_pair("x-tab-separated", "a\tb").is_ok());
        assert!(validate_header_pair("token-chars!#$%&'*+.^_`|~", "v").is_ok());
    }
}
