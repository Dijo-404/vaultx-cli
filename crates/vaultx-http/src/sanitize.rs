//! Response sanitization: header redaction, content-type allowlists, and
//! JSON field redaction.
//!
//! # Defense-in-depth notice
//!
//! [`redact_json_fields`] is a *best-effort* secondary control. Primary
//! protection against secret leakage is upstream: policy decides which
//! responses an agent may see at all. JSON redaction catches accidental
//! echo of sensitive field names (tokens, keys) in allowed payloads; it
//! cannot guarantee completeness (field names are matched literally,
//! values may embed secrets under innocuous names). Invalid JSON passes
//! through untouched rather than being dropped — callers must not rely on
//! redaction as a security boundary.

use crate::error::HttpPolicyError;

/// Replaces the value of every listed header name (case-insensitive)
/// with `"[redacted]"`.
///
/// Header order and non-listed headers pass through unchanged. Unknown
/// redaction targets are simply never hit.
#[must_use]
pub fn redact_headers(headers: &[(String, String)], redact: &[String]) -> Vec<(String, String)> {
    let targets: Vec<String> = redact.iter().map(|r| r.to_ascii_lowercase()).collect();
    headers
        .iter()
        .map(|(name, value)| {
            if targets.contains(&name.to_ascii_lowercase()) {
                (name.clone(), "[redacted]".to_owned())
            } else {
                (name.clone(), value.clone())
            }
        })
        .collect()
}

/// Enforces a response content-type against an allowlist.
///
/// The media type is compared case-insensitively, parameters (`; charset=
/// …`) stripped, and surrounding whitespace trimmed; bare `None` matches
/// only when the allowlist contains the empty string (i.e., a caller that
/// requires a content type keeps `None` out of its allowlist).
///
/// # Errors
/// Returns [`HttpPolicyError::InvalidHeaderValue`] when the type is not
/// permitted.
pub fn enforce_content_type(
    content_type: Option<&str>,
    allowlist: &[String],
) -> Result<(), HttpPolicyError> {
    let normalized = content_type.map_or_else(String::new, |ct| {
        ct.split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
    });
    if allowlist.iter().any(|allowed| {
        allowed
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .eq_ignore_ascii_case(&normalized)
    }) {
        Ok(())
    } else {
        Err(HttpPolicyError::InvalidHeaderValue(format!(
            "content-type `{normalized}` is not on the response allowlist"
        )))
    }
}

/// Recursively replaces values of matching object keys with
/// `"[redacted]"`, returning re-serialized bytes.
///
/// * traversal covers nested objects and arrays at any depth;
/// * key matching is exact (case-sensitive) — list every spelling;
/// * if the body is not valid JSON the input is returned unchanged;
/// * non-string values are replaced wholesale with the string sentinel.
#[must_use]
pub fn redact_json_fields(body: &[u8], field_names: &[String]) -> Vec<u8> {
    let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return body.to_vec();
    };
    redact_value(&mut value, field_names);
    serde_json::to_vec(&value).unwrap_or_else(|_| body.to_vec())
}

fn redact_value(value: &mut serde_json::Value, field_names: &[String]) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, inner) in map.iter_mut() {
                if field_names.iter().any(|f| f == key) {
                    *inner = serde_json::Value::String("[redacted]".to_owned());
                } else {
                    redact_value(inner, field_names);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items.iter_mut() {
                redact_value(item, field_names);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings<const N: usize>(items: [&str; N]) -> Vec<String> {
        items.into_iter().map(str::to_owned).collect()
    }

    #[test]
    fn header_redaction_is_case_insensitive_and_order_preserving() {
        let headers = vec![
            ("Content-Type".to_owned(), "application/json".to_owned()),
            ("SET-COOKIE".to_owned(), "session=abc".to_owned()),
            ("x-internal-hint".to_owned(), "10.0.0.5".to_owned()),
            ("Set-Cookie".to_owned(), "second=def".to_owned()),
        ];
        let out = redact_headers(&headers, &strings(["set-cookie", "X-Internal-Hint"]));
        assert_eq!(
            out,
            vec![
                ("Content-Type".to_owned(), "application/json".to_owned()),
                ("SET-COOKIE".to_owned(), "[redacted]".to_owned()),
                ("x-internal-hint".to_owned(), "[redacted]".to_owned()),
                ("Set-Cookie".to_owned(), "[redacted]".to_owned()),
            ]
        );
    }

    #[test]
    fn content_type_allowlist_admits_and_rejects() {
        let allow = strings(["application/json", "text/plain"]);

        // Exact match, parameter stripping, and case folding all pass.
        assert!(enforce_content_type(Some("application/json"), &allow).is_ok());
        assert!(enforce_content_type(Some("APPLICATION/JSON"), &allow).is_ok());
        assert!(enforce_content_type(Some("application/json; charset=utf-8"), &allow).is_ok());
        assert!(enforce_content_type(Some(" text/plain "), &allow).is_ok());

        // Wrong type denied.
        let err = enforce_content_type(Some("text/html"), &allow).unwrap_err();
        assert!(matches!(err, HttpPolicyError::InvalidHeaderValue(_)));

        // A missing content type matches nothing unless "" is allowlisted.
        assert!(enforce_content_type(None, &allow).is_err());
        assert!(enforce_content_type(None, &strings([""])).is_ok());

        // Parameters on the allowlist side do not block matching.
        assert!(enforce_content_type(
            Some("application/json"),
            &strings(["application/json;charset=utf-8"])
        )
        .is_ok());
    }

    #[test]
    fn json_redaction_traverses_nested_objects_and_arrays() {
        let body = br#"{
            "user": {"name": "ada", "api_key": "sk-123", "nested": {"password": "h4x"}},
            "history": [
                {"token": "tok-a", "note": "fine"},
                ["deep", {"secret": "s3cr3t"}]
            ],
            "keep": "visible"
        }"#;

        let out = redact_json_fields(body, &strings(["api_key", "password", "token", "secret"]));
        let parsed: serde_json::Value = serde_json::from_slice(&out).expect("still valid json");
        assert_eq!(parsed["user"]["api_key"], "[redacted]");
        assert_eq!(parsed["user"]["nested"]["password"], "[redacted]");
        assert_eq!(parsed["history"][0]["token"], "[redacted]");
        assert_eq!(parsed["history"][1][1]["secret"], "[redacted]");
        assert_eq!(parsed["user"]["name"], "ada");
        assert_eq!(parsed["history"][0]["note"], "fine");
        assert_eq!(parsed["history"][1][0], "deep");
        assert_eq!(parsed["keep"], "visible");
    }

    #[test]
    fn invalid_json_passes_through_unchanged() {
        for body in [b"not json".as_slice(), b"<html>401</html>", b"", b"{broken"] {
            assert_eq!(
                redact_json_fields(body, &strings(["token"])),
                body.to_vec(),
                "non-json body must be returned as-is"
            );
        }
    }

    #[test]
    fn empty_field_list_leaves_valid_json_intact() {
        let body = br#"{"a":1,"b":{"c":"d"}}"#;
        let out = redact_json_fields(body, &[]);
        // Re-serialization may reorder/compact but must stay equivalent.
        let original: serde_json::Value = serde_json::from_slice(body).unwrap();
        let result: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(original, result);
    }
}
