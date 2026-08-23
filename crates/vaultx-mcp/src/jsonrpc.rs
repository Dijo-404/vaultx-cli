//! Minimal JSON-RPC 2.0 line framing for the MCP stdio transport
//! (plan §26).
//!
//! Requests arrive one per line; responses leave one per line.
//! Notifications (no usable `id`) produce no output. Only the subset the
//! server needs is implemented: parse errors (`-32700`), method not
//! found (`-32601`), invalid params (`-32602`), plus two server-defined
//! classes used by tool execution.

use serde::Deserialize;
use serde_json::{json, Value};

/// A line could not be parsed as a JSON object.
pub const PARSE_ERROR: i64 = -32700;
/// The requested method does not exist on this server.
pub const METHOD_NOT_FOUND: i64 = -32601;
/// Tool arguments are missing or malformed.
pub const INVALID_PARAMS: i64 = -32602;
/// Tool execution failed (transport/service); message is secret-blind.
pub const TOOL_FAILURE: i64 = -32000;
/// `vaultx.capability_request` named a capability with no pack policy.
pub const UNKNOWN_CAPABILITY: i64 = -32001;

/// One inbound JSON-RPC line, already classified by [`parse_line`].
#[derive(Debug)]
pub struct IncomingRequest {
    /// Echoed verbatim in the response; `None` means notification.
    pub id: Option<Value>,
    /// Method name.
    pub method: String,
    /// Params object (absent params become an empty object).
    pub params: Value,
}

impl IncomingRequest {
    /// True when the request must not receive a response.
    #[must_use]
    pub fn is_notification(&self) -> bool {
        self.id.is_none()
    }
}

/// Outcome of parsing one inbound line.
#[derive(Debug)]
pub enum ParsedLine {
    /// Well-formed JSON object carrying a `method`.
    Request(IncomingRequest),
    /// Anything else: malformed JSON or missing `method`.
    Malformed,
}

/// Classifies one stdin line. Blank lines are swallowed silently —
/// terminal transports routinely emit stray newlines.
#[must_use]
pub fn parse_line(line: &str) -> ParsedLine {
    if line.trim().is_empty() {
        return ParsedLine::Malformed;
    }
    #[derive(Deserialize)]
    struct Wire {
        #[serde(default)]
        id: Option<Value>,
        method: Option<String>,
        #[serde(default)]
        params: Value,
    }
    match serde_json::from_str::<Wire>(line) {
        Ok(Wire {
            id,
            method: Some(method),
            params,
        }) => {
            // Absent params normalize to an empty object so tool code can
            // index without null checks.
            let params = if params.is_null() { json!({}) } else { params };
            ParsedLine::Request(IncomingRequest { id, method, params })
        }
        _ => ParsedLine::Malformed,
    }
}

/// Serializes a success response line for `id`.
#[must_use]
pub fn success_line(id: &Value, result: Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string()
}

/// Serializes an error response line for `id`.
#[must_use]
pub fn error_line(id: &Value, code: i64, message: &str) -> String {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_parses_with_id_method_and_params() {
        let parsed =
            parse_line(r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"x"}}"#);
        let ParsedLine::Request(req) = parsed else {
            panic!("expected request");
        };
        assert!(!req.is_notification());
        assert_eq!(req.id, Some(json!(7)));
        assert_eq!(req.method, "tools/call");
        assert_eq!(req.params["name"], "x");
    }

    #[test]
    fn absent_params_become_an_empty_object() {
        let parsed = parse_line(r#"{"jsonrpc":"2.0","id":"a","method":"tools/list"}"#);
        let ParsedLine::Request(req) = parsed else {
            panic!("expected request");
        };
        assert_eq!(req.params, json!({}));
        assert_eq!(req.id, Some(json!("a")));
    }

    #[test]
    fn notifications_are_classified_and_have_no_id() {
        let parsed = parse_line(r#"{"jsonrpc":"2.0","method":"initialized"}"#);
        let ParsedLine::Request(req) = parsed else {
            panic!("expected notification-classified request");
        };
        assert!(req.is_notification());
        // An explicit null id is equally unusable for correlation.
        let parsed = parse_line(r#"{"jsonrpc":"2.0","id":null,"method":"initialized"}"#);
        let ParsedLine::Request(req) = parsed else {
            panic!("expected request");
        };
        assert!(req.is_notification());
    }

    #[test]
    fn malformed_lines_and_blank_lines_are_flagged() {
        assert!(matches!(parse_line("{nope"), ParsedLine::Malformed));
        assert!(matches!(parse_line("[1,2,3]"), ParsedLine::Malformed));
        // Missing method entirely.
        assert!(matches!(
            parse_line(r#"{"jsonrpc":"2.0","id":1}"#),
            ParsedLine::Malformed
        ));
        assert!(matches!(parse_line("   "), ParsedLine::Malformed));
    }

    #[test]
    fn response_lines_round_trip_both_outcomes() {
        let ok = success_line(&json!(1), json!({"value": "x"}));
        let v: Value = serde_json::from_str(&ok).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["id"], 1);
        assert_eq!(v["result"]["value"], "x");
        assert!(v.get("error").is_none());

        let err = error_line(&Value::Null, PARSE_ERROR, "parse error");
        let v: Value = serde_json::from_str(&err).unwrap();
        assert_eq!(v["error"]["code"], PARSE_ERROR);
        assert_eq!(v["error"]["message"], "parse error");
        assert!(v.get("result").is_none());
    }
}
