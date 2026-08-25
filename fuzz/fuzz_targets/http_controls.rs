//! Fuzz target: header filter + response sanitizer (plan §43).
//!
//! Covers the two vaultx-http request/response control surfaces that
//! consume attacker-shaped bytes:
//!
//! * `filter_request_headers` / `validate_header_pair` — RFC 7230 token
//!   grammar, sensitive-name rejection, CR/LF/NUL control rejection;
//! * response sanitization — `redact_headers`, content-type allowlist
//!   enforcement, and recursive `redact_json_fields` over arbitrary JSON.
//!
//! Input is a JSON document shaped by the `HttpControlCase` struct below;
//! malformed inputs are skipped (the underlying parsers are exercised via
//! their own decode paths inside serde). Panics/hangs/UB are the finding.

#![no_main]

use libfuzzer_sys::fuzz_target;
use serde::Deserialize;
use vaultx_http::{enforce_content_type, filter_request_headers, redact_headers, redact_json_fields};

#[derive(Deserialize)]
struct HttpControlCase {
    #[serde(default)]
    headers: Vec<(String, String)>,
    #[serde(default)]
    redact: Vec<String>,
    #[serde(default)]
    content_type: Option<String>,
    #[serde(default)]
    content_type_allowlist: Vec<String>,
    /// Upstream body fed to the JSON field redactor; any JSON value.
    #[serde(default)]
    body: Option<serde_json::Value>,
    #[serde(default)]
    redact_body_fields: Vec<String>,
}

fn clamp_len(mut items: Vec<(String, String)>) -> Vec<(String, String)> {
    items.truncate(64);
    for (name, value) in items.iter_mut() {
        name.truncate(256);
        value.truncate(4096);
    }
    items
}

fuzz_target!(|data: &[u8]| {
    let case: HttpControlCase = match serde_json::from_slice(data) {
        Ok(case) => case,
        Err(_) => return,
    };

    // Request-side controls.
    let headers = clamp_len(case.headers);
    let (allowed, rejected) = filter_request_headers(&headers);
    let _ = (allowed.len(), rejected.len());

    // Response-side controls.
    let _ = redact_headers(&headers, &case.redact);
    if let Some(content_type) = case.content_type.as_deref() {
        let _ = enforce_content_type(Some(content_type), &case.content_type_allowlist);
    }
    // Bound the body so pathological nesting stays within fuzzer time
    // budgets; 64 KiB is well above any realistic response slice.
    if let Some(body) = case.body {
        let bytes = serde_json::to_vec(&body).unwrap_or_default();
        let _ = redact_json_fields(&bytes[..bytes.len().min(64 * 1024)], &case.redact_body_fields);
    }
});
