//! Fuzz target: policy document YAML parser (plan §43).
//!
//! Feeds arbitrary bytes through `parse_policy_yaml`, which runs serde
//! YAML deserialization *and* semantic validation (hostnames, header
//! tokens, matcher patterns, size limits). Non-UTF-8 input is skipped by
//! design — the parser's contract is text-only. Panics/hangs/UB are the
//! finding; parse/validation errors are expected outcomes.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(document) = vaultx_policy::parse_policy_yaml(text) {
        // A validly parsed document must re-serialize without panic.
        let _ = serde_yaml::to_string(&document);
    }
});
