//! Fuzz target: URL canonicalizer (plan §43).
//!
//! Feeds arbitrary text through `CanonicalUrl::parse`, the single
//! canonicalization boundary shared by authorization and transport. This
//! is the highest-value egress-security target: numeric-host spellings,
//! percent escapes, userinfo, ports, fragments, and dot segments all
//! funnel through here. Panics/hangs/UB are the finding; rejection
//! errors are expected outcomes. Errors are secret-blind by contract,
//! so they are simply discarded here.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vaultx_http::CanonicalUrl;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(canonical) = CanonicalUrl::parse(text) {
        // Accessors over a successfully canonicalized URL must never
        // panic (host/port/path/query extraction).
        let _ = format!(
            "{} {} {} {:?}",
            canonical.host(),
            canonical.port_or_default(),
            canonical.path(),
            canonical.query_pairs()
        );
    }
});
