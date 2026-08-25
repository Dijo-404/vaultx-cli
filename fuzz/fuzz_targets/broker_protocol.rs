//! Fuzz target: broker protocol decoder (plan §43).
//!
//! Exercises the structured wire protocol: `BrokerRequest` decode
//! (credential refs, methods, tagged body variants, capability hints)
//! followed by `BrokerResponse` decode (validated request ids, decision
//! variants). Arbitrary bytes are legal input; Ok/Err are ignored and
//! panics/hangs/UB are the finding.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vaultx_broker::{BrokerRequest, BrokerResponse};

fuzz_target!(|data: &[u8]| {
    if let Ok(request) = serde_json::from_slice::<BrokerRequest>(data) {
        // Re-encode must not panic; Debug is manually redacted and must
        // stay panic-free on any decoded request.
        let _ = serde_json::to_vec(&request);
        let _ = format!("{request:?}");
    }
    let _ = serde_json::from_slice::<BrokerResponse>(data);
});
